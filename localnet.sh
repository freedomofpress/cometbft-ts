#!/usr/bin/env bash
set -euo pipefail

# ===================== config =====================
COMETBFT_BIN="${COMETBFT_BIN:-cometbft}"   # path to cometbft binary
HOME_ROOT="${HOME_ROOT:-./mytestnet}"
NODES=4

# base ports (node0 uses these; others add STEP)
RPC_BASE=26657
P2P_BASE=26656
PPROF_BASE=6060
STEP=3

node_home() { echo "${HOME_ROOT}/node$1"; }
rpc_port()  { echo $((RPC_BASE  + ($1 * STEP))); }
p2p_port()  { echo $((P2P_BASE  + ($1 * STEP))); }
pprof_port(){ echo $((PPROF_BASE+ ($1 * STEP))); }

die() { echo "error: $*" >&2; exit 1; }
has() { command -v "$1" >/dev/null 2>&1; }

# ===================== portable sed =====================
# GNU vs BSD sed inline edit
sedi() {
  if sed --version >/dev/null 2>&1; then
    sed -i -e "$@"
  else
    sed -i '' -e "$@"
  fi
}

# set TOML key within a section [section]; quoted value
toml_set_q() {
  local file="$1" section="$2" key="$3" value="$4"
  sedi "/^\[${section}\]\$/,/^\[/{ s|^${key}[[:space:]]*=.*$|${key} = \"${value}\"|; }" "$file"
}

# set TOML key within a section [section]; raw (booleans/numbers)
toml_set_raw() {
  local file="$1" section="$2" key="$3" value="$4"
  sedi "/^\[${section}\]\$/,/^\[/{ s|^${key}[[:space:]]*=.*$|${key} = ${value}|; }" "$file"
}

# ===================== generation & patching =====================
ensure_tools() {
  has "$COMETBFT_BIN" || die "cometbft not found; set COMETBFT_BIN or add to PATH"
  has curl || die "curl required"
  has jq   || die "jq required (brew install jq)"
}

gen_testnet() {
  # nuke old, generate, THEN make logs/run dirs so they survive
  rm -rf "$HOME_ROOT"
  "$COMETBFT_BIN" testnet --v "$NODES" --o "$HOME_ROOT" >/dev/null
  mkdir -p "${HOME_ROOT}/_logs" "${HOME_ROOT}/_run"
  echo "Generated ${NODES}-node testnet in $HOME_ROOT"
}

patch_node_config() {
  local i="$1"
  local cfg="$(node_home "$i")/config/config.toml"

  toml_set_q   "$cfg" rpc laddr            "tcp://127.0.0.1:$(rpc_port "$i")"
  toml_set_q   "$cfg" p2p laddr            "tcp://127.0.0.1:$(p2p_port "$i")"
  toml_set_q   "$cfg" instrumentation pprof_laddr "localhost:$(pprof_port "$i")"

  # localhost-friendly P2P
  toml_set_raw "$cfg" p2p addr_book_strict false
  toml_set_raw "$cfg" p2p allow_duplicate_ip true
}

wire_peers() {
  # gather ids
  local -a ids
  for i in $(seq 0 $((NODES-1))); do
    ids[$i]=$("$COMETBFT_BIN" show-node-id --home "$(node_home "$i")")
  done
  # set persistent_peers (everyone else)
  for i in $(seq 0 $((NODES-1))); do
    local peers=""
    for j in $(seq 0 $((NODES-1))); do
      [ "$i" -eq "$j" ] && continue
      local addr="${ids[$j]}@127.0.0.1:$(p2p_port "$j")"
      peers="${peers:+$peers,}$addr"
    done
    toml_set_q "$(node_home "$i")/config/config.toml" p2p persistent_peers "$peers"
  done
}

# ===================== lifecycle =====================
start_nodes() {
  for i in $(seq 0 $((NODES-1))); do
    local home log pidfile
    home="$(node_home "$i")"
    log="${HOME_ROOT}/_logs/node${i}.log"
    pidfile="${HOME_ROOT}/_run/node${i}.pid"

    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      echo "node${i} already running (pid $(cat "$pidfile"))"
      continue
    fi

    echo "Starting node${i} (RPC :$(rpc_port "$i"), P2P :$(p2p_port "$i")) ..."
    nohup "$COMETBFT_BIN" node \
      --home "$home" \
      --proxy_app=persistent_kvstore \
      >"$log" 2>&1 &
    echo $! >"$pidfile"
  done

  # wait for RPC to be responsive
  for i in $(seq 0 $((NODES-1))); do
    local port; port=$(rpc_port "$i")
    printf "Waiting for node%s RPC :%s " "$i" "$port"
    for _ in $(seq 1 60); do
      if curl -sf "http://127.0.0.1:${port}/status" >/dev/null; then
        echo "✓"
        break
      fi
      sleep 0.2; printf "."
    done
    echo
    if ! curl -sf "http://127.0.0.1:${port}/status" >/dev/null; then
      echo "node${i} failed to start; last 50 log lines:"
      tail -n 50 "${HOME_ROOT}/_logs/node${i}.log" || true
      exit 1
    fi
  done
  echo "All nodes up."
}

stop_nodes() {
  local any=0
  for i in $(seq 0 $((NODES-1))); do
    local pidfile="${HOME_ROOT}/_run/node${i}.pid"
    if [ -f "$pidfile" ]; then
      local pid; pid="$(cat "$pidfile")"
      if kill -0 "$pid" 2>/dev/null; then
        echo "Stopping node${i} (pid $pid)"
        kill "$pid" || true
        any=1
      fi
      rm -f "$pidfile"
    fi
  done
  [ "$any" -eq 0 ] && echo "No nodes appeared to be running."
}

status_nodes() {
  for i in $(seq 0 $((NODES-1))); do
    local pidfile="${HOME_ROOT}/_run/node${i}.pid"
    local state="stopped"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      state="RUNNING (pid $(cat "$pidfile"))"
    fi
    local port; port=$(rpc_port "$i")
    local h="n/a"
    if curl -sf "http://127.0.0.1:${port}/status" >/dev/null 2>&1; then
      h=$(curl -s "http://127.0.0.1:${port}/status" | jq -r .result.sync_info.latest_block_height)
    fi
    echo "node${i}: ${state}, RPC :$port, height=${h}"
  done
}

logs_node() {
  local i="${1:-0}"
  tail -f "${HOME_ROOT}/_logs/node${i}.log"
}

clean_all() {
  stop_nodes || true
  rm -rf "$HOME_ROOT"
  echo "Cleaned $HOME_ROOT"
}

send_tx() {
  local port="${1:-26657}"
  local data="${2:-a=1}"
  curl -s "http://127.0.0.1:${port}/broadcast_tx_commit?tx=\"${data}\"" | jq .
}

snapshot() {
  local port="${1:-26657}"
  local H="${2:-$(curl -s 127.0.0.1:${port}/status | jq -r .result.sync_info.latest_block_height)}"
  curl -s "http://127.0.0.1:${port}/commit?height=${H}"     > "commit-${H}.json"
  curl -s "http://127.0.0.1:${port}/validators?height=${H}" > "validators-${H}.json"
  echo "Wrote commit-${H}.json and validators-${H}.json"
}

# ===================== CLI =====================
case "${1:-}" in
  start)
    ensure_tools
    gen_testnet
    for i in $(seq 0 $((NODES-1))); do patch_node_config "$i"; done
    wire_peers
    start_nodes
    ;;
  stop)     stop_nodes ;;
  status)   status_nodes ;;
  logs)     logs_node "${2:-0}" ;;
  clean)    clean_all ;;
  tx)       send_tx "${2:-26657}" "${3:-a=1}" ;;
  snapshot) snapshot "${2:-26657}" "${3:-}" ;;
  *)
    cat <<EOF
Usage: $0 {start|stop|status|logs [i]|clean|tx [rpc_port [kv]]|snapshot [rpc_port [height]]}

start     Generate & start 4-node localhost net (in-process kvstore)
stop      Stop all nodes
status    Show PID / RPC / height
logs [i]  Tail logs for node i (default 0)
clean     Stop & remove the testnet directory
tx [p d]  Broadcast kv tx to RPC port p (default 26657) with data d (default "a=1")
snapshot [p H] Export commit-H.json and validators-H.json from RPC port p (defaults to latest)
EOF
    ;;
esac
