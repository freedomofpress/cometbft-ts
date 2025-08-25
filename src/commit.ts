import {
  hexToUint8Array,
  base64ToUint8Array,
} from "./encoding";
import type { CommitResponse } from "./types";

type Timestamp = { seconds: bigint; nanos: number };

export interface ProtoPartSetHeader {
  total: number;
  hash: Uint8Array;
}

export interface ProtoBlockID {
  hash: Uint8Array;
  partSetHeader: ProtoPartSetHeader;
}

export interface ProtoHeader {
  version?: { block?: bigint; app?: bigint };
  chainId: string;
  height: bigint;
  time?: Timestamp;

  lastBlockId: ProtoBlockID;

  lastCommitHash: Uint8Array;
  dataHash: Uint8Array;
  validatorsHash: Uint8Array;
  nextValidatorsHash: Uint8Array;
  consensusHash: Uint8Array;
  appHash: Uint8Array;
  lastResultsHash: Uint8Array;
  evidenceHash: Uint8Array;

  proposerAddress: Uint8Array; // 20 bytes
}

export interface ProtoCommitSig {
  blockIdFlag: number;
  validatorAddress: Uint8Array; // 20 bytes
  timestamp?: Timestamp;
  signature: Uint8Array;        // 64 bytes (Ed25519)
}

export interface ProtoCommit {
  height: bigint;
  round: number;
  blockId: ProtoBlockID;
  signatures: ProtoCommitSig[];
}

export interface ProtoSignedHeader {
  header: ProtoHeader;
  commit: ProtoCommit;
}

// ---- helpers ----
function assertLen(name: string, u8: Uint8Array, expect: number) {
  if (u8.length !== expect) {
    throw new Error(`${name} must be ${expect} bytes, got ${u8.length}`);
  }
}

function parseRFC3339ToTimestamp(s: string): Timestamp {
  // Keep fractional seconds up to 9 digits (nanos)
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) throw new Error(`Invalid RFC3339 time: ${s}`);

  const fracMatch = s.match(/\.(\d+)Z$/i);
  const frac = fracMatch ? fracMatch[1] : "";
  const nanos = (() => {
    const n = Math.min(frac.length, 9);
    if (n === 0) return 0;
    return Number((frac + "0".repeat(9 - n)).slice(0, 9));
  })();

  const seconds = BigInt(Math.floor(d.getTime() / 1000));
  return { seconds, nanos };
}

// ---- main ----
export function importCommit(resp: CommitResponse): ProtoSignedHeader {
  if (!resp || !resp.result || !resp.result.signed_header) {
    throw new Error("Missing signed_header in response");
  }

  const sh = resp.result.signed_header;
  const h = sh.header;
  const c = sh.commit;

  if (!h) throw new Error("Missing header");
  if (!c) throw new Error("Missing commit");

  // Heights
  if (!h.height) throw new Error("Missing header.height");
  if (c.height == null || c.height === "") throw new Error("Missing commit.height");
  const headerHeight = BigInt(h.height);
  const commitHeight = BigInt(c.height);
  if (headerHeight !== commitHeight) {
    throw new Error(`height mismatch header=${h.height} commit=${c.height}`);
  }

  // Round
  if (typeof c.round !== "number" || c.round < 0 || !Number.isInteger(c.round)) {
    throw new Error("Invalid commit.round");
  }

  // Version (optional)
  let version: ProtoHeader["version"] | undefined;
  if (h.version) {
    const block = h.version.block ? BigInt(h.version.block) : undefined;
    const app = h.version.app ? BigInt(h.version.app) : undefined;
    version = { block, app };
  }

  // last_block_id
  if (!h.last_block_id || !h.last_block_id.hash || !h.last_block_id.parts) {
    throw new Error("Invalid last_block_id");
  }
  const lastBlockIdHash = hexToUint8Array(h.last_block_id.hash);
  assertLen("last_block_id.hash", lastBlockIdHash, 32);
  const lastBlockPartsHash = hexToUint8Array(h.last_block_id.parts.hash);
  assertLen("last_block_id.parts.hash", lastBlockPartsHash, 32);
  const lastBlockId: ProtoBlockID = {
    hash: lastBlockIdHash,
    partSetHeader: {
      total: Number(h.last_block_id.parts.total),
      hash: lastBlockPartsHash,
    },
  };
  if (!Number.isInteger(lastBlockId.partSetHeader.total) || lastBlockId.partSetHeader.total < 0) {
    throw new Error("Invalid last_block_id.parts.total");
  }

  // Hash fields (32 bytes)
  const lastCommitHash   = hexToUint8Array(h.last_commit_hash);   assertLen("last_commit_hash", lastCommitHash, 32);
  const dataHash         = hexToUint8Array(h.data_hash);          assertLen("data_hash", dataHash, 32);
  const validatorsHash   = hexToUint8Array(h.validators_hash);    assertLen("validators_hash", validatorsHash, 32);
  const nextValidatorsHash = hexToUint8Array(h.next_validators_hash); assertLen("next_validators_hash", nextValidatorsHash, 32);
  const consensusHash    = hexToUint8Array(h.consensus_hash);     assertLen("consensus_hash", consensusHash, 32);
  const appHash          = hexToUint8Array(h.app_hash);           // This is app dependent
  const lastResultsHash  = hexToUint8Array(h.last_results_hash);  assertLen("last_results_hash", lastResultsHash, 32);
  const evidenceHash     = hexToUint8Array(h.evidence_hash);      assertLen("evidence_hash", evidenceHash, 32);

  // proposer_address (20 bytes)
  if (!h.proposer_address) throw new Error("Missing proposer_address");
  const proposerAddress = hexToUint8Array(h.proposer_address);
  assertLen("proposer_address", proposerAddress, 20);

  // time
  if (!h.time) throw new Error("Missing header.time");
  const time = parseRFC3339ToTimestamp(h.time);

  // Commit BlockID
  if (!c.block_id || !c.block_id.hash || !c.block_id.parts) {
    throw new Error("Invalid commit.block_id");
  }
  const commitBlockHash = hexToUint8Array(c.block_id.hash);
  assertLen("commit.block_id.hash", commitBlockHash, 32);
  const commitPartsHash = hexToUint8Array(c.block_id.parts.hash);
  assertLen("commit.block_id.parts.hash", commitPartsHash, 32);
  const commitBlockId: ProtoBlockID = {
    hash: commitBlockHash,
    partSetHeader: {
      total: Number(c.block_id.parts.total),
      hash: commitPartsHash,
    },
  };
  if (!Number.isInteger(commitBlockId.partSetHeader.total) || commitBlockId.partSetHeader.total < 0) {
    throw new Error("Invalid commit.block_id.parts.total");
  }

  // Signatures
  if (!Array.isArray(c.signatures) || c.signatures.length === 0) {
    throw new Error("Commit has no signatures");
  }
  const signatures: ProtoCommitSig[] = c.signatures.map((s, i) => {
    if (typeof s.block_id_flag !== "number") {
      throw new Error(`signatures[${i}].block_id_flag must be a number`);
    }
    if (!s.validator_address) {
      throw new Error(`signatures[${i}].validator_address missing`);
    }
    const validatorAddress = hexToUint8Array(s.validator_address);
    assertLen(`signatures[${i}].validator_address`, validatorAddress, 20);

    if (!s.signature) throw new Error(`signatures[${i}].signature missing`);
    const sigBytes = base64ToUint8Array(s.signature);
    assertLen(`signatures[${i}].signature`, sigBytes, 64); // Ed25519 = 64 bytes

    let ts: Timestamp | undefined;
    if (s.timestamp) ts = parseRFC3339ToTimestamp(s.timestamp);

    return {
      blockIdFlag: s.block_id_flag,
      validatorAddress,
      timestamp: ts,
      signature: sigBytes,
    };
  });

  const header: ProtoHeader = {
    version,
    chainId: h.chain_id,
    height: headerHeight,
    time,
    lastBlockId,

    lastCommitHash,
    dataHash,
    validatorsHash,
    nextValidatorsHash,
    consensusHash,
    appHash,
    lastResultsHash,
    evidenceHash,

    proposerAddress,
  };

  const commit: ProtoCommit = {
    height: headerHeight,
    round: c.round,
    blockId: commitBlockId,
    signatures,
  };

  return { header, commit };
}