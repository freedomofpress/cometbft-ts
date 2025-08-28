// src/commit.ts
import { base64ToUint8Array, hexToUint8Array } from "./encoding";
import {
  BlockID,
  Commit,
  CommitSig,
  Header,
  SignedHeader,
} from "./proto/cometbft/types/v1/types";
import { BlockIDFlag } from "./proto/cometbft/types/v1/validator";
import { Consensus } from "./proto/cometbft/version/v1/types";
import { Timestamp as PbTimestamp } from "./proto/google/protobuf/timestamp";
import type { CommitResponse } from "./types";

// ---- helpers ----
function assertLen(name: string, u8: Uint8Array, expect: number) {
  if (u8.length !== expect) {
    throw new Error(`${name} must be ${expect} bytes, got ${u8.length}`);
  }
}

function parseRFC3339ToTimestamp(s: string): PbTimestamp {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) throw new Error(`Invalid RFC3339 time: ${s}`);

  // extract fractional seconds (up to 9 digits for nanos)
  const fracMatch = s.match(/\.(\d+)Z$/i);
  const frac = fracMatch ? fracMatch[1] : "";
  const n = Math.min(frac.length, 9);
  const nanos = n === 0 ? 0 : Number((frac + "0".repeat(9 - n)).slice(0, 9));
  const seconds = BigInt(Math.floor(d.getTime() / 1000));

  return { seconds, nanos };
}

/**
 * Parse and validate a /commit JSON and return a ts-proto SignedHeader
 * (cometbft.types.v1.SignedHeader).
 */
export function importCommit(resp: CommitResponse): SignedHeader {
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
  if (c.height == null || c.height === "")
    throw new Error("Missing commit.height");
  const headerHeight = BigInt(h.height);
  const commitHeight = BigInt(c.height);
  if (headerHeight !== commitHeight) {
    throw new Error(`height mismatch header=${h.height} commit=${c.height}`);
  }

  // Round
  if (
    typeof c.round !== "number" ||
    c.round < 0 ||
    !Number.isInteger(c.round)
  ) {
    throw new Error("Invalid commit.round");
  }

  // version (optional)
  const version: Consensus = {
    block: h.version?.block ? BigInt(h.version.block) : 0n,
    app: h.version?.app ? BigInt(h.version.app) : 0n,
  };

  // last_block_id
  if (!h.last_block_id || !h.last_block_id.hash || !h.last_block_id.parts) {
    throw new Error("Invalid last_block_id");
  }
  const lastBlockIdHash = hexToUint8Array(h.last_block_id.hash);
  assertLen("last_block_id.hash", lastBlockIdHash, 32);
  const lastBlockPartsHash = hexToUint8Array(h.last_block_id.parts.hash);
  assertLen("last_block_id.parts.hash", lastBlockPartsHash, 32);
  const lastBlockId: BlockID = {
    hash: lastBlockIdHash,
    partSetHeader: {
      total: Number(h.last_block_id.parts.total),
      hash: lastBlockPartsHash,
    },
  };
  if (
    !lastBlockId.partSetHeader ||
    !lastBlockId.partSetHeader.total ||
    !Number.isInteger(lastBlockId.partSetHeader.total) ||
    lastBlockId.partSetHeader.total < 0
  ) {
    throw new Error("Invalid last_block_id.parts.total");
  }

  // Hash fields (32 bytes unless app hash, which is app-defined length)
  const lastCommitHash = hexToUint8Array(h.last_commit_hash);
  assertLen("last_commit_hash", lastCommitHash, 32);
  const dataHash = hexToUint8Array(h.data_hash);
  assertLen("data_hash", dataHash, 32);
  const validatorsHash = hexToUint8Array(h.validators_hash);
  assertLen("validators_hash", validatorsHash, 32);
  const nextValidatorsHash = hexToUint8Array(h.next_validators_hash);
  assertLen("next_validators_hash", nextValidatorsHash, 32);
  const consensusHash = hexToUint8Array(h.consensus_hash);
  assertLen("consensus_hash", consensusHash, 32);
  const appHash = hexToUint8Array(h.app_hash); // variable length accepted
  const lastResultsHash = hexToUint8Array(h.last_results_hash);
  assertLen("last_results_hash", lastResultsHash, 32);
  const evidenceHash = hexToUint8Array(h.evidence_hash);
  assertLen("evidence_hash", evidenceHash, 32);

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
  const commitBlockId: BlockID = {
    hash: commitBlockHash,
    partSetHeader: {
      total: Number(c.block_id.parts.total),
      hash: commitPartsHash,
    },
  };
  if (
    !commitBlockId ||
    !commitBlockId.partSetHeader ||
    !Number.isInteger(commitBlockId.partSetHeader.total) ||
    commitBlockId.partSetHeader.total < 0
  ) {
    throw new Error("Invalid commit.block_id.parts.total");
  }

  // Signatures
  if (!Array.isArray(c.signatures) || c.signatures.length === 0) {
    throw new Error("Commit has no signatures");
  }
  const signatures: CommitSig[] = c.signatures.map((s, i) => {
    if (typeof s.block_id_flag !== "number") {
      throw new Error(`signatures[${i}].block_id_flag must be a number`);
    }
    if (!s.validator_address) {
      throw new Error(`signatures[${i}].validator_address missing`);
    }
    const validatorAddress = hexToUint8Array(s.validator_address);
    assertLen(`signatures[${i}].validator_address`, validatorAddress, 20);

    // bytes fields in proto3 are NOT optional -> use empty Uint8Array when absent
    const sigBytes = s.signature
      ? base64ToUint8Array(s.signature)
      : new Uint8Array(0);
    if (sigBytes.length !== 0) {
      assertLen(`signatures[${i}].signature`, sigBytes, 64); // Ed25519
    }

    const ts = s.timestamp ? parseRFC3339ToTimestamp(s.timestamp) : undefined;

    return {
      blockIdFlag: s.block_id_flag as BlockIDFlag,
      validatorAddress,
      timestamp: ts, // PbTimestamp | undefined (useDate=false)
      signature: sigBytes, // always Uint8Array (maybe length 0)
    };
  });

  const header: Header = {
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

  const commit: Commit = {
    height: headerHeight,
    round: c.round,
    blockId: commitBlockId,
    signatures,
  };

  return { header, commit };
}
