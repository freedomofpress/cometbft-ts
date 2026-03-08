// src/lightclient.ts
import { Uint8ArrayToHex } from "./encoding";
import {
  CanonicalBlockID,
  CanonicalPartSetHeader,
  CanonicalVote,
} from "./proto/cometbft/types/v1/canonical";
import {
  BlockID,
  SignedHeader,
  SignedMsgType,
} from "./proto/cometbft/types/v1/types";
import {
  Validator as ProtoValidator,
  ValidatorSet as ProtoValidatorSet,
} from "./proto/cometbft/types/v1/validator";
import { Consensus } from "./proto/cometbft/version/v1/types";
import { Timestamp as PbTimestamp } from "./proto/google/protobuf/timestamp";

export type CryptoIndex = Map<string, CryptoKey>;

export interface VerifyOutcome {
  ok: boolean;
  quorum: boolean;
  signedPower: bigint;
  totalPower: bigint;
  headerTime?: PbTimestamp;
  appHash: Uint8Array;
  blockIdHash: Uint8Array;
  unknownValidators: string[];
  invalidSignatures: string[];
  countedSignatures: number;
}

function encodeUvarint(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error("encodeUvarint expects a non-negative safe integer");

  const bytes: number[] = [];
  let v = value;
  while (v >= 0x80) {
    bytes.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  bytes.push(v);
  return new Uint8Array(bytes);
}

function makePrecommitSignBytesProto(
  chainId: string,
  height: bigint,
  round: bigint,
  blockIdHash: Uint8Array,
  partsTotal: number,
  partsHash: Uint8Array,
  timestamp?: PbTimestamp,
): Uint8Array {
  const psh: CanonicalPartSetHeader = { total: partsTotal, hash: partsHash };
  const bid: CanonicalBlockID = { hash: blockIdHash, partSetHeader: psh };

  const vote: CanonicalVote = {
    type: SignedMsgType.SIGNED_MSG_TYPE_PRECOMMIT,
    height, // fixed64
    round, // fixed64 (encoder omits 0)
    blockId: bid,
    timestamp, // omitted if undefined
    chainId,
  };

  const body = CanonicalVote.encode(vote).finish();
  // Go's protoio.MarshalDelimited length-prefixes the canonical vote. Using
  // the same varint prefix keeps signatures compatible with both v0.34.x and
  // v1.0.x chains.
  const prefix = encodeUvarint(body.length);
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix, 0);
  out.set(body, prefix.length);
  return out;
}

function hasTwoThirds(signed: bigint, total: bigint): boolean {
  return signed * 3n > total * 2n;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function encodeUvarintBigint(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("uvarint cannot encode negative values");

  const bytes: number[] = [];
  let v = value;
  while (v >= 0x80n) {
    bytes.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  bytes.push(Number(v));
  return new Uint8Array(bytes);
}

function encodeLengthPrefixed(value: Uint8Array): Uint8Array {
  return concatBytes(encodeUvarintBigint(BigInt(value.length)), value);
}

function encodeString(value: string): Uint8Array {
  if (value.length === 0) return new Uint8Array();
  return concatBytes(
    new Uint8Array([0x0a]),
    encodeLengthPrefixed(new TextEncoder().encode(value)),
  );
}

function encodeBytes(value: Uint8Array): Uint8Array {
  if (value.length === 0) return new Uint8Array();
  return concatBytes(new Uint8Array([0x0a]), encodeLengthPrefixed(value));
}

function encodeInt64Value(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array();
  return concatBytes(new Uint8Array([0x08]), encodeUvarintBigint(value));
}

function encodeTimestamp(timestamp?: PbTimestamp): Uint8Array {
  if (!timestamp) return new Uint8Array();
  return PbTimestamp.encode(timestamp).finish();
}

function encodeVersionForHeaderHash(
  version: NonNullable<SignedHeader["header"]>["version"],
): Uint8Array {
  if (!version) return new Uint8Array();
  return Consensus.encode(version).finish();
}

function encodeBlockIdForHeaderHash(
  blockId: NonNullable<SignedHeader["header"]>["lastBlockId"],
): Uint8Array {
  if (!blockId) return new Uint8Array();
  return BlockID.encode(blockId).finish();
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array(data)),
  );
}

async function hashLeaf(leaf: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(new Uint8Array([0]), leaf));
}

async function hashInner(
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  return sha256(concatBytes(new Uint8Array([1]), left, right));
}

function getSplitPoint(size: number): number {
  if (size < 1) throw new Error("Cannot split an empty merkle tree");
  const p = 2 ** Math.floor(Math.log2(size));
  return p < size ? p : p / 2;
}

async function simpleMerkleHashFromByteSlices(
  chunks: Uint8Array[],
): Promise<Uint8Array> {
  if (chunks.length === 0) throw new Error("Cannot hash an empty merkle tree");
  if (chunks.length === 1) return hashLeaf(chunks[0]);

  const split = getSplitPoint(chunks.length);
  const left = await simpleMerkleHashFromByteSlices(chunks.slice(0, split));
  const right = await simpleMerkleHashFromByteSlices(chunks.slice(split));
  return hashInner(left, right);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function hashHeaderForBlockId(
  header: NonNullable<SignedHeader["header"]>,
): Promise<Uint8Array> {
  if (!header.lastBlockId) {
    throw new Error(
      "Header missing lastBlockId required for hash verification",
    );
  }

  const fields: Uint8Array[] = [
    encodeVersionForHeaderHash(header.version),
    encodeString(header.chainId),
    encodeInt64Value(header.height),
    encodeTimestamp(header.time),
    encodeBlockIdForHeaderHash(header.lastBlockId),
    encodeBytes(header.lastCommitHash),
    encodeBytes(header.dataHash),
    encodeBytes(header.validatorsHash),
    encodeBytes(header.nextValidatorsHash),
    encodeBytes(header.consensusHash),
    encodeBytes(header.appHash),
    encodeBytes(header.lastResultsHash),
    encodeBytes(header.evidenceHash),
    encodeBytes(header.proposerAddress),
  ];

  return simpleMerkleHashFromByteSlices(fields);
}

export async function verifyCommit(
  sh: SignedHeader,
  vset: ProtoValidatorSet,
  cryptoIndex: CryptoIndex,
): Promise<VerifyOutcome> {
  if (!sh?.header || !sh?.commit) {
    throw new Error("SignedHeader missing header/commit");
  }
  const header = sh.header;
  const commit = sh.commit;

  if (header.height !== commit.height) {
    throw new Error(
      `Header/commit height mismatch: ${header.height} vs ${commit.height}`,
    );
  }

  const totalPower = vset?.totalVotingPower ?? 0n;
  if (!Array.isArray(vset?.validators) || vset.validators.length === 0) {
    throw new Error("ValidatorSet has no validators");
  }
  if (totalPower <= 0n) {
    throw new Error("ValidatorSet total power must be positive");
  }

  // Build address -> validator map
  const setByAddrHex = new Map<string, ProtoValidator>();
  for (const v of vset.validators) {
    const hex = Uint8ArrayToHex(v.address).toUpperCase();
    if (setByAddrHex.has(hex))
      throw new Error(`Duplicate validator address in set: ${hex}`);
    setByAddrHex.set(hex, v);
  }

  if (!commit.blockId) throw new Error("Commit missing BlockID");
  const bid = commit.blockId;
  if (!bid.hash || bid.hash.length === 0)
    throw new Error("Commit BlockID hash is missing");
  if (!bid.partSetHeader) throw new Error("Commit PartSetHeader is missing");
  if (!bid.partSetHeader.hash || bid.partSetHeader.hash.length === 0) {
    throw new Error("Commit PartSetHeader hash is missing");
  }
  if (
    !Number.isInteger(bid.partSetHeader.total) ||
    bid.partSetHeader.total < 0
  ) {
    throw new Error("Commit PartSetHeader total is invalid");
  }

  const chainId: string = header.chainId;
  const heightBig: bigint = header.height;
  const roundBig: bigint = BigInt(commit.round);
  const blockIdHash: Uint8Array = bid.hash;
  const partsHash: Uint8Array = bid.partSetHeader.hash;
  const partsTotal: number = bid.partSetHeader.total;
  const expectedBlockIdHash = await hashHeaderForBlockId(header);
  const headerMatchesCommitBlockId = bytesEqual(
    expectedBlockIdHash,
    blockIdHash,
  );

  let signedPower = 0n;
  const unknown: string[] = [];
  const invalid: string[] = [];
  let counted = 0;

  for (let idx = 0; idx < commit.signatures.length; idx++) {
    const s = commit.signatures[idx];

    // Only COMMIT votes (BLOCK_ID_FLAG_COMMIT == 2)
    if (s.blockIdFlag !== 2) continue;

    const addrHex = Uint8ArrayToHex(s.validatorAddress).toUpperCase();
    const v = setByAddrHex.get(addrHex);
    if (!v) {
      unknown.push(addrHex);
      continue;
    }

    if (!s.signature || s.signature.length === 0) {
      invalid.push(addrHex);
      continue;
    }

    // Count this COMMIT vote (known validator + non-empty signature)
    counted++;

    // Canonical sign-bytes
    const signBytes = makePrecommitSignBytesProto(
      chainId,
      heightBig,
      roundBig,
      blockIdHash,
      partsTotal,
      partsHash,
      s.timestamp,
    );

    const key = cryptoIndex.get(addrHex);
    if (!key) {
      invalid.push(addrHex);
      continue;
    }

    // Verify signature
    let ok = false;
    try {
      ok = await crypto.subtle.verify(
        { name: "Ed25519" },
        key,
        new Uint8Array(s.signature),
        new Uint8Array(signBytes),
      );
    } catch {
      ok = false;
    }

    if (!ok) {
      invalid.push(addrHex);
      continue;
    }

    signedPower += v.votingPower ?? 0n;
  }

  const quorum = hasTwoThirds(signedPower, totalPower);
  const ok = quorum && headerMatchesCommitBlockId;

  return {
    ok,
    quorum,
    signedPower,
    totalPower,
    headerTime: header.time,
    appHash: header.appHash,
    blockIdHash,
    unknownValidators: unknown,
    invalidSignatures: invalid,
    countedSignatures: counted,
  };
}
