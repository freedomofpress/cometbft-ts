// src/lightclient.ts
import { Uint8ArrayToHex } from "./encoding";
import {
  CanonicalBlockID,
  CanonicalPartSetHeader,
  CanonicalVote,
} from "./proto/cometbft/types/v1/canonical";
import { SignedHeader, SignedMsgType } from "./proto/cometbft/types/v1/types";
import {
  Validator as ProtoValidator,
  ValidatorSet as ProtoValidatorSet,
} from "./proto/cometbft/types/v1/validator";
import { Timestamp as PbTimestamp } from "./proto/google/protobuf/timestamp";

const LEAF_PREFIX = new Uint8Array([0]);
const INNER_PREFIX = new Uint8Array([1]);

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

async function sha256(input: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(digest);
}

function encodeVarint(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("encodeVarint expects a non-negative bigint");
  const bytes: number[] = [];
  let v = value;
  while (v >= 0x80n) {
    bytes.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  bytes.push(Number(v));
  return new Uint8Array(bytes);
}

function encodeFieldTag(fieldNumber: number, wireType: number): Uint8Array {
  return encodeVarint(BigInt((fieldNumber << 3) | wireType));
}

function encodeProtoBytes(fieldNumber: number, value: Uint8Array): Uint8Array {
  return concatBytes(
    encodeFieldTag(fieldNumber, 2),
    encodeVarint(BigInt(value.length)),
    value,
  );
}

function encodeProtoUint64(fieldNumber: number, value: bigint): Uint8Array {
  return concatBytes(encodeFieldTag(fieldNumber, 0), encodeVarint(value));
}

function encodeProtoInt64(fieldNumber: number, value: bigint): Uint8Array {
  const v = value < 0n ? (1n << 64n) + value : value;
  return concatBytes(encodeFieldTag(fieldNumber, 0), encodeVarint(v));
}

function cdcEncodeString(value: string): Uint8Array | undefined {
  if (value.length === 0) return undefined;
  return encodeProtoBytes(1, new TextEncoder().encode(value));
}

function cdcEncodeInt64(value: bigint): Uint8Array {
  return encodeProtoInt64(1, value);
}

function cdcEncodeBytes(value: Uint8Array): Uint8Array | undefined {
  if (value.length === 0) return undefined;
  return encodeProtoBytes(1, value);
}

function encodeTimestamp(ts: PbTimestamp): Uint8Array {
  const seconds = encodeProtoInt64(1, ts.seconds ?? 0n);
  const nanos = ts.nanos
    ? concatBytes(encodeFieldTag(2, 0), encodeVarint(BigInt(ts.nanos)))
    : new Uint8Array(0);
  return concatBytes(seconds, nanos);
}

function encodePartSetHeader(total: number, hash: Uint8Array): Uint8Array {
  return concatBytes(
    encodeProtoUint64(1, BigInt(total)),
    encodeProtoBytes(2, hash),
  );
}

function encodeBlockId(
  hash: Uint8Array,
  partSetTotal: number,
  partSetHash: Uint8Array,
): Uint8Array {
  const psh = encodePartSetHeader(partSetTotal, partSetHash);
  return concatBytes(encodeProtoBytes(1, hash), encodeProtoBytes(2, psh));
}

async function merkleLeafHash(leaf: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(LEAF_PREFIX, leaf));
}

async function merkleInnerHash(
  left: Uint8Array,
  right: Uint8Array,
): Promise<Uint8Array> {
  return sha256(concatBytes(INNER_PREFIX, left, right));
}

function merkleSplitPoint(length: number): number {
  if (length < 1) throw new Error("Trying to split a tree with size < 1");
  const bitLen = Math.floor(Math.log2(length)) + 1;
  let k = 1 << (bitLen - 1);
  if (k === length) k >>= 1;
  return k;
}

async function merkleHashFromByteSlices(
  items: Uint8Array[],
): Promise<Uint8Array> {
  if (items.length === 0) return sha256(new Uint8Array(0));
  if (items.length === 1) return merkleLeafHash(items[0]);

  const k = merkleSplitPoint(items.length);
  const left = await merkleHashFromByteSlices(items.slice(0, k));
  const right = await merkleHashFromByteSlices(items.slice(k));
  return merkleInnerHash(left, right);
}

async function computeHeaderHash(
  header: SignedHeader["header"],
): Promise<Uint8Array> {
  if (!header) throw new Error("SignedHeader missing header");
  if (!header.lastBlockId || !header.lastBlockId.partSetHeader) {
    throw new Error("Header lastBlockId is missing");
  }
  if (!header.time) throw new Error("Header time is missing");

  const version = concatBytes(
    encodeProtoUint64(1, header.version?.block ?? 0n),
    encodeProtoUint64(2, header.version?.app ?? 0n),
  );

  const lastBlockId = encodeBlockId(
    header.lastBlockId.hash,
    header.lastBlockId.partSetHeader.total,
    header.lastBlockId.partSetHeader.hash,
  );

  const fields: Uint8Array[] = [
    version,
    cdcEncodeString(header.chainId),
    cdcEncodeInt64(header.height),
    encodeTimestamp(header.time),
    lastBlockId,
    cdcEncodeBytes(header.lastCommitHash),
    cdcEncodeBytes(header.dataHash),
    cdcEncodeBytes(header.validatorsHash),
    cdcEncodeBytes(header.nextValidatorsHash),
    cdcEncodeBytes(header.consensusHash),
    cdcEncodeBytes(header.appHash),
    cdcEncodeBytes(header.lastResultsHash),
    cdcEncodeBytes(header.evidenceHash),
    cdcEncodeBytes(header.proposerAddress),
  ].filter((x): x is Uint8Array => Boolean(x));

  return merkleHashFromByteSlices(fields);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

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

  const expectedBlockHash = await computeHeaderHash(header);
  if (!bytesEqual(expectedBlockHash, blockIdHash)) {
    throw new Error(
      "Header hash does not match commit BlockID hash (header fields were tampered or inconsistent)",
    );
  }

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

  return {
    ok: quorum,
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
