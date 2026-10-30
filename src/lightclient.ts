// src/lightclient.ts
import {
  concatBytes,
  getSubtle,
  hashLeaf,
  rootHash,
  stringToUint8Array,
  uint8ArrayEqual,
  Uint8ArrayToHex,
} from "@freedomofpress/crypto-browser";

import {
  CanonicalBlockID,
  CanonicalPartSetHeader,
  CanonicalVote,
} from "./proto/cometbft/types/v1/canonical.js";
import {
  BlockID,
  SignedHeader,
  SignedMsgType,
} from "./proto/cometbft/types/v1/types.js";
import {
  SimpleValidator as ProtoSimpleValidator,
  Validator as ProtoValidator,
  ValidatorSet as ProtoValidatorSet,
} from "./proto/cometbft/types/v1/validator.js";
import { Consensus } from "./proto/cometbft/version/v1/types.js";
import { Timestamp as PbTimestamp } from "./proto/google/protobuf/timestamp.js";
import { MAX_TOTAL_VOTING_POWER } from "./validators.js";

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
    encodeLengthPrefixed(stringToUint8Array(value)),
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

async function merkleRoot(chunks: Uint8Array[]): Promise<Uint8Array> {
  if (chunks.length === 0) throw new Error("Cannot hash an empty merkle tree");
  return rootHash(await Promise.all(chunks.map(hashLeaf)));
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

  return merkleRoot(fields);
}

async function hashValidatorSet(vset: ProtoValidatorSet): Promise<Uint8Array> {
  const validators = vset.validators.map((validator) => {
    if (validator.pubKeyType !== "ed25519") {
      throw new Error(
        `Unsupported validator key type: ${validator.pubKeyType}`,
      );
    }
    return ProtoSimpleValidator.encode({
      pubKey: { ed25519: validator.pubKeyBytes },
      votingPower: validator.votingPower ?? 0n,
    }).finish();
  });
  return merkleRoot(validators);
}

export async function verifyCommit(
  sh: SignedHeader,
  vset: ProtoValidatorSet,
  cryptoIndex: CryptoIndex,
  expectedChainId: string,
): Promise<VerifyOutcome> {
  const subtle = await getSubtle();
  if (!sh?.header || !sh?.commit) {
    throw new Error("SignedHeader missing header/commit");
  }
  const header = sh.header;
  const commit = sh.commit;

  if (header.chainId !== expectedChainId) {
    throw new Error(
      `Chain ID mismatch: expected ${expectedChainId}, got ${header.chainId}`,
    );
  }

  if (header.height !== commit.height) {
    throw new Error(
      `Header/commit height mismatch: ${header.height} vs ${commit.height}`,
    );
  }

  const totalPower = vset?.totalVotingPower;
  if (!Array.isArray(vset?.validators) || vset.validators.length === 0) {
    throw new Error("ValidatorSet has no validators");
  }
  if (typeof totalPower !== "bigint" || totalPower <= 0n) {
    throw new Error("ValidatorSet total power must be positive");
  }

  // Build address -> validator map
  const setByAddrHex = new Map<string, ProtoValidator>();
  let countedPower = 0n;
  for (const v of vset.validators) {
    const hex = Uint8ArrayToHex(v.address).toUpperCase();
    if (setByAddrHex.has(hex))
      throw new Error(`Duplicate validator address in set: ${hex}`);
    if (typeof v.votingPower !== "bigint" || v.votingPower <= 0n) {
      throw new Error(`Invalid voting power for validator: ${hex}`);
    }
    countedPower += v.votingPower;
    if (countedPower > MAX_TOTAL_VOTING_POWER) {
      throw new Error("Total voting power exceeds CometBFT maximum");
    }
    setByAddrHex.set(hex, v);
  }
  if (totalPower !== countedPower) {
    throw new Error("ValidatorSet total power does not match validators");
  }

  if (commit.signatures.length !== vset.validators.length) {
    throw new Error("Commit signature count does not match validator set");
  }

  const validatorSetHash = await hashValidatorSet(vset);
  if (!uint8ArrayEqual(validatorSetHash, header.validatorsHash)) {
    throw new Error("Header validator hash does not match validator set");
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

  const heightBig: bigint = header.height;
  const roundBig: bigint = BigInt(commit.round);
  const blockIdHash: Uint8Array = bid.hash;
  const partsHash: Uint8Array = bid.partSetHeader.hash;
  const partsTotal: number = bid.partSetHeader.total;
  const expectedBlockIdHash = await hashHeaderForBlockId(header);
  const headerMatchesCommitBlockId = uint8ArrayEqual(
    expectedBlockIdHash,
    blockIdHash,
  );

  let signedPower = 0n;
  const unknown: string[] = [];
  const invalid: string[] = [];
  let counted = 0;
  const seenCommitValidators = new Set<string>();

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
    if (seenCommitValidators.has(addrHex)) {
      throw new Error(`Duplicate commit from validator: ${addrHex}`);
    }
    seenCommitValidators.add(addrHex);

    if (!s.signature || s.signature.length === 0) {
      invalid.push(addrHex);
      continue;
    }

    // Count this COMMIT vote (known validator + non-empty signature)
    counted++;

    // Canonical sign-bytes
    const signBytes = makePrecommitSignBytesProto(
      expectedChainId,
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
      ok = await subtle.verify(
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
