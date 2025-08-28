// src/lightclient.ts
import { SignedHeader, SignedMsgType } from "./proto/cometbft/types/v1/types";
import {
  ValidatorSet as ProtoValidatorSet,
  Validator as ProtoValidator,
} from "./proto/cometbft/types/v1/validator";
import {
  CanonicalVote,
  CanonicalBlockID,
  CanonicalPartSetHeader,
} from "./proto/cometbft/types/v1/canonical";
import { Timestamp as PbTimestamp } from "./proto/google/protobuf/timestamp";
import { Uint8ArrayToHex } from "./encoding";

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
    height,        // fixed64
    round,         // fixed64 (encoder omits 0)
    blockId: bid,
    timestamp,     // omitted if undefined
    chainId,
  };

  const body = CanonicalVote.encode(vote).finish();
  const out = new Uint8Array(1 + body.length);
  out[0] = 0x71; // CometBFT canonical prefix
  out.set(body, 1);
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
    throw new Error(`Header/commit height mismatch: ${header.height} vs ${commit.height}`);
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
    if (setByAddrHex.has(hex)) throw new Error(`Duplicate validator address in set: ${hex}`);
    setByAddrHex.set(hex, v);
  }

  if (!commit.blockId) throw new Error("Commit missing BlockID");
  const bid = commit.blockId;
  if (!bid.hash || bid.hash.length === 0) throw new Error("Commit BlockID hash is missing");
  if (!bid.partSetHeader) throw new Error("Commit PartSetHeader is missing");
  if (!bid.partSetHeader.hash || bid.partSetHeader.hash.length === 0) {
    throw new Error("Commit PartSetHeader hash is missing");
  }
  if (!Number.isInteger(bid.partSetHeader.total) || bid.partSetHeader.total < 0) {
    throw new Error("Commit PartSetHeader total is invalid");
  }

  const chainId: string = header.chainId;
  const heightBig: bigint = header.height;
  const roundBig: bigint = BigInt(commit.round);
  const blockIdHash: Uint8Array = bid.hash;
  const partsHash: Uint8Array = bid.partSetHeader.hash;
  const partsTotal: number = bid.partSetHeader.total;

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

    let key = cryptoIndex.get(addrHex);
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
