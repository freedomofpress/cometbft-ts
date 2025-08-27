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

// > 2/3
function hasTwoThirds(signed: bigint, total: bigint): boolean {
  return signed * 3n > total * 2n;
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
  unknownValidators: string[];  // addresses present in commit but not in set
  invalidSignatures: string[];  // addresses that failed verification
  countedSignatures: number;    // # of signatures counted (present in set, valid, non duplicated)
}

function makePrecommitSignBytes(
  chainId: string,
  height: bigint,
  round: bigint,
  blockIdHash: Uint8Array,
  partsTotal: number,
  partsHash: Uint8Array,
  timestamp?: PbTimestamp,
): Uint8Array {
  const cParts: CanonicalPartSetHeader = { total: partsTotal, hash: partsHash };
  const cBlockId: CanonicalBlockID = { hash: blockIdHash, partSetHeader: cParts };

  const cv: CanonicalVote = {
    type: SignedMsgType.SIGNED_MSG_TYPE_PRECOMMIT,
    height,
    round,
    blockId: cBlockId,
    timestamp,
    chainId,
  };

  return (CanonicalVote.encode(cv)).finish();
}

// A canonical zero timestamp (seconds=0, nanos=0)
const ZERO_TS: PbTimestamp = { seconds: 0n, nanos: 0 };

export async function verifyCommit(
  sh: SignedHeader,
  vset: ProtoValidatorSet,
  cryptoIndex: CryptoIndex,
): Promise<VerifyOutcome> {
  if (!sh?.header || !sh?.commit) throw new Error("SignedHeader missing header/commit");
  const header = sh.header;
  const commit = sh.commit;

  // Cross-check heights match
  if (header.height !== commit.height) {
    throw new Error(`Header/commit height mismatch: ${header.height} vs ${commit.height}`);
  }

  // ValidatorSet basics
  const totalPower = vset?.totalVotingPower ?? 0n;
  if (!Array.isArray(vset?.validators) || vset.validators.length === 0) {
    throw new Error("ValidatorSet has no validators");
  }
  if (totalPower <= 0n) {
    throw new Error("ValidatorSet total power must be positive");
  }

  // Map address -> validator, check duplicates
  const setByAddrHex = new Map<string, ProtoValidator>();
  for (const v of vset.validators) {
    const hex = Uint8ArrayToHex(v.address).toUpperCase();
    if (setByAddrHex.has(hex)) throw new Error(`Duplicate validator address in set: ${hex}`);
    setByAddrHex.set(hex, v);
  }

  // Guard commit.blockId and nested fields
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

  for (const s of commit.signatures) {
    // Only count votes with BLOCK_ID_FLAG_COMMIT (== 2)
    if (s.blockIdFlag !== 2) continue;

    const addrHex = Uint8ArrayToHex(s.validatorAddress).toUpperCase();

    const v = setByAddrHex.get(addrHex);
    if (!v) {
      unknown.push(addrHex);
      continue;
    }

    // Signature must be present for COMMIT votes
    if (!s.signature || s.signature.length === 0) {
      invalid.push(addrHex);
      continue;
    }

    const signBytesWithTS = makePrecommitSignBytes(
      chainId, heightBig, roundBig, blockIdHash, partsTotal, partsHash, s.timestamp
    );


    let key = cryptoIndex.get(addrHex);
    if (!key) {
      if (!v.pubKeyBytes || v.pubKeyType !== "ed25519") {
        invalid.push(addrHex);
        continue;
      }
      try {
        key = await crypto.subtle.importKey(
          "raw",
          new Uint8Array(v.pubKeyBytes),
          { name: "Ed25519" },
          false,
          ["verify"],
        );
      } catch {
        invalid.push(addrHex);
        continue;
      }
    }

    let ok = false;
    try {
      ok = await crypto.subtle.verify(
        { name: "Ed25519" },
        key,
        new Uint8Array(s.signature),
        new Uint8Array(signBytesWithTS),
      );
    } catch {
      ok = false;
    }

    if (!ok) {
      invalid.push(addrHex);
      continue;
    }

    signedPower += v.votingPower ?? 0n;
    counted++;
  }

  const quorum = hasTwoThirds(signedPower, totalPower);

  return {
    ok: quorum && invalid.length === 0,
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
