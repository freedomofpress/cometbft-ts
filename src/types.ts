export interface Validator {
  address: string;                  // 20-byte uppercase hex
  key: CryptoKey;                   // Web Crypto Ed25519 public key for verify()
  power: bigint;
}

export interface ValidatorSet {
  height: bigint;
  totalPower: bigint;
  validators: Validator[];
}

export interface LightBlock {
  signedHeader: SignedHeader;
  validatorSet: ValidatorSet;
}

export interface SignedHeader {
  header: Header;
  commit: Commit;
}

// Header (proto/tmproto Header)
export interface Header {
  chainId: string;
  height: string;            // int64 as string
  time: string;              // RFC3339Nano
  lastBlockId?: BlockID | null;
  lastCommitHash?: Uint8Array | null;
  dataHash?: Uint8Array | null;
  validatorsHash: Uint8Array;
  nextValidatorsHash: Uint8Array;
  consensusHash: Uint8Array;
  appHash: Uint8Array;
  lastResultsHash?: Uint8Array | null;
  evidenceHash?: Uint8Array | null;
  proposerAddress: Uint8Array;
}

// Commit and signatures
export interface Commit {
  height: string;            // same as header.height
  round: number;
  blockId: BlockID;
  signatures: CommitSig[];   // one per validator index (some may be absent)
}

export type BlockIDFlag = 0 | 1 | 2; // Absent=0, Commit=2 (most common)
export interface CommitSig {
  blockIdFlag: BlockIDFlag;
  validatorAddress: Uint8Array;  // 20 bytes
  timestamp: string;             // RFC3339Nano
  signature?: Uint8Array | null; // Ed25519
}

export interface BlockID {
  hash: Uint8Array;          // SHA-256 of the block parts
  partSetHeader: { total: number; hash: Uint8Array };
}
