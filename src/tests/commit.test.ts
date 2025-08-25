import { describe, expect, it } from "vitest";
import { importCommit } from "../commit";
import type { CommitResponse } from "../types";
import commitFixture from "./fixtures/commit-12.json";
import { base64ToUint8Array, Uint8ArrayToBase64 } from "../encoding";

// Deep-clone plain JSON-like objects
function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

// Mutate a hex string by changing one byte (for negative cases)
function mutateHex(h: string, byteIndex = 0, newByte = 0x00) {
  const pairs = h.match(/../g) ?? [];
  if (pairs.length === 0) return h;
  const i = Math.min(byteIndex, pairs.length - 1);
  pairs[i] = newByte.toString(16).padStart(2, "0").toUpperCase();
  return pairs.join("");
}

describe("importCommit: happy path (fixture)", () => {
  it("parses a valid signed_header into ProtoSignedHeader", () => {
    const resp = commitFixture as unknown as CommitResponse;

    const sh = importCommit(resp);

    // header basics
    expect(sh.header.chainId).toBe("chain-ORcSeX");
    expect(sh.header.height).toBe(12n);
    expect(sh.header.version?.block).toBe(11n);
    expect(sh.header.version?.app).toBe(1n);
    expect(sh.header.time).toEqual({
      seconds: expect.any(BigInt),
      nanos: expect.any(Number),
    });

    // 32-byte hashes
    expect(sh.header.lastCommitHash.length).toBe(32);
    expect(sh.header.dataHash.length).toBe(32);
    expect(sh.header.validatorsHash.length).toBe(32);
    expect(sh.header.nextValidatorsHash.length).toBe(32);
    expect(sh.header.consensusHash.length).toBe(32);
    expect(sh.header.appHash.length).toBe(8);
    expect(sh.header.lastResultsHash.length).toBe(32);
    expect(sh.header.evidenceHash.length).toBe(32);

    // proposer 20 bytes
    expect(sh.header.proposerAddress.length).toBe(20);

    // last_block_id + commit.block_id parts
    expect(sh.header.lastBlockId.hash.length).toBe(32);
    expect(sh.header.lastBlockId.partSetHeader.hash.length).toBe(32);
    expect(typeof sh.header.lastBlockId.partSetHeader.total).toBe("number");

    expect(sh.commit.height).toBe(12n);
    expect(sh.commit.round).toBe(0);
    expect(sh.commit.blockId.hash.length).toBe(32);
    expect(sh.commit.blockId.partSetHeader.hash.length).toBe(32);
    expect(sh.commit.signatures.length).toBeGreaterThan(0);

    for (const s of sh.commit.signatures) {
      expect(typeof s.blockIdFlag).toBe("number");
      expect(s.validatorAddress.length).toBe(20);
      expect(s.signature.length).toBe(64);
      expect(s.timestamp).toEqual({
        seconds: expect.any(BigInt),
        nanos: expect.any(Number),
      });
    }
  });
});

describe("importCommit: validation errors", () => {
  it("fails on missing signed_header", () => {
    const bad = { jsonrpc: "2.0", id: -1, result: {} } as unknown as CommitResponse;
    expect(() => importCommit(bad)).toThrow(/Missing signed_header/);
  });

  it("fails on missing header", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.header;
    expect(() => importCommit(bad)).toThrow(/Missing header/);
  });

  it("fails on missing commit", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.commit;
    expect(() => importCommit(bad)).toThrow(/Missing commit/);
  });

  it("fails on missing header.height", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.header.height;
    expect(() => importCommit(bad)).toThrow(/Missing header\.height/);
  });

  it("fails on missing commit.height", () => {
    const bad = clone(commitFixture) as any;
    bad.result.signed_header.commit.height = "";
    expect(() => importCommit(bad)).toThrow(/Missing commit\.height/);
  });

  it("fails on mismatched header/commit heights", () => {
    const bad = clone(commitFixture) as any;
    bad.result.signed_header.header.height = "13";
    expect(() => importCommit(bad)).toThrow(/height mismatch/);
  });

  it("fails on invalid commit.round (negative / non-integer)", () => {
    const bad1 = clone(commitFixture) as any;
    bad1.result.signed_header.commit.round = -1;
    expect(() => importCommit(bad1)).toThrow(/Invalid commit\.round/);

    const bad2 = clone(commitFixture) as any;
    bad2.result.signed_header.commit.round = 0.5;
    expect(() => importCommit(bad2)).toThrow(/Invalid commit\.round/);
  });

  it("fails on invalid last_block_id (missing fields)", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.header.last_block_id.parts;
    expect(() => importCommit(bad)).toThrow(/Invalid last_block_id/);
  });

  it("fails on bad last_block_id.parts.total (negative / non-integer)", () => {
    const bad1 = clone(commitFixture) as any;
    bad1.result.signed_header.header.last_block_id.parts.total = -1;
    expect(() => importCommit(bad1)).toThrow(/Invalid last_block_id\.parts\.total/);

    const bad2 = clone(commitFixture) as any;
    bad2.result.signed_header.header.last_block_id.parts.total = 1.2;
    expect(() => importCommit(bad2)).toThrow(/Invalid last_block_id\.parts\.total/);
  });

  it("fails on malformed header hash lengths (32 bytes expected)", () => {
    const fields = [
      "last_commit_hash",
      "data_hash",
      "validators_hash",
      "next_validators_hash",
      "consensus_hash",
      "last_results_hash",
      "evidence_hash",
    ] as const;

    for (const f of fields) {
      const bad = clone(commitFixture) as any;
      // Make hex too short (trim 2 chars -> 31 bytes)
      bad.result.signed_header.header[f] =
        bad.result.signed_header.header[f].slice(0, -2);
      expect(() => importCommit(bad)).toThrow(new RegExp(`${f.replace(/_/g, "\\_")}`));
    }
  });

  it("fails on missing header.time", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.header.time;
    expect(() => importCommit(bad)).toThrow(/Missing header\.time/);
  });

  it("fails on invalid header.time (not RFC3339)", () => {
    const bad = clone(commitFixture) as any;
    bad.result.signed_header.header.time = "not-a-time";
    expect(() => importCommit(bad)).toThrow(/Invalid RFC3339 time/);
  });

  it("fails on missing proposer_address", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.header.proposer_address;
    expect(() => importCommit(bad)).toThrow(/Missing proposer_address/);
  });

  it("fails on proposer_address wrong length", () => {
    const bad = clone(commitFixture) as any;
    bad.result.signed_header.header.proposer_address =
      bad.result.signed_header.header.proposer_address.slice(0, 38); // 19 bytes
    expect(() => importCommit(bad)).toThrow(/proposer_address must be 20 bytes/);
  });

  it("fails on invalid commit.block_id (missing parts)", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.commit.block_id.parts;
    expect(() => importCommit(bad)).toThrow(/Invalid commit\.block_id/);
  });

  it("fails on bad commit.block_id.parts.total", () => {
    const bad = clone(commitFixture) as any;
    bad.result.signed_header.commit.block_id.parts.total = -1;
    expect(() => importCommit(bad)).toThrow(/Invalid commit\.block_id\.parts\.total/);
  });

  it("fails when commit has no signatures", () => {
    const bad = clone(commitFixture) as any;
    bad.result.signed_header.commit.signatures = [];
    expect(() => importCommit(bad)).toThrow(/Commit has no signatures/);
  });

  it("fails on invalid signatures[*].block_id_flag type", () => {
    const bad = clone(commitFixture) as any;
    bad.result.signed_header.commit.signatures[0].block_id_flag = "2";
    expect(() => importCommit(bad)).toThrow(/block_id_flag must be a number/);
  });

  it("fails on missing validator_address", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.commit.signatures[0].validator_address;
    expect(() => importCommit(bad)).toThrow(/validator_address missing/);
  });

  it("fails on short validator_address (hex < 40 chars)", () => {
    const bad = clone(commitFixture) as any;
    bad.result.signed_header.commit.signatures[0].validator_address =
      bad.result.signed_header.commit.signatures[0].validator_address.slice(0, 38);
    expect(() => importCommit(bad)).toThrow(/validator_address.*20 bytes/);
  });

  it("fails on missing signature", () => {
    const bad = clone(commitFixture) as any;
    delete bad.result.signed_header.commit.signatures[0].signature;
    expect(() => importCommit(bad)).toThrow(/signature missing/);
  });

  it("fails on wrong signature length (not 64 bytes) without Buffer", () => {
    const bad = clone(commitFixture) as any;
    const sigB64: string = bad.result.signed_header.commit.signatures[0].signature;

    // Decode -> slice to 63 bytes -> encode back, purely via helpers
    const sigBytes = base64ToUint8Array(sigB64);
    const shorter = sigBytes.slice(0, 63);
    bad.result.signed_header.commit.signatures[0].signature = Uint8ArrayToBase64(shorter);

    expect(() => importCommit(bad)).toThrow(/signature.*64 bytes/);
  });

  it("parses timestamps with fractional seconds (nano padding/truncation)", () => {
    const withFrac = clone(commitFixture) as any;
    withFrac.result.signed_header.header.time = "2025-08-18T13:39:10.618857123Z";
    withFrac.result.signed_header.commit.signatures[0].timestamp = "2025-08-18T13:39:11.9Z";

    const sh = importCommit(withFrac as CommitResponse);
    expect(sh.header.time?.nanos).toBe(618857123);
    expect(sh.commit.signatures[0].timestamp?.nanos).toBe(900000000);
  });
});
