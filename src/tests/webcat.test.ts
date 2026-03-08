import { describe, expect, it } from "vitest";

import { importCommit } from "../commit";
import { Uint8ArrayToBase64, Uint8ArrayToHex } from "../encoding";
import { verifyCommit } from "../lightclient";
import type { CommitJson, ValidatorJson } from "../types";
import { importValidators } from "../validators";
import blockFixture from "./fixtures/webcat.json";

function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

function flipLastHexNibble(hex: string): string {
  const last = hex.at(-1);
  if (!last) throw new Error("Cannot mutate an empty hex string");

  const replacement = last.toLowerCase() === "0" ? "1" : "0";
  return `${hex.slice(0, -1)}${replacement}`;
}

describe("lightclient.verifyCommit", () => {
  it("verifies a valid commit against the validator set", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = blockFixture as unknown as CommitJson;

    const { proto: vset, cryptoIndex } = await importValidators(validators);
    const sh = importCommit(commit);

    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(true);
    expect(out.ok).toBe(true);
    expect(out.signedPower > 0n).toBe(true);
    expect(out.signedPower <= out.totalPower).toBe(true);
    expect(out.headerTime).toBeDefined();
    expect(out.appHash instanceof Uint8Array).toBe(true);
    expect(out.blockIdHash instanceof Uint8Array).toBe(true);
    expect(out.unknownValidators.length).toBe(0);
    expect(out.invalidSignatures.length).toBe(0);
    expect(out.countedSignatures).toBeGreaterThan(0);
  });

  it("flags invalid signatures", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = clone(blockFixture) as unknown as CommitJson;

    // Flip one byte of the BlockID hash to keep the signature well-formed but
    // cryptographically invalid for the mutated sign-bytes.
    commit.signed_header.commit.block_id.hash =
      "3A1D00CC2A092465E85EA2C24986BEE0105285039DC1873BB6B0CA7F610EC89D";

    const { proto: vset, cryptoIndex } = await importValidators(validators);
    const sh = importCommit(commit);

    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(false);
    expect(out.ok).toBe(false);
    expect(out.signedPower).toBe(0n);
    expect(out.invalidSignatures).toHaveLength(vset.validators.length);
    expect(out.invalidSignatures).toContain(
      Uint8ArrayToHex(vset.validators[0].address).toUpperCase(),
    );
    expect(out.countedSignatures).toBe(vset.validators.length);
  });

  it("flags invalid signatures", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = clone(blockFixture) as unknown as CommitJson;

    commit.signed_header.commit.signatures[0].signature = Uint8ArrayToBase64(
      new Uint8Array(64),
    );

    const { proto: vset, cryptoIndex } = await importValidators(validators);
    const sh = importCommit(commit);

    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(false);
    expect(out.ok).toBe(false);
    expect(out.signedPower).toBe(2n);
    expect(out.invalidSignatures).toEqual([
      Uint8ArrayToHex(vset.validators[0].address).toUpperCase(),
    ]);
    expect(out.countedSignatures).toBe(vset.validators.length);
  });

  it("rejects malformed signature bytes", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = clone(blockFixture) as unknown as CommitJson;

    // Truncate the signature (must be 64 bytes for Ed25519)
    commit.signed_header.commit.signatures[0].signature = "AA==";

    await expect(async () => importCommit(commit)).rejects.toThrow(
      /signature must be 64 bytes/,
    );
  });

  it("reports unknown validators", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = clone(blockFixture) as unknown as CommitJson;

    commit.signed_header.commit.signatures[0].validator_address =
      "0000000000000000000000000000000000000000";

    const { proto: vset, cryptoIndex } = await importValidators(validators);
    const sh = importCommit(commit);

    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(false);
    expect(out.ok).toBe(false);
    expect(out.signedPower).toBe(2n);
    expect(out.invalidSignatures).toEqual([]);
    expect(out.unknownValidators).toEqual([
      "0000000000000000000000000000000000000000",
    ]);
    expect(out.countedSignatures).toBe(vset.validators.length - 1);
  });

  it("detects tampering of every header field by checking the header merkle root against commit.block_id.hash", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const { proto: vset, cryptoIndex } = await importValidators(validators);

    const mutators: Record<string, (commit: any) => void> = {
      "header.version.block": (commit) => {
        commit.signed_header.header.version.block = String(
          BigInt(commit.signed_header.header.version.block) + 1n,
        );
      },
      "header.version.app": (commit) => {
        commit.signed_header.header.version.app = String(
          BigInt(commit.signed_header.header.version.app) + 1n,
        );
      },
      "header.chain_id": (commit) => {
        commit.signed_header.header.chain_id = `${commit.signed_header.header.chain_id}-tampered`;
      },
      "header.height": (commit) => {
        commit.signed_header.header.height = String(
          BigInt(commit.signed_header.header.height) + 1n,
        );
        commit.signed_header.commit.height = commit.signed_header.header.height;
      },
      "header.time": (commit) => {
        commit.signed_header.header.time = "2026-03-08T03:00:52.980342152Z";
      },
      "header.last_block_id.hash": (commit) => {
        commit.signed_header.header.last_block_id.hash = flipLastHexNibble(
          commit.signed_header.header.last_block_id.hash,
        );
      },
      "header.last_block_id.parts.total": (commit) => {
        commit.signed_header.header.last_block_id.parts.total += 1;
      },
      "header.last_block_id.parts.hash": (commit) => {
        commit.signed_header.header.last_block_id.parts.hash =
          flipLastHexNibble(
            commit.signed_header.header.last_block_id.parts.hash,
          );
      },
      "header.last_commit_hash": (commit) => {
        commit.signed_header.header.last_commit_hash = flipLastHexNibble(
          commit.signed_header.header.last_commit_hash,
        );
      },
      "header.data_hash": (commit) => {
        commit.signed_header.header.data_hash = flipLastHexNibble(
          commit.signed_header.header.data_hash,
        );
      },
      "header.validators_hash": (commit) => {
        commit.signed_header.header.validators_hash = flipLastHexNibble(
          commit.signed_header.header.validators_hash,
        );
      },
      "header.next_validators_hash": (commit) => {
        commit.signed_header.header.next_validators_hash = flipLastHexNibble(
          commit.signed_header.header.next_validators_hash,
        );
      },
      "header.consensus_hash": (commit) => {
        commit.signed_header.header.consensus_hash = flipLastHexNibble(
          commit.signed_header.header.consensus_hash,
        );
      },
      "header.app_hash": (commit) => {
        commit.signed_header.header.app_hash = flipLastHexNibble(
          commit.signed_header.header.app_hash,
        );
      },
      "header.last_results_hash": (commit) => {
        commit.signed_header.header.last_results_hash = flipLastHexNibble(
          commit.signed_header.header.last_results_hash,
        );
      },
      "header.evidence_hash": (commit) => {
        commit.signed_header.header.evidence_hash = flipLastHexNibble(
          commit.signed_header.header.evidence_hash,
        );
      },
      "header.proposer_address": (commit) => {
        commit.signed_header.header.proposer_address = flipLastHexNibble(
          commit.signed_header.header.proposer_address,
        );
      },
    };

    for (const [field, mutate] of Object.entries(mutators)) {
      const tampered = clone(blockFixture);
      mutate(tampered);

      const out = await verifyCommit(
        importCommit(tampered as unknown as CommitJson),
        vset,
        cryptoIndex,
      );

      expect(out.ok, `${field} tampering should be detected`).toBe(false);
    }
  });
});
