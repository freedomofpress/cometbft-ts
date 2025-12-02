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
    expect(out.invalidSignatures).toEqual([
      Uint8ArrayToHex(vset.validators[0].address).toUpperCase(),
    ]);
    expect(out.countedSignatures).toBe(1);
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
    expect(out.signedPower).toBe(0n);
    expect(out.invalidSignatures).toEqual([
      Uint8ArrayToHex(vset.validators[0].address).toUpperCase(),
    ]);
    expect(out.countedSignatures).toBe(1);
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
    expect(out.signedPower).toBe(0n);
    expect(out.invalidSignatures).toEqual([]);
    expect(out.unknownValidators).toEqual([
      "0000000000000000000000000000000000000000",
    ]);
    expect(out.countedSignatures).toBe(0);
  });
});
