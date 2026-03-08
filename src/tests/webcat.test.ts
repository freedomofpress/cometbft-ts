import { describe, expect, it } from "vitest";

import { importCommit } from "../commit";
import { Uint8ArrayToBase64 } from "../encoding";
import { verifyCommit } from "../lightclient";
import type { CommitJson, ValidatorJson } from "../types";
import { importValidators } from "../validators";
import blockFixture from "./fixtures/webcat.json";

function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

describe("lightclient.verifyCommit", () => {
  it("rejects this fixture when header hash does not match commit block_id.hash", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = blockFixture as unknown as CommitJson;

    const { proto: vset, cryptoIndex } = await importValidators(validators);
    const sh = importCommit(commit);

    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /header hash does not match commit blockid hash/i,
    );
  });

  it("throws when commit block_id.hash does not match header hash", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = clone(blockFixture) as unknown as CommitJson;

    commit.signed_header.commit.block_id.hash =
      "3A1D00CC2A092465E85EA2C24986BEE0105285039DC1873BB6B0CA7F610EC89D";

    const { proto: vset, cryptoIndex } = await importValidators(validators);
    const sh = importCommit(commit);

    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /header hash does not match commit blockid hash/i,
    );
  });

  it("still rejects on header/commit hash mismatch even when a signature is corrupted", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = clone(blockFixture) as unknown as CommitJson;

    commit.signed_header.commit.signatures[0].signature = Uint8ArrayToBase64(
      new Uint8Array(64),
    );

    const { proto: vset, cryptoIndex } = await importValidators(validators);
    const sh = importCommit(commit);

    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /header hash does not match commit blockid hash/i,
    );
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

  it("still rejects on header/commit hash mismatch even when validator is unknown", async () => {
    const validators = blockFixture.validator_set as unknown as ValidatorJson;
    const commit = clone(blockFixture) as unknown as CommitJson;

    commit.signed_header.commit.signatures[0].validator_address =
      "0000000000000000000000000000000000000000";

    const { proto: vset, cryptoIndex } = await importValidators(validators);
    const sh = importCommit(commit);

    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /header hash does not match commit blockid hash/i,
    );
  });
});
