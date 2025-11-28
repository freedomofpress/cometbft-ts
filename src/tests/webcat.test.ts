import { describe, expect, it } from "vitest";

import { importCommit } from "../commit";
import {
  base64ToUint8Array,
  Uint8ArrayToBase64,
  Uint8ArrayToHex,
} from "../encoding";
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
});
