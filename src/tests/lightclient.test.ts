// src/__tests__/lightclient.spec.ts
import { describe, it, expect } from "vitest";

import validatorsFixture from "./fixtures/validators-12.json";
import commitFixture from "./fixtures/commit-12.json";

import { importValidatorSetProto } from "../validators";
import { importCommit } from "../commit";
import { verifyCommit } from "../lightclient";
import type { CommitResponse, ValidatorResponse } from "../types";
import { base64ToUint8Array, Uint8ArrayToBase64 } from "../encoding";

// Deep-clone a JSON-ish object
function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

describe("lightclient.verifyCommit", () => {
  it("happy path: verifies commit against validator set (quorum, ok)", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const cResp = commitFixture as unknown as CommitResponse;

    const { proto: vset, cryptoIndex, height } = await importValidatorSetProto(vResp);
    const sh = importCommit(cResp);

    // basic sanity on shared height
    expect(height).toBe(sh.commit!.height);

    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(true);
    expect(out.ok).toBe(true);

    // signed power should be positive and never exceed total
    expect(out.signedPower > 0n).toBe(true);
    expect(out.signedPower <= out.totalPower).toBe(true);

    // helpful metadata is present
    expect(out.headerTime).toBeDefined();
    expect(out.appHash instanceof Uint8Array).toBe(true);
    expect(out.blockIdHash instanceof Uint8Array).toBe(true);

    // no diagnostics in happy path
    expect(out.unknownValidators.length).toBe(0);
    expect(out.invalidSignatures.length).toBe(0);
    expect(out.countedSignatures).toBeGreaterThan(0);
  });

  it("fails quorum if commit.block_id.hash is tampered (all signatures invalid)", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidatorSetProto(vResp);

    const badCommit = clone(commitFixture) as any;
    // Flip one byte of the block_id.hash (hex): replace last two hex chars
    const h: string = badCommit.result.signed_header.commit.block_id.hash;
    badCommit.result.signed_header.commit.block_id.hash = h.slice(0, -2) + (h.slice(-2) === "00" ? "01" : "00");

    const sh = importCommit(badCommit as CommitResponse);
    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(false);
    // all COMMIT sigs should fail verification
    expect(out.invalidSignatures.length).toBe(out.countedSignatures);
    expect(out.ok).toBe(false);
  });

  it("drops below 2/3 quorum if two COMMIT votes are marked ABSENT", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidatorSetProto(vResp);

    const lowPower = clone(commitFixture) as any;
    // For the first two signatures, set block_id_flag to 1 (ABSENT) and remove signature bytes.
    // (BLOCK_ID_FLAG_COMMIT == 2 in your generated enums; ABSENT == 1)
    for (let i = 0; i < 2; i++) {
      lowPower.result.signed_header.commit.signatures[i].block_id_flag = 1;
      lowPower.result.signed_header.commit.signatures[i].signature = ""; // strip it
    }

    const sh = importCommit(lowPower as CommitResponse);
    const out = await verifyCommit(sh, vset, cryptoIndex);

    // With 4 equal-power validators in the fixture, > 2/3 means at least 3 must sign.
    // We turned 2 to ABSENT, so quorum should fail.
    expect(out.quorum).toBe(false);
    expect(out.ok).toBe(false);
    // the two ABSENTs aren't counted nor "invalid", so invalidSignatures should be 0 here
    expect(out.invalidSignatures.length).toBe(0);
  });

  it("keeps quorum if only one signature is corrupted, but reports it as invalid", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidatorSetProto(vResp);

    const badSigResp = clone(commitFixture) as any;

    // Corrupt the first signature by flipping a byte (base64 <-> bytes)
    const sigB64: string = badSigResp.result.signed_header.commit.signatures[0].signature;
    const sigBytes = base64ToUint8Array(sigB64);
    sigBytes[0] ^= 0x01; // flip 1 bit
    badSigResp.result.signed_header.commit.signatures[0].signature = Uint8ArrayToBase64(sigBytes);

    const sh = importCommit(badSigResp as CommitResponse);
    const out = await verifyCommit(sh, vset, cryptoIndex);

    // We expect quorum to still hold (3/4 valid if all powers equal)
    expect(out.quorum).toBe(true);
    // But exactly one signature should be marked invalid
    expect(out.invalidSignatures.length).toBe(1);
    expect(out.ok).toBe(true); // ok stays true (quorum + no invalid among counted COMMITs except this one)
  });
});
