import { describe, expect, it } from "vitest";

import { importCommit } from "../commit";
import {
  base64ToUint8Array,
  Uint8ArrayToBase64,
  Uint8ArrayToHex,
} from "../encoding";
import { verifyCommit } from "../lightclient";
import type { CommitResponse, ValidatorResponse } from "../types";
import { importValidators } from "../validators";
import commitFixture from "./fixtures/commit-12.json";
import validatorsFixture from "./fixtures/validators-12.json";

function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

describe("lightclient.verifyCommit", () => {
  it("verifies a valid commit against the validator set", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const cResp = commitFixture as unknown as CommitResponse;

    const { proto: vset, cryptoIndex, height } = await importValidators(vResp);
    const sh = importCommit(cResp);
    expect(height).toBe(sh.commit!.height);

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

  it("fails quorum and invalidates all signatures when block_id.hash is tampered", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);

    const badCommit = clone(commitFixture) as any;
    const h: string = badCommit.result.signed_header.commit.block_id.hash;
    badCommit.result.signed_header.commit.block_id.hash =
      h.slice(0, -2) + (h.slice(-2) === "00" ? "01" : "00");

    const sh = importCommit(badCommit as CommitResponse);
    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(false);
    expect(out.invalidSignatures.length).toBe(out.countedSignatures);
    expect(out.ok).toBe(false);
  });

  it("drops below 2/3 quorum when two votes are ABSENT", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);

    const lowPower = clone(commitFixture) as any;
    for (let i = 0; i < 2; i++) {
      lowPower.result.signed_header.commit.signatures[i].block_id_flag = 1;
      lowPower.result.signed_header.commit.signatures[i].signature = "";
    }

    const sh = importCommit(lowPower as CommitResponse);
    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(false);
    expect(out.ok).toBe(false);
    expect(out.invalidSignatures.length).toBe(0);
  });

  it("keeps quorum when one signature is corrupted and reports it as invalid", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);

    const badSigResp = clone(commitFixture) as any;
    const sigB64: string =
      badSigResp.result.signed_header.commit.signatures[0].signature;
    const sigBytes = base64ToUint8Array(sigB64);
    sigBytes[0] ^= 0x01;
    badSigResp.result.signed_header.commit.signatures[0].signature =
      Uint8ArrayToBase64(sigBytes);

    const sh = importCommit(badSigResp as CommitResponse);
    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(true);
    expect(out.invalidSignatures.length).toBe(1);
    expect(out.ok).toBe(true);
  });

  it("adds 0 power when a validator's votingPower is undefined but signature is valid", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);

    const vsetZeroOne = {
      validators: vset.validators.map((vv, i) =>
        i === 0 ? { ...vv, votingPower: undefined as any } : vv,
      ),
      proposer: vset.proposer,
      totalVotingPower: vset.totalVotingPower, // still 4n
    } as any;

    const out = await verifyCommit(sh, vsetZeroOne, cryptoIndex);

    expect(out.countedSignatures).toBe(4);
    expect(out.invalidSignatures.length).toBe(0);
    expect(out.signedPower).toBe(out.totalPower - 1n); // 3n of 4n
    expect(out.quorum).toBe(true);
    expect(out.ok).toBe(true);
  });

  it("throws when SignedHeader is missing header/commit", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);

    delete (sh as any).header;
    await expect(verifyCommit(sh as any, vset, cryptoIndex)).rejects.toThrow(
      /SignedHeader missing header\/commit/i,
    );
  });

  it("throws on header/commit height mismatch", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);
    (sh.commit as any).height = 13n;
    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /height mismatch/i,
    );
  });

  it("throws when validator set is empty", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset0, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);
    const vset = { ...vset0, validators: [] };
    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /no validators/i,
    );
  });

  it("throws when validator set totalVotingPower is missing (defaults to 0n)", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);

    const vsetMissing = {
      validators: vset.validators,
      proposer: vset.proposer,
      totalVotingPower: undefined as any, // triggers ?? 0n path
    } as any;

    await expect(verifyCommit(sh, vsetMissing, cryptoIndex)).rejects.toThrow(
      /total power must be positive/i,
    );
  });

  it("throws when total voting power is non-positive", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset0, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);
    const vset = { ...vset0, totalVotingPower: 0n };
    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /total power/i,
    );
  });

  it("throws on duplicate validator address in the set", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset0, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);
    const dup = vset0.validators[0];
    const vset = { ...vset0, validators: [...vset0.validators, dup] };
    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /duplicate validator address/i,
    );
  });

  it("throws when commit BlockID is missing", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);
    (sh.commit as any).blockId = undefined;
    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /missing blockid/i,
    );
  });

  it("throws when PartSetHeader is missing or malformed", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);

    const sh1 = importCommit(commitFixture as unknown as CommitResponse);
    (sh1.commit!.blockId as any).partSetHeader = undefined;
    await expect(verifyCommit(sh1, vset, cryptoIndex)).rejects.toThrow(
      /partsetheader is missing/i,
    );

    const sh2 = importCommit(commitFixture as unknown as CommitResponse);
    (sh2.commit!.blockId!.partSetHeader as any).hash = new Uint8Array(0);
    await expect(verifyCommit(sh2, vset, cryptoIndex)).rejects.toThrow(
      /partsetheader hash is missing/i,
    );
  });

  it("throws when PartSetHeader.total is invalid", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);
    (sh.commit!.blockId!.partSetHeader as any).total = -1;
    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /total is invalid/i,
    );
  });

  it("collects unknown validator addresses without counting them", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);

    const u = new Uint8Array(20);
    u.fill(0xff);
    sh.commit!.signatures[0].validatorAddress = u;

    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(true);
    expect(out.ok).toBe(true);
    expect(out.unknownValidators.length).toBe(1);
    expect(out.invalidSignatures.length).toBe(0);
    expect(out.countedSignatures).toBe(3);
  });

  it("marks a COMMIT with empty signature as invalid and does not count it", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);

    sh.commit!.signatures[1].signature = new Uint8Array(0);

    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.invalidSignatures.length).toBe(1);
    expect(out.countedSignatures).toBe(3);
    expect(out.quorum).toBe(true);
    expect(out.ok).toBe(true);
  });

  it("keeps quorum when one verify() call throws (caught) and marks that vote invalid", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);

    const originalVerify = crypto.subtle.verify.bind(crypto.subtle) as (
      ...args: Parameters<SubtleCrypto["verify"]>
    ) => ReturnType<SubtleCrypto["verify"]>;

    let calls = 0;

    (crypto.subtle as any).verify = (
      ...args: Parameters<SubtleCrypto["verify"]>
    ): ReturnType<SubtleCrypto["verify"]> => {
      calls += 1;
      if (calls === 1) {
        return Promise.reject(new Error("forced verify error")) as ReturnType<
          SubtleCrypto["verify"]
        >;
      }
      return originalVerify(...args);
    };

    try {
      const out = await verifyCommit(sh, vset, cryptoIndex);
      expect(out.quorum).toBe(true);
      expect(out.ok).toBe(true);
      expect(out.invalidSignatures.length).toBe(1);
      expect(out.countedSignatures).toBe(4);
    } finally {
      (crypto.subtle as any).verify = originalVerify;
    }
  });

  it("treats a known validator without a crypto key as invalid but still counts the vote attempt", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);

    const addrHex = Uint8ArrayToHex(
      sh.commit!.signatures[0].validatorAddress,
    ).toUpperCase();
    cryptoIndex.delete(addrHex);

    const out = await verifyCommit(sh, vset, cryptoIndex);

    expect(out.quorum).toBe(true);
    expect(out.ok).toBe(true);
    expect(out.invalidSignatures.includes(addrHex)).toBe(true);
    expect(out.countedSignatures).toBe(4);
  });

  it("throws when BlockID hash is empty", async () => {
    const vResp = validatorsFixture as unknown as ValidatorResponse;
    const { proto: vset, cryptoIndex } = await importValidators(vResp);
    const sh = importCommit(commitFixture as unknown as CommitResponse);
    (sh.commit!.blockId as any).hash = new Uint8Array(0);
    await expect(verifyCommit(sh, vset, cryptoIndex)).rejects.toThrow(
      /blockid hash is missing/i,
    );
  });
});
