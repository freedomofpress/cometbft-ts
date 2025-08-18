import { describe, expect, it } from "vitest";

import { Uint8ArrayToBase64 } from "../encoding";
import { ValidatorResponse } from "./../types";
import { importValidators } from "./../validator";

/* eslint-disable @typescript-eslint/no-explicit-any */

async function sha256(u8: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", new Uint8Array(u8));
  return new Uint8Array(buf);
}

function hexOf(u8: Uint8Array): string {
  let out = "";
  for (let i = 0; i < u8.length; i++)
    out += u8[i].toString(16).padStart(2, "0");
  return out;
}

function filledBytes(seed: number, len = 32): Uint8Array {
  const u = new Uint8Array(len);
  u.fill(seed & 0xff);
  // small variation so different seeds give different keys
  if (len > 0) u[0] = (seed * 17) & 0xff;
  if (len > 1) u[len - 1] = (seed * 29) & 0xff;
  return u;
}

async function makeValidatorEntry(
  pub: Uint8Array,
  power: number,
  opts?: { lowercaseAddr?: boolean; keyType?: string },
) {
  const keyType = opts?.keyType ?? "tendermint/PubKeyEd25519";
  const addr = hexOf((await sha256(pub)).slice(0, 20));
  return {
    address: opts?.lowercaseAddr ? addr : addr.toUpperCase(),
    pub_key: { type: keyType, value: Uint8ArrayToBase64(pub) },
    voting_power: String(power),
    proposer_priority: "0",
  };
}

function makeResponse(
  entries: any[],
  height = "12",
  countOverride?: string,
  totalOverride?: string,
): ValidatorResponse {
  const count = countOverride ?? String(entries.length);
  const total = totalOverride ?? String(entries.length);
  return {
    jsonrpc: "2.0",
    id: -1,
    result: {
      block_height: height,
      validators: entries,
      count,
      total,
    },
  };
}

// ---------------------- tests -------------------------

describe("importValidators (browser crypto)", () => {
  it("happy path: imports full single-page set and sums number power", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const v2 = await makeValidatorEntry(filledBytes(2), 2);
    const v3 = await makeValidatorEntry(filledBytes(3), 3);
    const v4 = await makeValidatorEntry(filledBytes(4), 4);
    const resp = makeResponse([v1, v2, v3, v4], "42");

    const set = await importValidators(resp);

    expect(set.height).toBe(42n);
    expect(set.validators).toHaveLength(4);
    expect(set.totalPower).toBe(10); // 1+2+3+4
    for (const v of set.validators) {
      expect(v.address).toMatch(/^[0-9A-F]{40}$/);
      expect(typeof v.power).toBe("number");
      expect(v.power).toBeGreaterThanOrEqual(1);
    }
  });

  it("accepts lowercase input addresses but normalizes to uppercase internally", async () => {
    const v1 = await makeValidatorEntry(filledBytes(10), 1, {
      lowercaseAddr: true,
    });
    const v2 = await makeValidatorEntry(filledBytes(11), 1, {
      lowercaseAddr: true,
    });
    const resp = makeResponse([v1, v2], "99");

    const set = await importValidators(resp);
    expect(set.validators[0].address).toBe(
      set.validators[0].address.toUpperCase(),
    );
    expect(set.validators[1].address).toBe(
      set.validators[1].address.toUpperCase(),
    );
  });

  it("throws when the response paginates (count !== total)", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const v2 = await makeValidatorEntry(filledBytes(2), 1);
    const resp = makeResponse([v1, v2], "1", /*count*/ "2", /*total*/ "3");
    await expect(importValidators(resp)).rejects.toThrow(/must not paginate/i);
  });

  it("throws when validators.length !== count (mismatch)", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const v2 = await makeValidatorEntry(filledBytes(2), 1);
    // Your current implementation only catches this at the final length check.
    const resp = makeResponse([v1, v2], "1", /*count*/ "3", /*total*/ "3");
    await expect(importValidators(resp)).rejects.toThrow(
      /Failed to parse enough validators/i,
    );
  });

  it("throws on missing block height", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const resp = makeResponse([v1], ""); // empty height
    // Manually blank the height to trigger the check exactly
    (resp.result as any).block_height = "";
    await expect(importValidators(resp)).rejects.toThrow(
      /Missing block height/,
    );
  });

  it("throws on invalid address (wrong length/format)", async () => {
    const pub = filledBytes(1);
    const good = await makeValidatorEntry(pub, 1);
    const bad = { ...good, address: good.address.slice(0, 39) }; // 39 chars
    const resp = makeResponse([bad, good], "7");
    await expect(importValidators(resp)).rejects.toThrow(/address.*40/i);
  });

  it("throws on invalid pub_key object", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const bad = { ...v1, pub_key: { type: "tendermint/PubKeyEd25519" } }; // missing value
    const resp = makeResponse([bad, v1], "7");
    await expect(importValidators(resp)).rejects.toThrow(
      /key object is invalid/i,
    );
  });

  it("throws on unsupported pub_key.type", async () => {
    const bad = await makeValidatorEntry(filledBytes(1), 1, {
      keyType: "tendermint/PubKeySecp256k1",
    });
    const v2 = await makeValidatorEntry(filledBytes(2), 1);
    const resp = makeResponse([bad, v2], "7");
    await expect(importValidators(resp)).rejects.toThrow(/unsupported/i);
  });

  it("throws on wrong pubkey length (31 bytes)", async () => {
    const pub31 = filledBytes(5, 31); // 31 bytes
    const vBad = await makeValidatorEntry(pub31, 1);
    const v2 = await makeValidatorEntry(filledBytes(2), 1);
    const resp = makeResponse([vBad, v2], "7");
    // Real SubtleCrypto.importKey will reject for invalid length
    await expect(importValidators(resp)).rejects.toThrow();
  });

  it("throws on address/pubkey mismatch", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const v2 = await makeValidatorEntry(filledBytes(2), 1);
    // Corrupt v2's address to mismatch
    (v2 as any).address = v1.address; // duplicate/mismatch
    const resp = makeResponse([v1, v2], "7");
    await expect(importValidators(resp)).rejects.toThrow(
      /does not match its public key|mismatch/i,
    );
  });

  it("throws on duplicate address", async () => {
    // Use the exact same key twice
    const pub = filledBytes(9);
    const v1 = await makeValidatorEntry(pub, 1);
    const v2 = await makeValidatorEntry(pub, 1); // same address
    const resp = makeResponse([v1, v2], "7");
    await expect(importValidators(resp)).rejects.toThrow(/Duplicate entry/i);
  });

  it("throws on invalid voting power (non-integer / <1)", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 0); // invalid: zero
    const v2 = await makeValidatorEntry(filledBytes(2), 1);
    const resp = makeResponse([v1, v2], "7");
    await expect(importValidators(resp)).rejects.toThrow(
      /Invalid voting power/i,
    );
  });

  it("throws when final length check fails (validators.length !== total)", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const v2 = await makeValidatorEntry(filledBytes(2), 1);
    const v3 = await makeValidatorEntry(filledBytes(3), 1);
    // Say total is 4 but only 3 entries provided
    const resp = makeResponse([v1, v2, v3], "7", /*count*/ "4", /*total*/ "4");
    await expect(importValidators(resp)).rejects.toThrow(
      /Failed to parse enough validators/i,
    );
  });
});
