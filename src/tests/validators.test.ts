import { describe, expect, it } from "vitest";

import {
  base64ToUint8Array,
  Uint8ArrayToBase64,
  Uint8ArrayToHex,
} from "../encoding";
import type { ValidatorJson } from "../types";
import { importValidators } from "../validators";
import validatorsFixture from "./fixtures/validators-12.json";

/* eslint-disable @typescript-eslint/no-explicit-any */

async function sha256(u8: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", new Uint8Array(u8));
  return new Uint8Array(buf);
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
  const addr = Uint8ArrayToHex((await sha256(pub)).slice(0, 20));
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
): ValidatorJson {
  const count = countOverride ?? String(entries.length);
  const total = totalOverride ?? String(entries.length);
  return {
    block_height: height,
    validators: entries,
    count,
    total,
  };
}
// ---------------------- tests -------------------------

describe("importValidators (browser crypto)", () => {
  it("happy path: imports full single-page set and sums power", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const v2 = await makeValidatorEntry(filledBytes(2), 2);
    const v3 = await makeValidatorEntry(filledBytes(3), 3);
    const v4 = await makeValidatorEntry(filledBytes(4), 4);
    const resp = makeResponse([v1, v2, v3, v4], "42");

    const out = await importValidators(resp);

    expect(out.proto.validators).toHaveLength(4);
    expect(out.proto.totalVotingPower).toBe(10n); // 1+2+3+4

    // cryptoIndex should have 4 entries keyed by uppercase hex
    expect(out.cryptoIndex.size).toBe(4);
    for (const [addrHex, key] of out.cryptoIndex.entries()) {
      expect(addrHex).toMatch(/^[0-9A-F]{40}$/);
      expect(key.type).toBe("public");
      expect((key.algorithm as EcKeyAlgorithm).name).toBe("Ed25519");
      expect(key.usages).toEqual(["verify"]);
      expect(key.extractable).toBe(false);
    }

    // proto validators should have bytes + bigint fields
    for (const pv of out.proto.validators) {
      expect(pv.address instanceof Uint8Array).toBe(true);
      expect(pv.address.length).toBe(20);
      expect(typeof pv.votingPower).toBe("bigint");
      expect(pv.votingPower).toBeGreaterThanOrEqual(1n);
      expect(pv.pubKeyType).toBe("ed25519");
      expect(pv.pubKeyBytes instanceof Uint8Array).toBe(true);
      expect(pv.pubKeyBytes.length).toBe(32);
    }
  });

  it("accepts lowercase input addresses but normalizes keys to uppercase in cryptoIndex", async () => {
    const v1 = await makeValidatorEntry(filledBytes(10), 1, {
      lowercaseAddr: true,
    });
    const v2 = await makeValidatorEntry(filledBytes(11), 1, {
      lowercaseAddr: true,
    });
    const resp = makeResponse([v1, v2], "99");

    const out = await importValidators(resp);

    // Derive expected addresses (uppercase) from pubkeys and confirm present in cryptoIndex
    for (const e of resp.validators) {
      const pubRaw = base64ToUint8Array(e.pub_key.value);
      const derived = Uint8ArrayToHex(
        (await sha256(pubRaw)).slice(0, 20),
      ).toUpperCase();
      expect(out.cryptoIndex.has(derived)).toBe(true);
    }
  });

  it("throws when validators array is empty", async () => {
    const resp = {
      jsonrpc: "2.0",
      id: -1,
      result: {
        block_height: "12",
        validators: [], // <-- empty
        count: "0",
        total: "0",
      },
    } as any;

    await expect(importValidators(resp)).rejects.toThrow(/Missing validators/i);
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
    await expect(importValidators(resp)).rejects.toThrow();
  });

  it("throws on address/pubkey mismatch", async () => {
    const v1 = await makeValidatorEntry(filledBytes(1), 1);
    const v2 = await makeValidatorEntry(filledBytes(2), 1);
    (v2 as any).address = v1.address; // duplicate/mismatch
    const resp = makeResponse([v1, v2], "7");
    await expect(importValidators(resp)).rejects.toThrow(
      /does not match its public key|mismatch/i,
    );
  });

  it("throws on duplicate address", async () => {
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
});

describe("validators fixture:", () => {
  it("derives address as SHA-256(pubkey)[0..20] (uppercased)", async () => {
    const resp = validatorsFixture as unknown as ValidatorJson;

    for (const entry of resp.validators) {
      const pubRaw = base64ToUint8Array(entry.pub_key.value);
      const derived = Uint8ArrayToHex(
        (await sha256(pubRaw)).slice(0, 20),
      ).toUpperCase();
      expect(derived).toBe(entry.address.toUpperCase());
    }
  });

  it("imports Ed25519 keys and fills proto validators correctly", async () => {
    const resp = validatorsFixture as unknown as ValidatorJson;

    const out = await importValidators(resp);

    expect(out.proto.validators).toHaveLength(4);
    expect(out.proto.totalVotingPower).toBe(4n);

    // cryptoIndex: correct WebCrypto attributes
    for (const key of out.cryptoIndex.values()) {
      expect(key.type).toBe("public");
      expect((key.algorithm as EcKeyAlgorithm).name).toBe("Ed25519");
      expect(key.usages).toEqual(["verify"]);
      expect(key.extractable).toBe(false);
      await expect(crypto.subtle.exportKey("raw", key)).rejects.toBeTruthy();
    }

    // proto validators content matches derived bytes
    for (const e of resp.validators) {
      const pubRaw = base64ToUint8Array(e.pub_key.value);
      const sha = await sha256(pubRaw);
      const addr20 = sha.slice(0, 20);

      const match = out.proto.validators.find(
        (pv) => Uint8ArrayToHex(pv.address) === Uint8ArrayToHex(addr20),
      );
      expect(match).toBeTruthy();
      expect(match!.pubKeyType).toBe("ed25519");
      expect(Uint8ArrayToHex(match!.pubKeyBytes)).toBe(Uint8ArrayToHex(pubRaw));
      expect(match!.votingPower).toBe(1n);
    }
  });
});
