import { base64ToUint8Array, Uint8ArrayToHex } from "./encoding";
import { Validator, ValidatorSet } from "./proto/cometbft/types/v1/validator";
import type { ValidatorJson } from "./types";

export async function importValidators(resp: ValidatorJson): Promise<{
  proto: ValidatorSet;
  cryptoIndex: Map<string, CryptoKey>;
}> {
  const seen: Set<string> = new Set();
  const cryptoIndex = new Map<string, CryptoKey>();
  const protoValidators: Validator[] = [];

  if (!resp.validators || resp.validators.length < 1) {
    throw new Error("Missing validators");
  }
  let countedPower = 0n;

  for (const v of resp.validators) {
    if (!v.address || v.address.length !== 40) {
      throw new Error(
        `Validator address must be 40 HEX digits, provided: ${v.address}`,
      );
    }
    if (!v.pub_key?.type || !v.pub_key?.value) {
      throw new Error("Validator key object is invalid");
    }
    if (v.pub_key.type !== "tendermint/PubKeyEd25519") {
      throw new Error(
        `Key of type ${v.pub_key.type} is currently unsupported.`,
      );
    }

    const rawKey = base64ToUint8Array(v.pub_key.value);
    const key = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(rawKey),
      { name: "Ed25519" },
      false,
      ["verify"],
    );

    const sha = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new Uint8Array(rawKey)),
    );
    const addrHex = Uint8ArrayToHex(sha.slice(0, 20)).toUpperCase();

    if (addrHex !== v.address.toUpperCase()) {
      throw new Error(`Address ${v.address} does not match its public key`);
    }
    if (seen.has(addrHex)) {
      throw new Error("Duplicate entry in validators set");
    }
    seen.add(addrHex);
    cryptoIndex.set(addrHex, key);

    const powerNum = Number(v.voting_power) || Number(v.power);
    if (
      !Number.isFinite(powerNum) ||
      !Number.isInteger(powerNum) ||
      powerNum < 1
    ) {
      throw new Error(`Invalid voting power for ${addrHex}`);
    }
    countedPower += BigInt(powerNum);

    const protoV: Validator = {
      address: new Uint8Array(sha.slice(0, 20)),
      pubKeyBytes: rawKey,
      pubKeyType: "ed25519",
      votingPower: BigInt(powerNum),
      proposerPriority: 0n, // JSON gives string "0"; use 0n by default
    };

    protoValidators.push(protoV);
  }

  const protoSet: ValidatorSet = {
    validators: protoValidators,
    proposer: undefined,
    totalVotingPower: countedPower,
  };

  return { proto: protoSet, cryptoIndex };
}
