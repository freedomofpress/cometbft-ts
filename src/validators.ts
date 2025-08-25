import { base64ToUint8Array, Uint8ArrayToHex } from "./encoding";
import { Validator, ValidatorResponse, ValidatorSet } from "./types";

export async function importValidators(
  validatorsJson: ValidatorResponse,
): Promise<ValidatorSet> {
  if (
    !validatorsJson.result ||
    !validatorsJson.result.validators ||
    validatorsJson.result.validators.length < 1
  ) {
    throw new Error("Missing validators from response object");
  }

  if (!validatorsJson.result.count || !validatorsJson.result.total) {
    throw new Error("Missing validator count and total from response object");
  }

  if (!validatorsJson.result.block_height) {
    throw new Error("Missing block height");
  }

  const total = Number(validatorsJson.result.total);

  if (total !== Number(validatorsJson.result.count) || total < 2) {
    throw new Error("The response object must not paginate");
  }

  const height = BigInt(validatorsJson.result.block_height);
  let countedPower = 0;
  const seen: Set<string> = new Set();
  const validators: Validator[] = [];

  for (const validatorEntry of validatorsJson.result.validators) {
    if (!validatorEntry.address || validatorEntry.address.length != 40) {
      throw new Error(
        `Validator address must be 40 HEX digits, provided: ${validatorEntry.address}`,
      );
    }

    if (
      !validatorEntry.pub_key ||
      !validatorEntry.pub_key.type ||
      !validatorEntry.pub_key.value
    ) {
      throw new Error("Validator key object is invalid");
    }

    if (validatorEntry.pub_key.type !== "tendermint/PubKeyEd25519") {
      throw new Error(
        `Key of type ${validatorEntry.pub_key.type} is currently unsupported. `,
      );
    }

    const rawKey = new Uint8Array(
      base64ToUint8Array(validatorEntry.pub_key.value),
    );
    // Should throw in case of error
    const key = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "Ed25519" },
      false,
      ["verify"],
    );

    const calculatedAddress = Uint8ArrayToHex(
      new Uint8Array(await crypto.subtle.digest("SHA-256", rawKey)).slice(
        0,
        20,
      ),
    ).toUpperCase();
    if (calculatedAddress !== validatorEntry.address.toUpperCase()) {
      throw new Error(
        `Address ${validatorEntry.address} does not match its public key`,
      );
    }

    if (seen.has(calculatedAddress)) {
      throw new Error("Duplicate entry in validators set");
    }

    seen.add(calculatedAddress);

    const power = Number(validatorEntry.voting_power);

    if (!Number.isFinite(power) || !Number.isInteger(power) || power < 1) {
      throw new Error(`Invalid voting power for ${calculatedAddress}`);
    }

    countedPower += power;

    validators.push({
      key: key,
      address: calculatedAddress,
      power: power,
    });
  }

  const validatorSet: ValidatorSet = {
    height: height,
    totalPower: countedPower,
    validators: validators,
  };

  if (validatorSet.validators.length < 2 || validators.length !== total) {
    throw new Error("Failed to parse enough validators");
  }

  return validatorSet;
}
