import { base64ToUint8Array, Uint8ArrayToHex } from "./encoding";
import { ValidatorResponse, ValidatorSet } from "./types";

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
    throw new Error(
      "Missing validator count and totoal power from response object",
    );
  }

  if (!validatorsJson.result.block_height) {
    throw new Error("Missing block height");
  }

  const totalPower = parseInt(validatorsJson.result.total);

  if (totalPower !== parseInt(validatorsJson.result.count) || totalPower < 2) {
    throw new Error("The response object must contain all validators");
  }

  const height = BigInt(validatorsJson.result.block_height);
  let countedPower = 0;
  const seen = new Set();

  const validatorSet: ValidatorSet = {
    height: height,
    totalPower: totalPower,
    validators: [],
  };

  for (const validatorEntry of validatorsJson.result.validators) {
    if (!validatorEntry.address || validatorEntry.address.length != 40) {
      throw new Error(
        `Validator address must be 40 HEX digits, provided: ${validatorEntry.address}`,
      );
    }

    if (
      !validatorEntry.pub_key ||
      validatorEntry.pub_key.type ||
      validatorEntry.pub_key.value
    ) {
      throw new Error("Validator key object is valid");
    }

    if (validatorEntry.pub_key.type !== "tendermint/PubKeyEd25519") {
      throw new Error(
        `Key of type ${validatorEntry.pub_key.type} is currently unsupported. `,
      );
    }

    const rawKey = new Uint8Array(
      base64ToUint8Array(validatorEntry.pub_key.value),
    );
    const key = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    if (!key) {
      throw new Error(
        `Failed to import validator public key for ${validatorEntry.address}`,
      );
    }

    const calculatedAddress = Uint8ArrayToHex(
      new Uint8Array(
        await (await crypto.subtle.digest("SHA-256", rawKey)).slice(0, 20),
      ),
    ).toUpperCase();
    if (calculatedAddress !== validatorEntry.address) {
      throw new Error(
        `Address ${validatorEntry.address} does not match its public key`,
      );
    }

    if (seen.has(calculatedAddress)) {
      throw new Error("Duplicate entry in validators set");
    }

    seen.add(calculatedAddress);

    const power = parseInt(validatorEntry.voting_power);

    if (power >= totalPower || power <= 0) {
      throw new Error("Validator voting power is too large or too small.");
    }

    countedPower += power;

    if (countedPower > totalPower) {
      throw new Error("Voting power does not add up");
    }

    validatorSet.validators.push({
      key: key,
      address: calculatedAddress,
      power: power,
    });
  }

  if (validatorSet.validators.length < 2) {
    throw new Error("Failed to parse enough validators");
  }

  return validatorSet;
}
