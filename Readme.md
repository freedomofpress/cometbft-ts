# cometbft-ts

_Note: this library has not been audited, thus its security has not been independently verified._

`cometbft-ts` is a small TypeScript library for verifying CometBFT commits in the browser. It takes the JSON you get from CometBFT ABCI/RPC for a `commit` and its `validators`, constructs canonical sign-bytes via protobuf, and verifies Ed25519 signatures and >2/3 quorum. It is verification-only and throws on any cryptographic or format error. Hashing, encoding, Merkle trees and signature verification come from [crypto-browser](https://github.com/freedomofpress/crypto-browser), which uses the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API); applications targeting engines without Ed25519 call `installEd25519Fallback()` from `@freedomofpress/crypto-browser/noble` once at startup. The library is developed as part of [WEBCAT](https://github.com/freedomofpress/webcat) and is **not audited**.

## Usage

```ts
import {
  importCommit,
  importValidators,
  verifyCommit,
} from "@freedomofpress/cometbft";

// JSON from CometBFT RPC: /commit and /validators
const sh = importCommit(commitJson);
const { proto: vset, cryptoIndex } = await importValidators(validatorsJson);

const result = await verifyCommit(sh, vset, cryptoIndex, "my-chain-id");
```

Configure the expected chain ID independently of the RPC response.

## Tests

```bash
$ npm run coverage

> @freedomofpress/cometbft@0.2.0 coverage
> vitest run --coverage


 RUN  v5.0.5 /Users/g/cometbft-ts
      Coverage enabled with v8


 Test Files  4 passed (4)
      Tests  86 passed (86)
   Start at  19:44:23
   Duration  244ms (transform 43%, import 35%, tests 14%, worker 8%)

 % Coverage report from v8
----------------|---------|----------|---------|---------|-------------------
File            | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s
----------------|---------|----------|---------|---------|-------------------
All files       |   95.32 |    93.62 |     100 |   98.06 |
 lightclient.ts |    90.9 |    85.55 |     100 |   96.18 | 48,53-54,155,183
----------------|---------|----------|---------|---------|-------------------

=============================== Coverage summary ===============================
Statements   : 95.32% ( 265/278 )
Branches     : 93.62% ( 191/204 )
Functions    : 100% ( 21/21 )
Lines        : 98.06% ( 254/259 )
================================================================================
```
