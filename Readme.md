# cometbft-ts

*Note: this library has not been audited, thus its security has not been independently verified.*

`cometbft-ts` is a small TypeScript library for verifying CometBFT commits in the browser. It takes the JSON you get from CometBFT ABCI/RPC for a `commit` and its `validators`, constructs canonical sign-bytes via protobuf, and verifies Ed25519 signatures and >2/3 quorum. It is verification-only and throws on any cryptographic or format error. It uses the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The library was developed as part of **WEBCAT** and is **not audited**.

## Usage

```ts
import { importCommit } from "./src/commit";
import { importValidators } from "./src/validators";
import { verifyCommit } from "./src/lightclient";

// JSON from CometBFT RPC: /commit and /validators
const sh = importCommit(commitJson);
const { proto: vset, cryptoIndex } = await importValidators(validatorsJson);

const result = await verifyCommit(sh, vset, cryptoIndex);
```

## Tests

Paste your test output here. For example:

```bash
$ npm run coverage
> cometbft@0.1.0 coverage
> vitest run --coverage


 RUN  v3.2.4 /Users/g/cometbft-ts
      Coverage enabled with v8

 ✓ src/tests/encoding.test.ts (6 tests) 2ms
 ✓ src/tests/commit.test.ts (27 tests) 7ms
 ✓ src/tests/validators.test.ts (18 tests) 13ms
 ✓ src/tests/lightclient.test.ts (19 tests) 11ms

 Test Files  4 passed (4)
      Tests  70 passed (70)
   Start at  20:45:26
   Duration  377ms (transform 133ms, setup 0ms, collect 222ms, tests 33ms, environment 0ms, prepare 241ms)

 % Coverage report from v8
----------------|---------|----------|---------|---------|-------------------
File            | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s 
----------------|---------|----------|---------|---------|-------------------
All files       |     100 |      100 |     100 |     100 |                   
 commit.ts      |     100 |      100 |     100 |     100 |                   
 encoding.ts    |     100 |      100 |     100 |     100 |                   
 lightclient.ts |     100 |      100 |     100 |     100 |                   
 types.ts       |       0 |        0 |       0 |       0 |                   
 validators.ts  |     100 |      100 |     100 |     100 |                   
----------------|---------|----------|---------|---------|-------------------
```
