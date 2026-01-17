# pumpfun-sdk
open-source free sdk for pump.fun tokens on solana

## the issue: pump.fun API is very obscure and no one knows how to interact with it on code

## solution: my sdk

---

A Node.js SDK for interacting with **Pump.fun / PumpSwap tokens on Solana**, including:

* Buying tokens (pre-bonded & post-bonded)
* Deploying new Pump tokens
* Claiming creator fees
* Burning tokens
* Wallet derivation & balance checks

Built on `@solana/web3.js`, `@solana/spl-token`, and Jupiter for post-bonded swaps.

---

## Requirements

* **Node.js 18+**
* A Solana RPC endpoint
* Funded Solana wallet

---

## Installation

```bash
npm install
```

Dependencies used:

* `@solana/web3.js`
* `@solana/spl-token`
* `axios`
* `bs58`
* `bip39`
* `ed25519-hd-key`
* `dotenv`

---

## Environment Variables

Create a `.env` file:

```env
RPC_URL=https://your-solana-rpc
```

These are **required**.

---

## Basic Usage

```js
const {
  buyToken,
  deployToken,
  claimCreatorFees,
  getWalletBalance,
} = require('./sdk');
```

---

## Core Concepts

### Bonding States

* **Pre-bonded**: Uses Pump.fun’s native bonding curve
* **Post-bonded**: Routes trades via **Jupiter**

The SDK auto-detects which path to use.

---

## API Reference

---

### `buyToken(options)`

Buy a Pump token using SOL.

**Parameters**

```ts
{
  privateKey: string | Uint8Array,
  mint: string,           // token mint address
  sol: number,            // amount of SOL to spend
  slippageBps?: number    // default: 500 (5%)
}
```

**Returns**

```ts
{
  signature: string,
  tradeLamports: number
}
```

**Example**

```js
await buyToken({
  privateKey: process.env.PRIVATE_KEY,
  mint: "MintAddressHere",
  sol: 0.5,
});
```

---

### `deployToken(options)`

Deploy a new Pump.fun token.

**Parameters**

```ts
{
  privateKey: string,
  name: string,          // max 32 chars
  symbol: string,        // max 10 chars
  metadataUri: string,  // IPFS or HTTPS
  initialBuySol?: number,
  simulate?: boolean,
  mintKeypair: Keypair  // REQUIRED
}
```

**Returns**

```ts
{
  signature: string,
  mint: string,
  bondingCurve: string
}
```

**Example**

```js
await deployToken({
  privateKey,
  name: "My Token",
  symbol: "MTK",
  metadataUri: "https://ipfs.io/ipfs/...",
  initialBuySol: 1,
  mintKeypair,
});
```

---

### `claimCreatorFees(options)`

Claim accumulated creator fees.

**Parameters**

```ts
{
  privateKey: string,
  feeBps?: number // default: 2500 (25%)
}
```

**Returns**

```ts
{
  claimSig: string,
  claimedLamports: number,
  feeSig: string | null,
  feeLamports: number
}
```

---

### `burnTokens(options)`

Burn **all tokens** in your wallet for a given mint.

**Parameters**

```ts
{
  privateKey: string,
  mint: string
}
```

**Returns**

```ts
{
  sig: string | null,
  amount: bigint,
  decimals: number
}
```

---

### `getWalletBalance(pubkey)`

Get SOL balance of a wallet.

```ts
number // SOL
```

**Example**

```js
const sol = await getWalletBalance(walletPubkey);
```

---

### `deriveWallet(index, mnemonic)`

Derive a Solana wallet from a BIP-39 mnemonic.

**Returns**

```ts
{
  publicKey: string,
  privateKey: string,
  index: number
}
```

---

### `preflightCheck(walletPubkey, minSol)`

Ensures:

* RPC is reachable
* Wallet has enough SOL

Throws on failure.

---

### `keypairFromPrivateKey(privateKey)`

Utility to normalize private keys:

* Base58
* Uint8Array
* JSON array

---

## Fees & Internals

* **Priority fees** are auto-calculated
* **Vault fees** are applied during buys
* Uses **Versioned Transactions + ALTs** when routing through Jupiter

---

## Logging

All `console.log` output is also written to:

```
logs.txt
```

(with timestamps)

---

## Notes & Warnings

* This SDK interacts with **live Solana programs**
* Always test with **small amounts**
* RPC quality matters for success rate
* No vanity mint generation included

---

## Exported API routes

```js
module.exports = {
  connection,
  keypairFromPrivateKey,
  tokenProgramForMint,
  applyBuySplit,
  sendTx,
  buyToken,
  claimCreatorFees,
  deployToken,
  deriveWallet,
  getWalletBalance,
  preflightCheck,
  burnTokens,
  getCreatorVaultBalance,
};
```

---

thank u for using my code! please do not monetize any part of this code
side note: i do take a small fee on all transactions on my open source code
if you would like to remove it thats fine :)