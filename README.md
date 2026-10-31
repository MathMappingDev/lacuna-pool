# Lacuna

Privacy pool on Solana. Proofs are built on the user's device with Circom and Groth16. Addresses use the `0LcnZK` prefix. There is no Lacuna server and no wallet UI in this repository.

Notes sit in a shared vault. Relayers pay fees only; they never hold user tokens. Private swaps use a **one-shot escrow** plus an allowlisted hop (Jupiter in production, a dummy AMM in tests). The circuit is Lacuna's `Transact(16)` (2 in / 2 out).

Devnet program ids (after you fund the deployer and run `npm run deploy:devnet`) are written to `deployments/devnet.json`.

## What it is

- `lacuna-pool` — shared note pool. Shield SOL, any safe SPL / Token-2022 mint, or a 1-unit NFT mint. Private send. Withdraw. Isolated `swap_prepare` / `swap_execute` / `swap_refund`.
- TypeScript SDK — keys, notes, proofs, scan, escrow swaps.
- `dummy-amm` — 1:1 test hop so localnet can exercise the escrow without Jupiter.
- `lacuna-relay` — leftover program id only. Relayers are off-chain fee payers; they do not hold user tokens.

## How a private swap works

1. Your proof unshields the input into a PDA escrow derived from the spent nullifier. Only that swap can sign it.
2. `swap_execute` runs an **allowlisted** hop against that escrow. The vault must receive at least `min_out`. The output note is always `min_out` minus the swap fee; any extra hop surplus is protocol fee. The input ATA must end empty. Native SOL and transfer-fee mints cannot be swap legs.
3. Output is shielded to the `owner_hash` bound in the proof. The hop cannot touch the rest of the pool.
4. If the hop never runs, `swap_refund` returns the escrow to a note for that same `owner_hash`, minus the swap fee. Refund stays available when swaps are paused. The preparing payer can refund immediately; after `refund_delay_slots` (default 200, owner-set 150–300) anyone may, and they cannot choose the recipient. Escrow and ATA rent return to the preparer.

The proof binds `keccak` of the execute ciphertext and the refund ciphertext. A relayer must submit those exact buffers; garbage encryption is rejected. The execute ciphertext carries `(blinding, token)` with value omitted (scan reads the public net on the note). The refund ciphertext carries the full net known at prepare. `reject_extra_escrow_token_accounts` only sees hop accounts present at the start of the CPI — keep `min_out` tight so an allowlisted hop cannot siphon through an ATA it creates mid-call.

There is no shared leftover pile and no permissionless `reshield`.

## Fees and authority

Shield, unshield, and swap start at 20 bps (0.20%). Private sends have no protocol fee. The owner can set each from 0 to 100 bps (1%). The treasury pulls `fee_balance` and cannot touch note balances. The owner cannot withdraw notes or transfer ownership.

The owner can pause deposits, private sends, and swaps. Withdrawals stay open unless `pause_exits` is used (at most 3 days, 7 days between pauses). The swap hop is allowlisted with `set_swap_program`.

`initialize` must be signed by the upgrade authority when one is set. Freeze that key after init.

## Tokens

Native SOL is token id `0`. Every mint is `keccak256(mint) % FIELD` (rejected if that is 0). Anyone's first shield opens the vault. Mints with a transfer hook, permanent delegate, default-frozen accounts, non-transferable, pausable, mint-close, or confidential-transfer extension are refused. Token-2022 transfer fees are allowed: the note is for the amount the vault actually received, minus the protocol fee.

## Layout

A Solana transaction is 1232 bytes, so the Groth16 proof (800 bytes) and ciphertexts live in buffer accounts the SDK writes first. Swaps are two transactions: prepare, then execute.

Nullifiers, used commitments, and every Merkle root are PDAs so old proofs never expire. Encrypted notes are stored in note PDAs so scan does not depend on RPC log retention.

Recipient and tip fields in the proof are `keccak256(pubkey) % FIELD`. For a swap, the recipient is the escrow PDA and `externalHash` is the swap commitment (hop, output mint, min out, output owner hash, refund owner hash).

Clients precompute the next note and root PDAs from `next_index` and pass that index as `expected_index`. Two inserts in the same slot race: the loser gets `StaleTree` and the SDK retries up to three times.

Proof and cipher buffers can be closed with `closeBuffers` to recover their rent. Marker PDAs stay forever.

## Build and test

Rust, Solana CLI, and Anchor 0.31.1 are required.

```bash
npm install
anchor build
anchor test
```

Do not rebuild `circuits/transact.circom` unless you also replace the verifying key in `programs/lacuna-pool/src/verifying_key.rs`.

## Deploy on Devnet

```bash
npm run deploy:devnet
```

The first run prints a deployer address. Send it about 2 SOL on Devnet and run the command again. The deployer is the treasury. After init, set the swap hop (`set_swap_program`) to the Jupiter program you want to allow. Devnet keeps the deployer as upgrade authority. For a final freeze, run `LACUNA_FREEZE_UPGRADE=1 npm run deploy:devnet` (or `solana program set-upgrade-authority <program> --final`). Do that only when you are done upgrading.

This is not audited. The proving key is still a single-machine setup. Do not put real funds in until a public ceremony, a frozen upgrade authority, and an external audit.
