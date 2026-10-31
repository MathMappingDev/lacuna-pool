import { BN } from "@coral-xyz/anchor";
import { ComputeBudgetProgram, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
  getOrCreateAssociatedTokenAccount,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { be32, pubkeyField, swapCommitment } from "./encoding";
import { commitmentOf, hash2, nullifierOf } from "./poseidon";
import { encryptNote } from "./note";
import { splitGross } from "./constants";
import {
  cipherBufferPda,
  configPda,
  escrowPda,
  tokenPda,
  treePda,
  vaultPda,
} from "./pda";
import { ensureCipher, insertAccounts, submitTransact, type TransactOpts } from "./pool";
import type { OutputNote, SpendNote } from "./prover";

type AnyProgram = any;

function toBe32(value: bigint): Buffer {
  return be32(value);
}

function providerSigner(program: AnyProgram) {
  return (program.provider as { wallet: { payer: { publicKey: PublicKey; secretKey: Uint8Array } } })
    .wallet.payer;
}

export type SwapHop = {
  programId: PublicKey;
  data: Buffer;
  accounts: { pubkey: PublicKey; isWritable: boolean; isSigner: boolean }[];
};

async function nullifier0Of(inputs: [SpendNote, SpendNote]): Promise<bigint> {
  const note = inputs[0];
  if (!note.enabled) return 0n;
  const commitment = await commitmentOf(note.value, note.npk, note.blinding, note.token ?? 0n);
  return nullifierOf(note.spendingKey, commitment);
}

export async function swapPrepare(input: {
  pool: AnyProgram;
  payer: PublicKey;
  root: bigint;
  token: bigint;
  mintIn: PublicKey;
  mintOut: PublicKey;
  hop: PublicKey;
  minOut: bigint;
  amountIn: bigint;
  inputs: [SpendNote, SpendNote];
  outputs: [OutputNote, OutputNote];
  ciphertexts: [string, string];
  outNpk: bigint;
  outBlinding: bigint;
  refundNpk: bigint;
  refundBlinding: bigint;
  tokenProgram?: PublicKey;
  accounts?: TransactOpts;
}): Promise<{ signature: string; nullifier0: bigint; escrow: PublicKey }> {
  const tokenProgram = input.tokenProgram ?? TOKEN_PROGRAM_ID;
  const nullifier0 = await nullifier0Of(input.inputs);
  const [escrow] = escrowPda(toBe32(nullifier0));
  const outOwnerHash = await hash2(input.outNpk, input.outBlinding);
  const refundOwnerHash = await hash2(input.refundNpk, input.refundBlinding);
  const vault = vaultPda()[0];
  await getOrCreateAssociatedTokenAccount(
    input.pool.provider.connection,
    providerSigner(input.pool),
    input.mintIn,
    vault,
    true,
    undefined,
    undefined,
    tokenProgram,
  );
  const escrowAta = (
    await getOrCreateAssociatedTokenAccount(
      input.pool.provider.connection,
      providerSigner(input.pool),
      input.mintIn,
      escrow,
      true,
      undefined,
      undefined,
      tokenProgram,
    )
  ).address;
  const tree = await input.pool.account.tree.fetch(treePda()[0]);
  const expectedIndex = new BN(tree.nextIndex.toString());
  const built = await submitTransact({
    program: input.pool,
    payer: input.payer,
    root: input.root,
    token: input.token,
    inputs: input.inputs,
    outputs: input.outputs,
    ciphertexts: input.ciphertexts,
    publicAmount: input.amountIn,
    protocolFee: 0n,
    recipient: escrow,
    externalHash: swapCommitment({
      hop: input.hop,
      mintOut: input.mintOut,
      minOut: input.minOut,
      outOwnerHash,
      refundOwnerHash,
    }),
    accounts: {
      ...input.accounts,
      tokenMint0: input.mintIn,
      vaultAta0: getAssociatedTokenAddressSync(input.mintIn, vault, true, tokenProgram),
      recipientAta0: escrowAta,
      tokenProgram,
    },
    buildOnly: true,
  });
  if (pubkeyField(escrow) !== BigInt(built.proof.pubSignals[7])) {
    throw new Error("Swap proof recipient is not the escrow");
  }
  const signature = await input.pool.methods
    .swapPrepare(
      expectedIndex,
      new BN(input.minOut.toString()),
      [...toBe32(outOwnerHash)],
      [...toBe32(refundOwnerHash)],
      [...toBe32(nullifier0)],
    )
    .accounts({
      payer: input.payer,
      escrow,
      mintIn: input.mintIn,
      mintOut: input.mintOut,
      hopProgram: input.hop,
      escrowAta,
      tokenProgram,
      associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
      transact: built.accounts,
    })
    .preInstructions([ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 })])
    .rpc();
  return { signature, nullifier0, escrow };
}

export async function swapExecute(input: {
  pool: AnyProgram;
  payer: PublicKey;
  nullifier0: bigint;
  mintIn: PublicKey;
  mintOut: PublicKey;
  hop: SwapHop;
  amountOut: bigint;
  outNpk: bigint;
  outBlinding: bigint;
  viewingPublic: Uint8Array;
  tokenIdOut: bigint;
  tokenProgram?: PublicKey;
}): Promise<string> {
  const tokenProgram = input.tokenProgram ?? TOKEN_PROGRAM_ID;
  const [escrow] = escrowPda(toBe32(input.nullifier0));
  const config = await input.pool.account.config.fetch(configPda()[0]);
  const net = splitGross(input.amountOut, BigInt(config.swapFeeBps)).net;
  const ciphertext = encryptNote(
    { value: net, blinding: input.outBlinding, token: input.tokenIdOut },
    input.viewingPublic,
  );
  const ownerHash = await hash2(input.outNpk, input.outBlinding);
  const commitment = await commitmentOf(net, input.outNpk, input.outBlinding, input.tokenIdOut);
  const cipher = await ensureCipher(input.pool, input.payer, 2, ciphertext);
  const insert = await insertAccounts(input.pool, commitment);
  if (ownerHash === 0n) throw new Error("Bad output owner hash");
  const vault = vaultPda()[0];
  await getOrCreateAssociatedTokenAccount(
    input.pool.provider.connection,
    providerSigner(input.pool),
    input.mintOut,
    vault,
    true,
    undefined,
    undefined,
    tokenProgram,
  );
  return input.pool.methods
    .swapExecute(new BN(insert.nextIndex.toString()), Buffer.from(input.hop.data))
    .accounts({
      payer: input.payer,
      config: configPda()[0],
      vault,
      tree: treePda()[0],
      escrow,
      mintIn: input.mintIn,
      mintOut: input.mintOut,
      escrowAta: getAssociatedTokenAddressSync(input.mintIn, escrow, true, tokenProgram),
      vaultAtaOut: getAssociatedTokenAddressSync(input.mintOut, vault, true, tokenProgram),
      hopProgram: input.hop.programId,
      ciphertext: cipher,
      commitment: insert.commitment,
      root: insert.root,
      note: insert.note,
      tokenStateOut: tokenPda(toBe32(input.tokenIdOut))[0],
      tokenProgram,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(
      input.hop.accounts.map((account) => ({
        pubkey: account.pubkey,
        isWritable: account.isWritable,
        isSigner: account.pubkey.equals(escrow) ? false : account.isSigner,
      })),
    )
    .preInstructions([ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 })])
    .rpc();
}

export async function swapRefund(input: {
  pool: AnyProgram;
  payer: PublicKey;
  nullifier0: bigint;
  mintIn: PublicKey;
  amountIn: bigint;
  refundNpk: bigint;
  refundBlinding: bigint;
  viewingPublic: Uint8Array;
  tokenIdIn: bigint;
  tokenProgram?: PublicKey;
}): Promise<string> {
  const tokenProgram = input.tokenProgram ?? TOKEN_PROGRAM_ID;
  const [escrow] = escrowPda(toBe32(input.nullifier0));
  const config = await input.pool.account.config.fetch(configPda()[0]);
  const net = splitGross(input.amountIn, BigInt(config.swapFeeBps)).net;
  const ciphertext = encryptNote(
    { value: net, blinding: input.refundBlinding, token: input.tokenIdIn },
    input.viewingPublic,
  );
  const commitment = await commitmentOf(
    net,
    input.refundNpk,
    input.refundBlinding,
    input.tokenIdIn,
  );
  const cipher = await ensureCipher(input.pool, input.payer, 2, ciphertext);
  const insert = await insertAccounts(input.pool, commitment);
  const vault = vaultPda()[0];
  return input.pool.methods
    .swapRefund(new BN(insert.nextIndex.toString()))
    .accounts({
      payer: input.payer,
      config: configPda()[0],
      vault,
      tree: treePda()[0],
      escrow,
      mintIn: input.mintIn,
      escrowAta: getAssociatedTokenAddressSync(input.mintIn, escrow, true, tokenProgram),
      vaultAta: getAssociatedTokenAddressSync(input.mintIn, vault, true, tokenProgram),
      ciphertext: cipher,
      commitment: insert.commitment,
      root: insert.root,
      note: insert.note,
      tokenState: tokenPda(toBe32(input.tokenIdIn))[0],
      tokenProgram,
      systemProgram: SystemProgram.programId,
    })
    .preInstructions([ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 })])
    .rpc();
}

export { cipherBufferPda };
