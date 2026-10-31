import { appendFileSync } from "fs";
import { BN } from "@coral-xyz/anchor";

type AnyProgram = any;
import { ComputeBudgetProgram, PublicKey, SystemProgram, type Signer } from "@solana/web3.js";
import {
  calculateEpochFee,
  getAssociatedTokenAddressSync,
  getMint,
  getOrCreateAssociatedTokenAccount,
  getTransferFeeConfig,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { minProtocolFee, splitGross } from "./constants";
import { be32, ciphertextHash, hexBytes, packProof, pubkeyField } from "./encoding";
import type { LacunaKeys } from "./keys";
import { decryptNote, encryptNote, type NoteBody } from "./note";
import { commitmentOf, hash2, nullifierOf } from "./poseidon";
import {
  cipherBufferPda,
  commitmentPda,
  configPda,
  nativeTokenId,
  notePda,
  nullifierPda,
  proofBufferPda,
  rootPda,
  tokenPda,
  treePda,
  vaultPda,
} from "./pda";
import {
  emptySpend,
  proveTransact,
  type OutputNote,
  type ProofCall,
  type SpendNote,
} from "./prover";
import { NoteForest } from "./tree";

export type ScannedNote = NoteBody & {
  treeNumber: number;
  index: number;
  commitment: bigint;
  spent: boolean;
};

export type Submitted = {
  signature: string;
  proof: ProofCall;
  outputs: OutputSecret[];
  transactIx?: import("@solana/web3.js").TransactionInstruction;
  accounts?: Record<string, PublicKey | null>;
};

type OutputSecret = {
  value: string;
  blinding: string;
  token: string;
  npk: string;
  ciphertext: string;
};

export type TransactOpts = {
  tokenMint0?: PublicKey;
  tokenMint1?: PublicKey;
  vaultAta0?: PublicKey;
  vaultAta1?: PublicKey;
  recipientAta0?: PublicKey;
  recipientAta1?: PublicKey;
  relayAta?: PublicKey;
  tokenProgram?: PublicKey;
};

function toBe32(value: bigint): Buffer {
  return be32(value);
}

function providerSigner(program: AnyProgram): Signer {
  return (program.provider as { wallet: { payer: Signer } }).wallet.payer;
}

export function outputOf(value: bigint, npk: bigint, blinding: bigint, token?: bigint): OutputNote {
  return { enabled: value > 0n, value, npk, blinding, token };
}

type DecodedNote = {
  treeNumber: number;
  index: number;
  commitment: bigint;
  ciphertext: string;
};

function decodeNote(data: Buffer): DecodedNote {
  const treeNumber = Number(data.readBigUInt64LE(8));
  const index = Number(data.readBigUInt64LE(16));
  const commitment = BigInt("0x" + data.subarray(24, 56).toString("hex"));
  const len = data.readUInt16LE(56);
  const ciphertext = "0x" + data.subarray(58, 58 + len).toString("hex");
  return { treeNumber, index, commitment, ciphertext };
}

function isInsertRace(error: unknown): boolean {
  return /already in use|DoubleSpend|Allocate|StaleTree/i.test(String(error));
}

async function retryInsert<T>(run: () => Promise<T>): Promise<T> {
  let last: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await run();
    } catch (error) {
      last = error;
      if (!isInsertRace(error) || attempt === 2) throw error;
    }
  }
  throw last;
}

export async function closeBuffers(program: AnyProgram, payer: PublicKey, slots: number[] = [0, 1, 2, 3]) {
  const connection = program.provider.connection;
  const proof = proofBufferPda(payer)[0];
  if (await connection.getAccountInfo(proof)) {
    await program.methods.closeProofBuffer().accounts({ payer, buffer: proof }).rpc();
  }
  for (const slot of slots) {
    const cipher = cipherBufferPda(payer, slot)[0];
    if (await connection.getAccountInfo(cipher)) {
      await program.methods.closeCipherBuffer().accounts({ payer, buffer: cipher }).rpc();
    }
  }
}

async function fetchNotes(program: AnyProgram): Promise<DecodedNote[]> {
  const tree = await program.account.tree.fetch(treePda()[0]);
  const currentTree = Number(tree.treeNumber);
  const nextIndex = Number(tree.nextIndex);
  const keys: PublicKey[] = [];
  for (let t = 0; t <= currentTree; t++) {
    const count = t < currentTree ? 65536 : nextIndex;
    for (let i = 0; i < count; i++) {
      keys.push(notePda(BigInt(t), BigInt(i))[0]);
    }
  }
  const notes: DecodedNote[] = [];
  const connection = program.provider.connection;
  for (let offset = 0; offset < keys.length; offset += 100) {
    const batch = await connection.getMultipleAccountsInfo(keys.slice(offset, offset + 100));
    for (const info of batch) {
      if (info) notes.push(decodeNote(info.data));
    }
  }
  return notes;
}

export async function loadTree(program: AnyProgram): Promise<NoteForest> {
  const { getHasher } = await import("./poseidon");
  const forest = new NoteForest(await getHasher());
  const notes = await fetchNotes(program);
  for (const leaf of notes.sort((a, b) => a.treeNumber - b.treeNumber || a.index - b.index)) {
    if (forest.ensure(leaf.treeNumber).insert(leaf.commitment) !== leaf.index) {
      throw new Error("Note accounts are not a continuous tree");
    }
  }
  return forest;
}

export async function scan(program: AnyProgram, keys: LacunaKeys): Promise<ScannedNote[]> {
  const notes = await fetchNotes(program);
  const found: ScannedNote[] = [];
  for (const entry of notes) {
    const ciphertext = entry.ciphertext;
    if (ciphertext === "0x") continue;
    const decrypted = decryptNote(ciphertext, keys.viewingPrivate);
    if (!decrypted) continue;
    const eventCommitment = entry.commitment;
    let value = decrypted.value;
    if ((await commitmentOf(value, keys.npk, decrypted.blinding, decrypted.token)) !== eventCommitment) {
      const net = splitGross(value).net;
      const nftTry = await commitmentOf(1n, keys.npk, decrypted.blinding, decrypted.token);
      const netTry = await commitmentOf(net, keys.npk, decrypted.blinding, decrypted.token);
      if (nftTry === eventCommitment) value = 1n;
      else if (netTry === eventCommitment) value = net;
      else continue;
    }
    const body = { ...decrypted, value };
    const commitment = await commitmentOf(body.value, keys.npk, body.blinding, body.token);
    const nullifier = await nullifierOf(keys.spendingKey, commitment);
    const [nullPda] = nullifierPda(toBe32(nullifier));
    const spentInfo = await program.provider.connection.getAccountInfo(nullPda);
    found.push({
      ...body,
      treeNumber: entry.treeNumber,
      index: entry.index,
      commitment,
      spent: spentInfo !== null,
    });
  }
  return found.sort((a, b) => a.treeNumber - b.treeNumber || a.index - b.index);
}

export async function spendable(keys: LacunaKeys, note: ScannedNote, forest: NoteForest): Promise<SpendNote> {
  const proof = forest.tree(note.treeNumber).path(note.index);
  return {
    enabled: true,
    value: note.value,
    npk: keys.npk,
    blinding: note.blinding,
    spendingKey: keys.spendingKey,
    siblings: proof.siblings,
    indices: proof.indices,
    token: note.token,
  };
}

export async function ensureCipher(program: AnyProgram, payer: PublicKey, slot: number, hex: string) {
  const [pda] = cipherBufferPda(payer, slot);
  const info = await program.provider.connection.getAccountInfo(pda);
  if (!info) {
    await program.methods.createCipherBuffer(slot).accounts({ payer, buffer: pda }).rpc();
  }
  const bytes = hex === "0x" || hex === "" ? Buffer.alloc(0) : hexBytes(hex);
  await program.methods.writeCipherBuffer(0, bytes).accounts({ payer, buffer: pda }).rpc();
  return pda;
}

export async function ensureProof(program: AnyProgram, payer: PublicKey, packed: Buffer) {
  const [pda] = proofBufferPda(payer);
  const info = await program.provider.connection.getAccountInfo(pda);
  if (!info) {
    await program.methods.createProofBuffer().accounts({ payer, buffer: pda }).rpc();
  }
  const chunk = 800;
  for (let offset = 0; offset < packed.length; offset += chunk) {
    await program.methods
      .writeProofBuffer(offset, packed.subarray(offset, offset + chunk))
      .accounts({ payer, buffer: pda })
      .rpc();
  }
  return pda;
}

const TREE_CAPACITY = 65536;

export function leafSlot(treeNumber: number, nextIndex: number) {
  if (nextIndex >= TREE_CAPACITY) {
    return { treeNumber: treeNumber + 1, nextIndex: 0 };
  }
  return { treeNumber, nextIndex };
}

export async function insertAccounts(program: AnyProgram, commitment: bigint) {
  const tree = await program.account.tree.fetch(treePda()[0]);
  const forest = await loadTree(program);
  const slot = leafSlot(Number(tree.treeNumber), Number(tree.nextIndex));
  forest.ensure(slot.treeNumber).insert(commitment);
  const newRoot = forest.tree(slot.treeNumber).path(slot.nextIndex).root;
  return {
    commitment: commitmentPda(toBe32(commitment))[0],
    root: rootPda(toBe32(newRoot))[0],
    note: notePda(BigInt(slot.treeNumber), BigInt(slot.nextIndex))[0],
    treeNumber: slot.treeNumber,
    nextIndex: slot.nextIndex,
  };
}

async function shieldNote(input: {
  program: AnyProgram;
  payer: PublicKey;
  net: bigint;
  token: bigint;
  npk: bigint;
  blinding: bigint;
  viewingPublic: Uint8Array;
  ciphertext?: string;
}) {
  const ciphertext =
    input.ciphertext ??
    encryptNote({ value: input.net, blinding: input.blinding, token: input.token }, input.viewingPublic);
  const ownerHash = await hash2(input.npk, input.blinding);
  const commitment = await commitmentOf(input.net, input.npk, input.blinding, input.token);
  const cipher = await ensureCipher(input.program, input.payer, 0, ciphertext);
  const insert = await insertAccounts(input.program, commitment);
  return { ownerHash, commitment, cipher, insert, ciphertext };
}

export async function shieldSol(input: {
  program: AnyProgram;
  payer: PublicKey;
  gross: bigint;
  npk: bigint;
  blinding: bigint;
  viewingPublic: Uint8Array;
}): Promise<string> {
  const config = await input.program.account.config.fetch(configPda()[0]);
  const { net } = splitGross(input.gross, BigInt(config.shieldFeeBps));
  return retryInsert(async () => {
    const prepared = await shieldNote({ ...input, net, token: 0n });
    return input.program.methods
      .shieldSol(
        [...toBe32(prepared.ownerHash)],
        new BN(input.gross.toString()),
        new BN(prepared.insert.nextIndex),
      )
      .accounts({
        payer: input.payer,
        source: input.payer,
        ciphertext: prepared.cipher,
        commitment: prepared.insert.commitment,
        root: prepared.insert.root,
        note: prepared.insert.note,
        tokenState: tokenPda(nativeTokenId())[0],
        vault: vaultPda()[0],
        tree: treePda()[0],
        config: configPda()[0],
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  });
}

export async function shieldToken(input: {
  program: AnyProgram;
  payer: PublicKey;
  mint: PublicKey;
  amount: bigint;
  npk: bigint;
  blinding: bigint;
  viewingPublic: Uint8Array;
  tokenId: bigint;
  nft?: boolean;
  tokenProgram?: PublicKey;
}): Promise<string> {
  const tokenProgram = input.tokenProgram ?? TOKEN_PROGRAM_ID;
  const config = await input.program.account.config.fetch(configPda()[0]);
  let gross = input.amount;
  if (!input.nft) {
    try {
      const mintInfo = await getMint(
        input.program.provider.connection,
        input.mint,
        undefined,
        tokenProgram,
      );
      const feeConfig = getTransferFeeConfig(mintInfo);
      if (feeConfig) {
        const epoch = BigInt((await input.program.provider.connection.getEpochInfo()).epoch);
        const charged = calculateEpochFee(feeConfig, epoch, input.amount);
        gross = charged >= input.amount ? 0n : input.amount - charged;
      }
    } catch {
      // Classic SPL mints have no transfer-fee extension.
    }
  }
  const net = input.nft ? 1n : splitGross(gross, BigInt(config.shieldFeeBps)).net;
  const vault = vaultPda()[0];
  await getOrCreateAssociatedTokenAccount(
    input.program.provider.connection,
    providerSigner(input.program),
    input.mint,
    vault,
    true,
    undefined,
    undefined,
    tokenProgram,
  );
  const payerAta = getAssociatedTokenAddressSync(input.mint, input.payer, false, tokenProgram);
  const vaultAta = getAssociatedTokenAddressSync(input.mint, vault, true, tokenProgram);
  return retryInsert(async () => {
    const prepared = await shieldNote({
      program: input.program,
      payer: input.payer,
      net,
      token: input.tokenId,
      npk: input.npk,
      blinding: input.blinding,
      viewingPublic: input.viewingPublic,
    });
    const method = input.nft
      ? input.program.methods.shieldNft(
          [...toBe32(prepared.ownerHash)],
          new BN(1),
          [...toBe32(input.tokenId)],
          new BN(prepared.insert.nextIndex),
        )
      : input.program.methods.shieldSpl(
          [...toBe32(prepared.ownerHash)],
          new BN(input.amount.toString()),
          [...toBe32(input.tokenId)],
          new BN(prepared.insert.nextIndex),
        );
    return method
      .accounts({
        payer: input.payer,
        authority: input.payer,
        mint: input.mint,
        payerAta,
        vaultAta,
        ciphertext: prepared.cipher,
        commitment: prepared.insert.commitment,
        root: prepared.insert.root,
        note: prepared.insert.note,
        tokenState: tokenPda(toBe32(input.tokenId))[0],
        vault,
        tree: treePda()[0],
        config: configPda()[0],
        tokenProgram,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  });
}

export async function shieldNft(input: {
  program: AnyProgram;
  payer: PublicKey;
  mint: PublicKey;
  npk: bigint;
  blinding: bigint;
  viewingPublic: Uint8Array;
  tokenId: bigint;
  tokenProgram?: PublicKey;
}): Promise<string> {
  return shieldToken({ ...input, amount: 1n, nft: true });
}

export async function submitTransact(input: {
  program: AnyProgram;
  payer: PublicKey;
  root: bigint;
  token: bigint;
  inputs: [SpendNote, SpendNote];
  outputs: [OutputNote, OutputNote];
  ciphertexts: [string, string];
  publicAmount?: bigint;
  protocolFee?: bigint;
  relayFee?: bigint;
  relayRecipient?: PublicKey;
  recipient?: PublicKey;
  externalHash?: bigint;
  twoTokens?: boolean;
  token1?: bigint;
  publicAmount1?: bigint;
  protocolFee1?: bigint;
  /** Opt-in path for plaintext output-note secrets. Never written unless set. */
  secretFile?: string;
  accounts?: TransactOpts;
  buildOnly?: boolean;
}): Promise<Submitted> {
  const config = await input.program.account.config.fetch(configPda()[0]);
  const feeBps = BigInt(config.unshieldFeeBps);
  const relayFee = input.relayFee ?? 0n;
  const first = splitExit(input.publicAmount ?? 0n, input.protocolFee, feeBps, relayFee);
  const second = splitExit(input.publicAmount1 ?? 0n, input.protocolFee1, feeBps, 0n);
  const relayRecipient = input.relayRecipient ? pubkeyField(input.relayRecipient) : 0n;
  const recipient = input.recipient ? pubkeyField(input.recipient) : 0n;
  const proof = await proveTransact({
    root: input.root,
    token: input.token,
    token1: input.token1,
    twoTokens: input.twoTokens,
    publicAmount: first.publicAmount,
    publicAmount1: second.publicAmount,
    recipient,
    relayFee,
    protocolFee: first.protocolFee,
    protocolFee1: second.protocolFee,
    relayRecipient,
    externalHash: input.externalHash ?? 0n,
    ciphertextHash: ciphertextHash(input.ciphertexts[0], input.ciphertexts[1]),
    inputs: input.inputs,
    outputs: input.outputs,
  });
  const outputs = input.outputs.map((note, index) => ({
    value: (note.enabled ? note.value : 0n).toString(),
    blinding: note.blinding.toString(),
    token: (note.token ?? input.token).toString(),
    npk: note.npk.toString(),
    ciphertext: input.ciphertexts[index],
  }));
  if (input.secretFile) {
    appendFileSync(
      input.secretFile,
      `${JSON.stringify({ savedAt: new Date().toISOString(), outputs })}\n`,
    );
  }
  const packed = packProof(proof);
  const proofPda = await ensureProof(input.program, input.payer, packed);
  const c0 = await ensureCipher(input.program, input.payer, 0, input.ciphertexts[0]);
  const c1 = await ensureCipher(input.program, input.payer, 1, input.ciphertexts[1]);
  const nullifiers = proof.pubSignals.slice(1, 3).map((v) => BigInt(v));
  const outCommitments = proof.pubSignals.slice(3, 5).map((v) => BigInt(v));
  const needExit =
    first.publicAmount > 0n || first.protocolFee > 0n || relayFee > 0n || second.publicAmount > 0n || second.protocolFee > 0n;
  const token0 = input.token === 0n ? nativeTokenId() : toBe32(input.token);
  const extra = input.accounts ?? {};
  return retryInsert(async () => {
    const forest = await loadTree(input.program);
    const tree = await input.program.account.tree.fetch(treePda()[0]);
    const startIndex = Number(tree.nextIndex);
    let nextIndex = startIndex;
    let treeNumber = Number(tree.treeNumber);
    const noteAccounts: PublicKey[] = [];
    const commitmentAccounts: PublicKey[] = [];
    const rootAccounts: PublicKey[] = [];
    for (const commitment of outCommitments) {
      if (commitment === 0n) {
        noteAccounts.push(notePda(0n, 0n)[0]);
        commitmentAccounts.push(commitmentPda(toBe32(0n))[0]);
        rootAccounts.push(rootPda(toBe32(0n))[0]);
        continue;
      }
      const slot = leafSlot(treeNumber, nextIndex);
      treeNumber = slot.treeNumber;
      nextIndex = slot.nextIndex;
      commitmentAccounts.push(commitmentPda(toBe32(commitment))[0]);
      noteAccounts.push(notePda(BigInt(treeNumber), BigInt(nextIndex))[0]);
      forest.ensure(treeNumber).insert(commitment);
      rootAccounts.push(rootPda(toBe32(forest.tree(treeNumber).path(nextIndex).root))[0]);
      nextIndex += 1;
    }
    const transactAccounts = {
      payer: input.payer,
      config: configPda()[0],
      vault: vaultPda()[0],
      tree: treePda()[0],
      proof: proofPda,
      ciphertext0: c0,
      ciphertext1: c1,
      knownRoot: rootPda(toBe32(input.root))[0],
      nullifier0: nullifierPda(toBe32(nullifiers[0]))[0],
      nullifier1: nullifierPda(toBe32(nullifiers[1]))[0],
      commitment0: commitmentAccounts[0],
      commitment1: commitmentAccounts[1],
      root0: rootAccounts[0],
      root1: rootAccounts[1],
      note0: noteAccounts[0],
      note1: noteAccounts[1],
      tokenState0: needExit ? tokenPda(token0)[0] : null,
      tokenState1: input.twoTokens ? tokenPda(toBe32(input.token1 ?? 0n))[0] : null,
      recipient: input.recipient ?? null,
      relayRecipient: input.relayRecipient ?? null,
      mint0: extra.tokenMint0 ?? null,
      mint1: extra.tokenMint1 ?? null,
      vaultAta0: extra.vaultAta0 ?? null,
      vaultAta1: extra.vaultAta1 ?? null,
      recipientAta0: extra.recipientAta0 ?? null,
      recipientAta1: extra.recipientAta1 ?? null,
      relayAta: extra.relayAta ?? null,
      tokenProgram: extra.tokenProgram ?? null,
      systemProgram: SystemProgram.programId,
    };
    const builder = input.program.methods
      .transact(new BN(startIndex))
      .accounts(transactAccounts as never)
      .preInstructions([ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 })]);
    if (input.buildOnly) {
      const transactIx = await builder.instruction();
      return { signature: "", proof, outputs, transactIx, accounts: transactAccounts };
    }
    const signature = await builder.rpc();
    return { signature, proof, outputs, accounts: transactAccounts };
  });
}

function splitExit(
  requested: bigint,
  protocolFee: bigint | undefined,
  feeBps: bigint,
  relayFee: bigint,
): { publicAmount: bigint; protocolFee: bigint } {
  if (protocolFee != null) return { publicAmount: requested, protocolFee };
  if (requested === 0n && relayFee === 0n) return { publicAmount: 0n, protocolFee: 0n };
  if (relayFee === 0n) {
    const split = splitGross(requested, feeBps);
    return { publicAmount: split.net, protocolFee: split.fee };
  }
  const recipient = requested === 0n ? { net: 0n, fee: 0n } : splitGross(requested, feeBps);
  const combined = minProtocolFee(recipient.net + relayFee, feeBps);
  return { publicAmount: recipient.net, protocolFee: combined > recipient.fee ? combined : recipient.fee };
}

export { splitExit };
