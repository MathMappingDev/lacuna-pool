import { PublicKey } from "@solana/web3.js";

export const POOL_PROGRAM_ID = new PublicKey("2JNUVMq3Qg3DM5SUFDXXaW1zjxDUkt8WMNtMAwJmJPiH");
export const RELAY_PROGRAM_ID = new PublicKey("BGWyueTRXKDyq2j1KbCT1LGYj6kegwEVEUFzbjPqgtA7");
export const DUMMY_AMM_PROGRAM_ID = new PublicKey("3t95TV1mKuYTnUdV6snomdNKUG9dBSTMSgVYNVGgoTah");
export const BPF_LOADER_UPGRADEABLE = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");

export function programDataPda(programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([programId.toBuffer()], BPF_LOADER_UPGRADEABLE)[0];
}

function pda(program: PublicKey, seeds: (Buffer | Uint8Array)[]): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, program);
}

export function configPda(program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("config")]);
}

export function vaultPda(program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("vault")]);
}

export function treePda(program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("tree")]);
}

export function tokenPda(tokenId: Buffer, program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("token"), tokenId]);
}

export function rootPda(root: Buffer, program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("root"), root]);
}

export function commitmentPda(commitment: Buffer, program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("commitment"), commitment]);
}

export function nullifierPda(nullifier: Buffer, program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("nullifier"), nullifier]);
}

export function notePda(treeNumber: bigint, index: bigint, program = POOL_PROGRAM_ID) {
  const tree = Buffer.alloc(8);
  tree.writeBigUInt64LE(treeNumber);
  const leaf = Buffer.alloc(8);
  leaf.writeBigUInt64LE(index);
  return pda(program, [Buffer.from("note"), tree, leaf]);
}

export function proofBufferPda(authority: PublicKey, program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("buffer"), Buffer.from("proof"), authority.toBuffer()]);
}

export function cipherBufferPda(authority: PublicKey, slot: number, program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("buffer"), Buffer.from("cipher"), authority.toBuffer(), Buffer.from([slot])]);
}

export function escrowPda(nullifier0: Buffer, program = POOL_PROGRAM_ID) {
  return pda(program, [Buffer.from("escrow"), nullifier0]);
}

export function relayPda(program = RELAY_PROGRAM_ID) {
  return pda(program, [Buffer.from("relay")]);
}

export function relayVaultPda(program = RELAY_PROGRAM_ID) {
  return pda(program, [Buffer.from("vault")]);
}

export function nativeTokenId(): Buffer {
  return Buffer.alloc(32);
}
