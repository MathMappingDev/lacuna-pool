import { keccak256 } from "ethers";
import { PublicKey } from "@solana/web3.js";
import { FIELD } from "./constants";
import type { ProofCall } from "./prover";

const BN254_Q =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

export function be32(value: bigint): Buffer {
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}

export function bytesField(data: Uint8Array): bigint {
  return BigInt(keccak256(data)) % FIELD;
}

export function pubkeyField(key: PublicKey): bigint {
  return bytesField(key.toBytes());
}

export function mintField(mint: PublicKey): bigint {
  const field = pubkeyField(mint);
  if (field === 0n) throw new Error("Mint field collided with native SOL");
  return field;
}

function parseHex(value: string): bigint {
  return BigInt(value);
}

export function packProof(proof: ProofCall): Buffer {
  const ax = parseHex(proof.pA[0]);
  const ay = parseHex(proof.pA[1]);
  const negAy = (BN254_Q - (ay % BN254_Q)) % BN254_Q;
  const a = Buffer.concat([be32(ax), be32(negAy)]);
  const b = Buffer.concat([
    be32(parseHex(proof.pB[0][0])),
    be32(parseHex(proof.pB[0][1])),
    be32(parseHex(proof.pB[1][0])),
    be32(parseHex(proof.pB[1][1])),
  ]);
  const c = Buffer.concat([be32(parseHex(proof.pC[0])), be32(parseHex(proof.pC[1]))]);
  let signals = proof.pubSignals.map((value) => BigInt(value));
  if (signals.length === 18 && signals[0] === 1n) signals = signals.slice(1);
  if (signals.length !== 17) throw new Error("Proof must carry 17 public signals");
  return Buffer.concat([a, b, c, ...signals.map(be32)]);
}

export function hexBytes(hex: string): Buffer {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Buffer.from(clean, "hex");
}

export function ciphertextHash(first: string, second: string): bigint {
  const a = first === "0x" || first === "" ? Buffer.alloc(0) : hexBytes(first);
  const b = second === "0x" || second === "" ? Buffer.alloc(0) : hexBytes(second);
  const buf = Buffer.concat([
    Buffer.from([a.length & 255, (a.length >> 8) & 255, (a.length >> 16) & 255, (a.length >> 24) & 255]),
    a,
    Buffer.from([b.length & 255, (b.length >> 8) & 255, (b.length >> 16) & 255, (b.length >> 24) & 255]),
    b,
  ]);
  return bytesField(buf);
}

export function cipherHash(hex: string): Buffer {
  const data = hex === "0x" || hex === "" ? Buffer.alloc(0) : hexBytes(hex);
  return Buffer.from(keccak256(data).slice(2), "hex");
}

export function swapCommitment(input: {
  hop: PublicKey;
  mintOut: PublicKey;
  minOut: bigint;
  outOwnerHash: bigint;
  refundOwnerHash: bigint;
  outCipherHash: Uint8Array;
  refundCipherHash: Uint8Array;
}): bigint {
  return bytesField(
    Buffer.concat([
      input.hop.toBuffer(),
      input.mintOut.toBuffer(),
      u64(input.minOut),
      be32(input.outOwnerHash),
      be32(input.refundOwnerHash),
      Buffer.from(input.outCipherHash),
      Buffer.from(input.refundCipherHash),
    ]),
  );
}

function u64(value: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(value);
  return buf;
}
