import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import { x25519 } from "@noble/curves/ed25519";
import { hexlify } from "ethers";

export type NoteBody = {
  value: bigint;
  blinding: bigint;
  token: bigint;
  memo?: string;
  sender?: string;
};

function u256(value: bigint): Buffer {
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}

function readU256(buffer: Buffer, offset: number): bigint {
  return BigInt(`0x${buffer.subarray(offset, offset + 32).toString("hex")}`);
}

function sharedKey(privateKey: Uint8Array, publicKey: Uint8Array): Buffer {
  const shared = x25519.getSharedSecret(privateKey, publicKey);
  return createHash("sha256").update(shared).digest();
}

function packBody(note: NoteBody): { version: number; body: Buffer } {
  const core = Buffer.concat([u256(note.value), u256(note.blinding), u256(note.token)]);
  if (!note.memo && !note.sender) return { version: 1, body: core };
  const memo = Buffer.from(note.memo ?? "", "utf8");
  if (memo.length > 256) throw new Error("A note memo can be at most 256 bytes");
  const sender = note.sender ? Buffer.from(note.sender.replace(/^0x/, ""), "hex") : Buffer.alloc(20);
  if (sender.length !== 20) throw new Error("A note sender must be an address");
  const length = Buffer.alloc(2);
  length.writeUInt16BE(memo.length);
  return {
    version: 2,
    body: Buffer.concat([core, Buffer.from([note.sender ? 1 : 0]), sender, length, memo]),
  };
}

export function encryptNote(note: NoteBody, viewingPublic: Uint8Array): string {
  const ephemeral = randomBytes(32);
  const ephemeralPublic = Buffer.from(x25519.getPublicKey(ephemeral));
  const iv = randomBytes(12);
  const packed = packBody(note);
  const cipher = createCipheriv("aes-256-gcm", sharedKey(ephemeral, viewingPublic), iv);
  const encrypted = Buffer.concat([cipher.update(packed.body), cipher.final()]);
  const tag = cipher.getAuthTag();
  return hexlify(Buffer.concat([Buffer.from([packed.version]), ephemeralPublic, iv, tag, encrypted]));
}

export function decryptNote(ciphertext: string, viewingPrivate: Uint8Array): NoteBody | null {
  try {
    const bytes = Buffer.from(ciphertext.replace(/^0x/, ""), "hex");
    if (bytes.length < 1 + 32 + 12 + 16 + 96 || (bytes[0] !== 1 && bytes[0] !== 2)) return null;
    const ephemeralPublic = bytes.subarray(1, 33);
    const iv = bytes.subarray(33, 45);
    const tag = bytes.subarray(45, 61);
    const encrypted = bytes.subarray(61);
    const decipher = createDecipheriv("aes-256-gcm", sharedKey(viewingPrivate, ephemeralPublic), iv);
    decipher.setAuthTag(tag);
    const body = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    if (body.length < 96) return null;
    const note: NoteBody = {
      value: readU256(body, 0),
      blinding: readU256(body, 32),
      token: readU256(body, 64),
    };
    if (bytes[0] === 1) {
      if (body.length !== 96) return null;
      return note;
    }
    if (body.length < 96 + 1 + 20 + 2) return null;
    const memoLength = body.readUInt16BE(96 + 1 + 20);
    const memo = body.subarray(96 + 1 + 20 + 2, 96 + 1 + 20 + 2 + memoLength).toString("utf8");
    if (memo) note.memo = memo;
    if (body[96] === 1) note.sender = `0x${body.subarray(97, 117).toString("hex")}`;
    return note;
  } catch {
    return null;
  }
}
