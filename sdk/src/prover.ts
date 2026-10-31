import path from "path";
import { groth16 } from "snarkjs";
import { LEVELS } from "./constants";
import { commitmentOf, nullifierOf } from "./poseidon";

export type ProofCall = {
  pA: [string, string];
  pB: [[string, string], [string, string]];
  pC: [string, string];
  pubSignals: string[];
};

export type SpendNote = {
  enabled: boolean;
  value: bigint;
  npk: bigint;
  blinding: bigint;
  spendingKey: bigint;
  siblings: bigint[];
  indices: number[];
  token?: bigint;
};

export type OutputNote = {
  enabled: boolean;
  value: bigint;
  npk: bigint;
  blinding: bigint;
  token?: bigint;
};

export type TransactRequest = {
  root: bigint;
  token: bigint;
  token1?: bigint;
  twoTokens?: boolean;
  publicAmount: bigint;
  publicAmount1?: bigint;
  recipient: bigint;
  relayFee: bigint;
  protocolFee: bigint;
  protocolFee1?: bigint;
  relayRecipient: bigint;
  externalHash: bigint;
  ciphertextHash: bigint;
  inputs: [SpendNote, SpendNote];
  outputs: [OutputNote, OutputNote];
};

const wasmPath = path.join(__dirname, "../../circuits/build/transact_js/transact.wasm");
const zkeyPath = path.join(__dirname, "../../circuits/build/transact_final.zkey");

function blankInput(): SpendNote {
  return {
    enabled: false,
    value: 0n,
    npk: 0n,
    blinding: 0n,
    spendingKey: 0n,
    siblings: Array.from({ length: LEVELS }, () => 0n),
    indices: Array.from({ length: LEVELS }, () => 0),
  };
}

function blankOutput(): OutputNote {
  return { enabled: false, value: 0n, npk: 0n, blinding: 0n };
}

export function emptySpend(): SpendNote {
  return blankInput();
}

export function emptyOutput(): OutputNote {
  return blankOutput();
}

function asDec(value: bigint): string {
  return value.toString(10);
}

function noteToken(enabled: boolean, token: bigint | undefined, fallback: bigint): bigint {
  if (!enabled) return 0n;
  return token ?? fallback;
}

export async function proveTransact(request: TransactRequest): Promise<ProofCall> {
  const twoTokens = request.twoTokens ? 1n : 0n;
  const token1 = twoTokens === 1n ? (request.token1 ?? 0n) : 0n;
  const publicAmount1 = twoTokens === 1n ? (request.publicAmount1 ?? 0n) : 0n;
  const protocolFee1 = twoTokens === 1n ? (request.protocolFee1 ?? 0n) : 0n;
  const token0Public = request.publicAmount + request.protocolFee + request.relayFee > 0n ? request.token : 0n;
  const token1Public = publicAmount1 + protocolFee1 > 0n ? token1 : 0n;
  const inputTokens = request.inputs.map((note) => noteToken(note.enabled, note.token, request.token));
  const outputTokens = request.outputs.map((note) => noteToken(note.enabled, note.token, request.token));
  const inputCommitments = await Promise.all(
    request.inputs.map((note, index) =>
      note.enabled
        ? commitmentOf(note.value, note.npk, note.blinding, inputTokens[index])
        : commitmentOf(0n, note.npk, note.blinding, 0n),
    ),
  );
  const nullifiers = await Promise.all(
    request.inputs.map((note, index) =>
      note.enabled ? nullifierOf(note.spendingKey, inputCommitments[index]) : Promise.resolve(0n),
    ),
  );
  const outputCommitments = await Promise.all(
    request.outputs.map((note, index) =>
      note.enabled ? commitmentOf(note.value, note.npk, note.blinding, outputTokens[index]) : Promise.resolve(0n),
    ),
  );

  const circuitInput = {
    merkleRoot: asDec(request.root),
    nullifier0: asDec(nullifiers[0]),
    nullifier1: asDec(nullifiers[1]),
    commitment0: asDec(outputCommitments[0]),
    commitment1: asDec(outputCommitments[1]),
    publicAmount0: asDec(request.publicAmount),
    publicAmount1: asDec(publicAmount1),
    recipient: asDec(request.recipient),
    token0: asDec(token0Public),
    token1: asDec(token1Public),
    twoTokens: asDec(twoTokens),
    relayFee: asDec(request.relayFee),
    protocolFee0: asDec(request.protocolFee),
    protocolFee1: asDec(protocolFee1),
    relayRecipient: asDec(request.relayRecipient),
    externalHash: asDec(request.externalHash),
    ciphertextHash: asDec(request.ciphertextHash),
    privateToken0: asDec(request.token),
    privateToken1: asDec(token1),
    inValue: request.inputs.map((note) => asDec(note.enabled ? note.value : 0n)),
    inNpk: request.inputs.map((note) => asDec(note.enabled ? note.npk : 0n)),
    inBlinding: request.inputs.map((note) => asDec(note.blinding)),
    inToken: inputTokens.map((token) => asDec(token)),
    inSpendingKey: request.inputs.map((note) => asDec(note.enabled ? note.spendingKey : 0n)),
    inSiblings: request.inputs.map((note) => note.siblings.map((value) => asDec(value))),
    inIndices: request.inputs.map((note) => note.indices.map((value) => value.toString())),
    inEnabled: request.inputs.map((note) => (note.enabled ? "1" : "0")),
    outValue: request.outputs.map((note) => asDec(note.enabled ? note.value : 0n)),
    outNpk: request.outputs.map((note) => asDec(note.enabled ? note.npk : 0n)),
    outBlinding: request.outputs.map((note) => asDec(note.blinding)),
    outToken: outputTokens.map((token) => asDec(token)),
    outEnabled: request.outputs.map((note) => (note.enabled ? "1" : "0")),
  };

  const proof = await groth16.fullProve(circuitInput, wasmPath, zkeyPath);
  const expected = [
    request.root,
    nullifiers[0],
    nullifiers[1],
    outputCommitments[0],
    outputCommitments[1],
    request.publicAmount,
    publicAmount1,
    request.recipient,
    token0Public,
    token1Public,
    twoTokens,
    request.relayFee,
    request.protocolFee,
    protocolFee1,
    request.relayRecipient,
    request.externalHash,
    request.ciphertextHash,
  ];
  let signals = (proof.publicSignals as string[]).map((value) => BigInt(value));
  if (signals.length === expected.length + 1 && signals[0] === 1n) signals = signals.slice(1);
  if (signals.length !== expected.length || signals.some((value, index) => value !== expected[index])) {
    throw new Error("The proof public signals do not match this transaction");
  }
  const call = JSON.parse(`[${await groth16.exportSolidityCallData(proof.proof, proof.publicSignals)}]`) as [
    [string, string],
    [[string, string], [string, string]],
    [string, string],
    string[],
  ];
  return { pA: call[0], pB: call[1], pC: call[2], pubSignals: call[3] };
}
