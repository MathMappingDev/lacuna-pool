// circomlibjs ships without types.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { buildPoseidon } = require("circomlibjs") as {
  buildPoseidon: () => Promise<{ F: { toObject: (value: unknown) => unknown }; (...inputs: unknown[]): unknown }>;
};

type Hasher = (left: bigint, right: bigint) => bigint;

let ready: Promise<Hasher> | undefined;

export function getHasher(): Promise<Hasher> {
  if (!ready) {
    ready = buildPoseidon().then((poseidon) => {
      return (left: bigint, right: bigint) => {
        const digest = (poseidon as unknown as (inputs: bigint[]) => unknown)([left, right]);
        return BigInt(String(poseidon.F.toObject(digest)));
      };
    });
  }
  return ready;
}

export async function hash2(left: bigint, right: bigint): Promise<bigint> {
  return (await getHasher())(left, right);
}

export async function commitmentOf(
  value: bigint,
  npk: bigint,
  blinding: bigint,
  token: bigint,
): Promise<bigint> {
  const ownerHash = await hash2(npk, blinding);
  const left = await hash2(value, token);
  return hash2(left, ownerHash);
}

export async function npkOf(spendingKey: bigint): Promise<bigint> {
  return hash2(spendingKey, 1n);
}

export async function nullifierOf(spendingKey: bigint, commitment: bigint): Promise<bigint> {
  return hash2(spendingKey, commitment);
}
