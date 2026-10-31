import { LEVELS } from "./constants";

export class NoteTree {
  readonly levels = LEVELS;
  readonly zeros: bigint[];
  readonly leaves: bigint[] = [];
  private layers: bigint[][] | undefined;

  constructor(private readonly hash2: (left: bigint, right: bigint) => bigint) {
    this.zeros = [0n];
    for (let level = 1; level < LEVELS; level++) {
      this.zeros.push(hash2(this.zeros[level - 1], this.zeros[level - 1]));
    }
  }

  emptyRoot(): bigint {
    return this.hash2(this.zeros[LEVELS - 1], this.zeros[LEVELS - 1]);
  }

  insert(leaf: bigint): number {
    const index = this.leaves.length;
    this.leaves.push(leaf);
    this.layers = undefined;
    return index;
  }

  path(index: number): { siblings: bigint[]; indices: number[]; root: bigint } {
    if (index >= this.leaves.length) throw new Error("Leaf is not in the tree");
    const layers = this.ensureLayers();
    let cursor = index;
    const siblings: bigint[] = [];
    const indices: number[] = [];
    for (let level = 0; level < this.levels; level++) {
      const isRight = cursor % 2 === 1;
      const siblingIndex = isRight ? cursor - 1 : cursor + 1;
      const nodes = layers[level];
      siblings.push(siblingIndex < nodes.length ? nodes[siblingIndex] : this.zeros[level]);
      indices.push(isRight ? 1 : 0);
      cursor = Math.floor(cursor / 2);
    }
    return { siblings, indices, root: layers[this.levels][0] };
  }

  private ensureLayers(): bigint[][] {
    if (this.layers) return this.layers;
    const layers: bigint[][] = [this.leaves.slice()];
    for (let level = 0; level < this.levels; level++) {
      const nodes = layers[level];
      const next: bigint[] = [];
      for (let i = 0; i < nodes.length; i += 2) {
        const right = i + 1 < nodes.length ? nodes[i + 1] : this.zeros[level];
        next.push(this.hash2(nodes[i], right));
      }
      layers.push(next);
    }
    this.layers = layers;
    return layers;
  }
}

export class NoteForest {
  readonly trees: NoteTree[] = [];

  constructor(private readonly hash2: (left: bigint, right: bigint) => bigint) {}

  emptyRoot(): bigint {
    return new NoteTree(this.hash2).emptyRoot();
  }

  ensure(treeNumber: number): NoteTree {
    while (this.trees.length <= treeNumber) this.trees.push(new NoteTree(this.hash2));
    return this.trees[treeNumber];
  }

    tree(treeNumber: number): NoteTree {
    const found = this.trees[treeNumber];
    if (!found) throw new Error("Tree is missing");
    return found;
  }
}
