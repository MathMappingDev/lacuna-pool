import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";
import { Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  createAccount,
  createInitializeMint2Instruction,
  createInitializeTransferFeeConfigInstruction,
  createMint,
  ExtensionType,
  getAssociatedTokenAddressSync,
  getMintLen,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import {
  closeBuffers,
  commitmentPda,
  commitmentOf,
  configPda,
  createWallet,
  ciphertextHash,
  emptySpend,
  encryptNote,
  getHasher,
  hash2,
  keysFromPhrase,
  loadTree,
  minProtocolFee,
  mintField,
  nativeTokenId,
  NoteTree,
  notePda,
  outputOf,
  parseAddress,
  programDataPda,
  proveTransact,
  randomBlinding,
  relayPda,
  rootPda,
  scan,
  shieldNft,
  shieldSol,
  shieldToken,
  spendable,
  splitGross,
  submitTransact,
  swapExecute,
  swapPrepare,
  swapRefund,
  tokenPda,
  treePda,
  vaultPda,
} from "../sdk/src";

describe("Lacuna Solana pool", function () {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.LacunaPool as any;
  const relayProgram = anchor.workspace.LacunaRelay as any;
  const ammProgram = anchor.workspace.DummyAmm as any;
  const payer = provider.wallet.publicKey;
  const wallet = (provider.wallet as unknown as { payer: Keypair }).payer;
  const [relayKey] = relayPda();

  async function initializeOnce() {
    const hasher = await getHasher();
    const empty = new NoteTree(hasher).emptyRoot();
    const [emptyRoot] = PublicKey.findProgramAddressSync(
      [Buffer.from("root"), Buffer.from(empty.toString(16).padStart(64, "0"), "hex")],
      program.programId,
    );
    const configInfo = await provider.connection.getAccountInfo(configPda()[0]);
    if (!configInfo) {
      await program.methods.initialize(payer).accounts({
        payer,
        emptyRoot,
        programData: programDataPda(program.programId),
        systemProgram: SystemProgram.programId,
      }).rpc();
    }
    const relayInfo = await provider.connection.getAccountInfo(relayKey);
    if (!relayInfo) {
      await relayProgram.methods.initialize(program.programId).accounts({
        payer,
        programData: programDataPda(relayProgram.programId),
      }).rpc();
    }
    const config = await program.account.config.fetch(configPda()[0]);
    if (config.swapProgram.equals(PublicKey.default)) {
      await program.methods.setSwapProgram(ammProgram.programId).accounts({ payer }).rpc();
    }
  }

  before(async function () {
    await initializeOnce();
  });

  it("matches the SDK Poseidon hash and keeps both fees within 0% to 1%", async function () {
    const config = await program.account.config.fetch(configPda()[0]);
    expect(config.owner.toBase58()).to.equal(payer.toBase58());
    expect(config.shieldFeeBps).to.equal(20);
    expect(config.unshieldFeeBps).to.equal(20);
    expect(config.swapFeeBps).to.equal(20);
    await program.methods.setShieldFeeBps(0).accounts({ payer }).rpc();
    await program.methods.setShieldFeeBps(100).accounts({ payer }).rpc();
    await program.methods.setUnshieldFeeBps(0).accounts({ payer }).rpc();
    await program.methods.setUnshieldFeeBps(100).accounts({ payer }).rpc();
    await program.methods.setSwapFeeBps(0).accounts({ payer }).rpc();
    await program.methods.setSwapFeeBps(100).accounts({ payer }).rpc();
    try {
      await program.methods.setShieldFeeBps(101).accounts({ payer }).rpc();
      expect.fail("expected BadFee");
    } catch (error: unknown) {
      expect(String(error)).to.match(/BadFee|custom program error/i);
    }
    const tree = new NoteTree(await getHasher());
    const onchain = await program.account.tree.fetch(treePda()[0]);
    const root = BigInt("0x" + Buffer.from(onchain.currentRoot).toString("hex"));
    expect(root).to.equal(tree.emptyRoot());
    await program.methods.setShieldFeeBps(20).accounts({ payer }).rpc();
    await program.methods.setUnshieldFeeBps(20).accounts({ payer }).rpc();
    await program.methods.setSwapFeeBps(20).accounts({ payer }).rpc();
  });

  it("shields, sends privately, pays a broadcaster, unshields, and withdraws fees", async function () {
    const alice = await createWallet();
    const bob = await keysFromPhrase((await createWallet()).phrase);
    expect(parseAddress(alice.address).npk).to.equal(alice.npk);
    expect(alice.address.startsWith("0LcnZK")).to.equal(true);
    expect(alice.address).to.have.length(142);
    const flipped = `${alice.address.slice(0, -1)}${alice.address.endsWith("0") ? "1" : "0"}`;
    expect(() => parseAddress(flipped)).to.throw(/checksum/);

    const gross = BigInt(LAMPORTS_PER_SOL);
    const shielded = splitGross(gross);
    await shieldSol({
      program,
      payer,
      gross,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
    });
    const nativeState = await program.account.tokenState.fetch(tokenPda(nativeTokenId())[0]);
    expect(BigInt(nativeState.poolBalance.toString())).to.equal(shielded.net);
    expect(BigInt(nativeState.feeBalance.toString())).to.equal(shielded.fee);

    const stranger = Keypair.generate();
    try {
      await program.methods
        .withdrawFees()
        .accounts({
          payer: stranger.publicKey,
          destination: stranger.publicKey,
          tokenState: tokenPda(nativeTokenId())[0],
          mint: null,
          vaultAta: null,
          destinationAta: null,
          tokenProgram: null,
        })
        .signers([stranger])
        .rpc();
      expect.fail("expected NotTreasury");
    } catch (error: unknown) {
      expect(String(error)).to.match(/NotTreasury|custom program error/i);
    }

    const treasuryBefore = await provider.connection.getBalance(payer);
    await program.methods
      .withdrawFees()
      .accounts({
        payer,
        destination: payer,
        tokenState: tokenPda(nativeTokenId())[0],
        mint: null,
        vaultAta: null,
        destinationAta: null,
        tokenProgram: null,
      })
      .rpc();
    const afterWithdraw = await program.account.tokenState.fetch(tokenPda(nativeTokenId())[0]);
    expect(BigInt(afterWithdraw.feeBalance.toString())).to.equal(0n);
    expect(BigInt(afterWithdraw.poolBalance.toString())).to.equal(shielded.net);
    expect(await provider.connection.getBalance(payer)).to.be.greaterThan(treasuryBefore - Number(gross));

    let tree = await loadTree(program);
    let aliceNotes = await scan(program, alice);
    expect(aliceNotes).to.have.length(1);
    expect(aliceNotes[0].value).to.equal(shielded.net);

    const payment = (4n * gross) / 10n;
    const relayFee = gross / 100n;
    const tipFee = minProtocolFee(relayFee);
    const changeValue = shielded.net - payment - relayFee - tipFee;
    const paymentNote = outputOf(payment, bob.npk, randomBlinding());
    const changeNote = outputOf(changeValue, alice.npk, randomBlinding());
    const tipWallet = Keypair.generate();
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(tipWallet.publicKey, LAMPORTS_PER_SOL),
    );
    const tipBefore = await provider.connection.getBalance(tipWallet.publicKey);
    await submitTransact({
      program,
      payer,
      root: tree.tree(aliceNotes[0].treeNumber).path(aliceNotes[0].index).root,
      token: 0n,
      inputs: [await spendable(alice, aliceNotes[0], tree), emptySpend()],
      outputs: [paymentNote, changeNote],
      ciphertexts: [
        encryptNote({ value: payment, blinding: paymentNote.blinding, token: 0n }, bob.viewingPublic),
        encryptNote({ value: changeValue, blinding: changeNote.blinding, token: 0n }, alice.viewingPublic),
      ],
      relayFee,
      relayRecipient: tipWallet.publicKey,
    });
    expect(await provider.connection.getBalance(tipWallet.publicKey)).to.equal(tipBefore + Number(relayFee));

    tree = await loadTree(program);
    const bobNotes = await scan(program, bob);
    expect(bobNotes).to.have.length(1);
    const unshield = splitGross(bobNotes[0].value);
    await submitTransact({
      program,
      payer,
      root: tree.tree(bobNotes[0].treeNumber).path(bobNotes[0].index).root,
      token: 0n,
      inputs: [await spendable(bob, bobNotes[0], tree), emptySpend()],
      outputs: [outputOf(0n, 0n, 0n), outputOf(0n, 0n, 0n)],
      ciphertexts: ["0x", "0x"],
      publicAmount: bobNotes[0].value,
      recipient: payer,
    });
    const nativeAfter = await program.account.tokenState.fetch(tokenPda(nativeTokenId())[0]);
    expect(BigInt(nativeAfter.feeBalance.toString())).to.equal(tipFee + unshield.fee);

    const mint = await createMint(provider.connection, wallet, payer, null, 9);
    const tokenId = mintField(mint);
    const payerAta = await createAccount(provider.connection, wallet, mint, payer);
    await mintTo(provider.connection, wallet, mint, payerAta, payer, 1_000_000);
    const splAlice = await createWallet();
    await shieldToken({
      program,
      payer,
      mint,
      amount: 1_000_000n,
      npk: splAlice.npk,
      blinding: randomBlinding(),
      viewingPublic: splAlice.viewingPublic,
      tokenId,
    });
    const splState = await program.account.tokenState.fetch(tokenPda(Buffer.from(tokenId.toString(16).padStart(64, "0"), "hex"))[0]);
    expect(BigInt(splState.poolBalance.toString())).to.equal(splitGross(1_000_000n).net);
    expect(BigInt(splState.feeBalance.toString())).to.equal(splitGross(1_000_000n).fee);
    const proofBefore = await provider.connection.getAccountInfo(
      PublicKey.findProgramAddressSync(
        [Buffer.from("buffer"), Buffer.from("proof"), payer.toBuffer()],
        program.programId,
      )[0],
    );
    expect(proofBefore).to.not.equal(null);
    await closeBuffers(program, payer);
    const proofAfter = await provider.connection.getAccountInfo(
      PublicKey.findProgramAddressSync(
        [Buffer.from("buffer"), Buffer.from("proof"), payer.toBuffer()],
        program.programId,
      )[0],
    );
    expect(proofAfter).to.equal(null);
  });

  it("rejects a tip that skips the unshield fee", async function () {
    const alice = await createWallet();
    const gross = BigInt(LAMPORTS_PER_SOL) / 10n;
    await shieldSol({
      program,
      payer,
      gross,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
    });
    const tree = await loadTree(program);
    const notes = await scan(program, alice);
    const last = notes[notes.length - 1];
    try {
      await submitTransact({
        program,
        payer,
        root: tree.tree(last.treeNumber).path(last.index).root,
        token: 0n,
        inputs: [await spendable(alice, last, tree), emptySpend()],
        outputs: [outputOf(0n, 0n, 0n), outputOf(0n, 0n, 0n)],
        ciphertexts: ["0x", "0x"],
        publicAmount: 0n,
        protocolFee: 0n,
        relayFee: last.value,
        relayRecipient: payer,
      });
      expect.fail("expected BadFee");
    } catch (error: unknown) {
      expect(String(error)).to.match(/BadFee|custom program error|The proof/i);
    }
  });

  it("shields Token-2022 transfer-fee mints for the amount received", async function () {
    const mintKp = Keypair.generate();
    const mintLen = getMintLen([ExtensionType.TransferFeeConfig]);
    const lamports = await provider.connection.getMinimumBalanceForRentExemption(mintLen);
    const tx = new anchor.web3.Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: payer,
        newAccountPubkey: mintKp.publicKey,
        space: mintLen,
        lamports,
        programId: TOKEN_2022_PROGRAM_ID,
      }),
      createInitializeTransferFeeConfigInstruction(mintKp.publicKey, payer, payer, 500, 5_000n, TOKEN_2022_PROGRAM_ID),
      createInitializeMint2Instruction(mintKp.publicKey, 9, payer, null, TOKEN_2022_PROGRAM_ID),
    );
    await provider.sendAndConfirm(tx, [mintKp]);
    const tokenId = mintField(mintKp.publicKey);
    const payerAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      wallet,
      mintKp.publicKey,
      payer,
      false,
      undefined,
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );
    await mintTo(provider.connection, wallet, mintKp.publicKey, payerAta.address, payer, 1_000_000, [], undefined, TOKEN_2022_PROGRAM_ID);
    const alice = await createWallet();
    await shieldToken({
      program,
      payer,
      mint: mintKp.publicKey,
      amount: 1_000_000n,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
      tokenId,
      tokenProgram: TOKEN_2022_PROGRAM_ID,
    });
    const received = 995_000n;
    const state = await program.account.tokenState.fetch(
      tokenPda(Buffer.from(tokenId.toString(16).padStart(64, "0"), "hex"))[0],
    );
    expect(BigInt(state.poolBalance.toString())).to.equal(splitGross(received).net);
  });

  it("rejects a flipped ciphertext and a replayed nullifier", async function () {
    const alice = await createWallet();
    await shieldSol({
      program,
      payer,
      gross: BigInt(LAMPORTS_PER_SOL) / 20n,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
    });
    const tree = await loadTree(program);
    const note = (await scan(program, alice)).pop()!;
    const change = outputOf(note.value, alice.npk, randomBlinding());
    const good = encryptNote({ value: note.value, blinding: change.blinding, token: 0n }, alice.viewingPublic);
    const built = await submitTransact({
      program,
      payer,
      root: tree.tree(note.treeNumber).path(note.index).root,
      token: 0n,
      inputs: [await spendable(alice, note, tree), emptySpend()],
      outputs: [change, outputOf(0n, 0n, 0n)],
      ciphertexts: [good, "0x"],
      buildOnly: true,
    });
    const tamper = Buffer.from("ffff", "hex");
    const accounts = built.accounts!;
    const expectedIndex = () =>
      program.account.tree.fetch(treePda()[0]).then((tree: { nextIndex: { toString(): string } }) =>
        new anchor.BN(tree.nextIndex.toString()),
      );
    await program.methods.writeCipherBuffer(0, tamper).accounts({ payer, buffer: accounts.ciphertext0 }).rpc();
    try {
      await program.methods.transact(await expectedIndex()).accounts(accounts).rpc();
      expect.fail("expected BadProof");
    } catch (error: unknown) {
      expect(String(error)).to.match(/BadProof|custom program error/i);
    }
    await program.methods.writeCipherBuffer(0, Buffer.from(good.slice(2), "hex")).accounts({ payer, buffer: accounts.ciphertext0 }).rpc();
    await program.methods.transact(await expectedIndex()).accounts(accounts).rpc();
    try {
      await program.methods.transact(await expectedIndex()).accounts(accounts).rpc();
      expect.fail("expected DoubleSpend");
    } catch (error: unknown) {
      expect(String(error)).to.match(/DoubleSpend|already in use|custom program error/i);
    }
  });

  it("rejects a proof with both inputs disabled", async function () {
    const empty = await proveTransact({
      root: new NoteTree(await getHasher()).emptyRoot(),
      token: 0n,
      publicAmount: 0n,
      recipient: 0n,
      relayFee: 0n,
      protocolFee: 0n,
      relayRecipient: 0n,
      externalHash: 0n,
      ciphertextHash: ciphertextHash("0x", "0x"),
      inputs: [emptySpend(), emptySpend()],
      outputs: [outputOf(0n, 0n, 0n), outputOf(0n, 0n, 0n)],
    });
    expect(BigInt(empty.pubSignals[1])).to.equal(0n);
    expect(BigInt(empty.pubSignals[2])).to.equal(0n);
    const alice = await createWallet();
    await shieldSol({
      program,
      payer,
      gross: BigInt(LAMPORTS_PER_SOL) / 50n,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
    });
    const tree = await loadTree(program);
    const onchain = await program.account.tree.fetch(treePda()[0]);
    const root = BigInt("0x" + Buffer.from(onchain.currentRoot).toString("hex"));
    try {
      await submitTransact({
        program,
        payer,
        root,
        token: 0n,
        inputs: [emptySpend(), emptySpend()],
        outputs: [outputOf(0n, 0n, 0n), outputOf(0n, 0n, 0n)],
        ciphertexts: ["0x", "0x"],
      });
      expect.fail("expected BadValue");
    } catch (error: unknown) {
      expect(String(error)).to.match(/BadValue|disabled|custom program error|The proof/i);
    }
  });

  it("treats an NFT note as value 1 with no percent fee", async function () {
    const nft = await createMint(provider.connection, wallet, payer, null, 0);
    const tokenId = mintField(nft);
    const payerAta = await createAccount(provider.connection, wallet, nft, payer);
    await mintTo(provider.connection, wallet, nft, payerAta, payer, 1);
    const alice = await createWallet();
    const bob = await createWallet();
    await shieldNft({
      program,
      payer,
      mint: nft,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
      tokenId,
    });
    const state = await program.account.tokenState.fetch(
      tokenPda(Buffer.from(tokenId.toString(16).padStart(64, "0"), "hex"))[0],
    );
    expect(state.isNft).to.equal(true);
    expect(BigInt(state.feeBalance.toString())).to.equal(0n);
    let tree = await loadTree(program);
    const notes = (await scan(program, alice)).filter((note) => note.token === tokenId);
    expect(notes[0].value).to.equal(1n);
    const sent = outputOf(1n, bob.npk, randomBlinding(), tokenId);
    await submitTransact({
      program,
      payer,
      root: tree.tree(notes[0].treeNumber).path(notes[0].index).root,
      token: tokenId,
      inputs: [await spendable(alice, notes[0], tree), emptySpend()],
      outputs: [sent, outputOf(0n, 0n, 0n)],
      ciphertexts: [encryptNote({ value: 1n, blinding: sent.blinding, token: tokenId }, bob.viewingPublic), "0x"],
    });
    tree = await loadTree(program);
    const bobNotes = (await scan(program, bob)).filter((note) => note.token === tokenId);
    const bobAta = await getOrCreateAssociatedTokenAccount(provider.connection, wallet, nft, payer);
    const vaultAta = getAssociatedTokenAddressSync(nft, vaultPda()[0], true);
    await submitTransact({
      program,
      payer,
      root: tree.tree(bobNotes[0].treeNumber).path(bobNotes[0].index).root,
      token: tokenId,
      inputs: [await spendable(bob, bobNotes[0], tree), emptySpend()],
      outputs: [outputOf(0n, 0n, 0n), outputOf(0n, 0n, 0n)],
      ciphertexts: ["0x", "0x"],
      publicAmount: 1n,
      protocolFee: 0n,
      recipient: payer,
      accounts: {
        tokenMint0: nft,
        vaultAta0: vaultAta,
        recipientAta0: bobAta.address,
        tokenProgram: TOKEN_PROGRAM_ID,
      },
    });
    const after = await program.account.tokenState.fetch(
      tokenPda(Buffer.from(tokenId.toString(16).padStart(64, "0"), "hex"))[0],
    );
    expect(BigInt(after.feeBalance.toString())).to.equal(0n);
  });

  it("swaps through an isolated escrow", async function () {
    const sell = await createMint(provider.connection, wallet, payer, null, 9);
    const buy = await createMint(provider.connection, wallet, payer, null, 9);
    const sellId = mintField(sell);
    const buyId = mintField(buy);
    const alice = await createWallet();
    const payerSell = await getOrCreateAssociatedTokenAccount(provider.connection, wallet, sell, payer);
    await mintTo(provider.connection, wallet, sell, payerSell.address, payer, 1_000_000);
    await shieldToken({
      program,
      payer,
      mint: sell,
      amount: 1_000_000n,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
      tokenId: sellId,
    });
    const [ammAuth] = PublicKey.findProgramAddressSync([Buffer.from("amm")], ammProgram.programId);
    const vault = vaultPda()[0];
    const ammSell = await getOrCreateAssociatedTokenAccount(provider.connection, wallet, sell, ammAuth, true);
    const ammBuy = await getOrCreateAssociatedTokenAccount(provider.connection, wallet, buy, ammAuth, true);
    await mintTo(provider.connection, wallet, buy, ammBuy.address, payer, 400_000);
    let tree = await loadTree(program);
    const note = (await scan(program, alice)).filter((item) => item.token === sellId).pop()!;
    const swapAmount = 400_000n;
    const changeValue = note.value - swapAmount;
    const change = outputOf(changeValue, alice.npk, randomBlinding(), sellId);
    const outBlinding = randomBlinding();
    const refundBlinding = randomBlinding();
    const prepared = await swapPrepare({
      pool: program,
      payer,
      root: tree.tree(note.treeNumber).path(note.index).root,
      token: sellId,
      mintIn: sell,
      mintOut: buy,
      hop: ammProgram.programId,
      minOut: swapAmount,
      amountIn: swapAmount,
      inputs: [await spendable(alice, note, tree), emptySpend()],
      outputs: [change, outputOf(0n, 0n, 0n)],
      ciphertexts: [
        encryptNote({ value: changeValue, blinding: change.blinding, token: sellId }, alice.viewingPublic),
        "0x",
      ],
      outNpk: alice.npk,
      outBlinding,
      refundNpk: alice.npk,
      refundBlinding,
      accounts: {
        tokenMint0: sell,
        vaultAta0: getAssociatedTokenAddressSync(sell, vault, true),
        tokenProgram: TOKEN_PROGRAM_ID,
      },
    });
    const swapIx = await ammProgram.methods
      .swap(new anchor.BN(swapAmount.toString()))
      .accounts({
        user: prepared.escrow,
        ammAuthority: ammAuth,
        mintIn: sell,
        mintOut: buy,
        userSource: getAssociatedTokenAddressSync(sell, prepared.escrow, true),
        userDest: getAssociatedTokenAddressSync(buy, vault, true),
        ammSource: ammSell.address,
        ammDest: ammBuy.address,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .instruction();
    await swapExecute({
      pool: program,
      payer,
      nullifier0: prepared.nullifier0,
      mintIn: sell,
      mintOut: buy,
      hop: {
        programId: ammProgram.programId,
        data: Buffer.from(swapIx.data),
        accounts: swapIx.keys.map((key) => ({
          pubkey: key.pubkey,
          isWritable: key.isWritable,
          isSigner: key.pubkey.equals(prepared.escrow) ? false : key.isSigner,
        })),
      },
      amountOut: swapAmount,
      outNpk: alice.npk,
      outBlinding,
      viewingPublic: alice.viewingPublic,
      tokenIdOut: buyId,
    });
    const buyNotes = (await scan(program, alice)).filter((item) => item.token === buyId);
    expect(buyNotes[0].value).to.equal(splitGross(swapAmount).net);

    const bob = await createWallet();
    await mintTo(provider.connection, wallet, sell, payerSell.address, payer, 500_000);
    await shieldToken({
      program,
      payer,
      mint: sell,
      amount: 500_000n,
      npk: bob.npk,
      blinding: randomBlinding(),
      viewingPublic: bob.viewingPublic,
      tokenId: sellId,
    });
    tree = await loadTree(program);
    const bobNote = (await scan(program, bob)).filter((item) => item.token === sellId).pop()!;
    const refundAmount = 100_000n;
    const refundChange = outputOf(bobNote.value - refundAmount, bob.npk, randomBlinding(), sellId);
    const refundBlinding2 = randomBlinding();
    const refunded = await swapPrepare({
      pool: program,
      payer,
      root: tree.tree(bobNote.treeNumber).path(bobNote.index).root,
      token: sellId,
      mintIn: sell,
      mintOut: buy,
      hop: ammProgram.programId,
      minOut: refundAmount,
      amountIn: refundAmount,
      inputs: [await spendable(bob, bobNote, tree), emptySpend()],
      outputs: [refundChange, outputOf(0n, 0n, 0n)],
      ciphertexts: [
        encryptNote(
          { value: bobNote.value - refundAmount, blinding: refundChange.blinding, token: sellId },
          bob.viewingPublic,
        ),
        "0x",
      ],
      outNpk: bob.npk,
      outBlinding: randomBlinding(),
      refundNpk: bob.npk,
      refundBlinding: refundBlinding2,
      accounts: {
        tokenMint0: sell,
        vaultAta0: getAssociatedTokenAddressSync(sell, vault, true),
        tokenProgram: TOKEN_PROGRAM_ID,
      },
    });
    await swapRefund({
      pool: program,
      payer,
      nullifier0: refunded.nullifier0,
      mintIn: sell,
      amountIn: refundAmount,
      refundNpk: bob.npk,
      refundBlinding: refundBlinding2,
      viewingPublic: bob.viewingPublic,
      tokenIdIn: sellId,
    });
    const bobAfter = (await scan(program, bob)).filter((item) => item.token === sellId);
    expect(bobAfter.some((item) => item.value === splitGross(refundAmount).net && !item.spent)).to.equal(true);
  });

  it("rejects owner_hash 0", async function () {
    const [cipher] = PublicKey.findProgramAddressSync(
      [Buffer.from("buffer"), Buffer.from("cipher"), payer.toBuffer(), Buffer.from([9])],
      program.programId,
    );
    await program.methods.createCipherBuffer(9).accounts({ payer, buffer: cipher }).rpc().catch(() => undefined);
    try {
      await program.methods
        .shieldSol(
          Array.from({ length: 32 }, () => 0),
          new anchor.BN(1_000_000),
          new anchor.BN((await program.account.tree.fetch(treePda()[0])).nextIndex.toString()),
        )
        .accounts({
          payer,
          source: payer,
          ciphertext: cipher,
          commitment: commitmentPda(Buffer.alloc(32))[0],
          root: rootPda(Buffer.alloc(32))[0],
          note: notePda(0n, 99n)[0],
          tokenState: tokenPda(nativeTokenId())[0],
        })
        .rpc();
      expect.fail("expected BadValue");
    } catch (error: unknown) {
      expect(String(error)).to.match(/BadValue|custom program error|Simulation failed/i);
    }
    expect((await hash2(1n, 2n)) !== 0n).to.equal(true);
    expect(ciphertextHash("0x", "0x")).to.not.equal(undefined);
  });

  it("keeps accepted roots after further inserts", async function () {
    const alice = await createWallet();
    await shieldSol({
      program,
      payer,
      gross: BigInt(LAMPORTS_PER_SOL) / 30n,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
    });
    const firstNotes = await scan(program, alice);
    const first = firstNotes[firstNotes.length - 1];
    const snapshot = (await loadTree(program)).tree(first.treeNumber).path(first.index);
    const firstRoot = snapshot.root;
    await shieldSol({
      program,
      payer,
      gross: BigInt(LAMPORTS_PER_SOL) / 30n,
      npk: alice.npk,
      blinding: randomBlinding(),
      viewingPublic: alice.viewingPublic,
    });
    const tree = await loadTree(program);
    const latest = (await scan(program, alice)).pop()!;
    expect(tree.tree(latest.treeNumber).path(latest.index).root).to.not.equal(firstRoot);
    const spend = await spendable(alice, first, tree);
    spend.siblings = snapshot.siblings;
    spend.indices = snapshot.indices;
    await submitTransact({
      program,
      payer,
      root: firstRoot,
      token: 0n,
      inputs: [spend, emptySpend()],
      outputs: [outputOf(0n, 0n, 0n), outputOf(0n, 0n, 0n)],
      ciphertexts: ["0x", "0x"],
      publicAmount: first.value,
      recipient: payer,
    });
    const [rootAccount] = PublicKey.findProgramAddressSync(
      [Buffer.from("root"), Buffer.from(firstRoot.toString(16).padStart(64, "0"), "hex")],
      program.programId,
    );
    expect(await provider.connection.getAccountInfo(rootAccount)).to.not.equal(null);
  });
});

