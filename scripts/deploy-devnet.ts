import { execSync } from "child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync } from "fs";
import { join } from "path";
import * as anchor from "@coral-xyz/anchor";
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram } from "@solana/web3.js";
import { getHasher } from "../sdk/src/poseidon";
import { NoteTree } from "../sdk/src/tree";
import { configPda, programDataPda, relayPda, treePda, vaultPda } from "../sdk/src/pda";

const ROOT = join(__dirname, "..");
const KEY_PATH = join(ROOT, "deployments/devnet-keypair.json");
const RPC = process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com";
const IDS = JSON.parse(readFileSync(join(ROOT, "scripts/program-ids.json"), "utf8")) as {
  lacuna_pool: string;
  lacuna_relay: string;
  dummy_amm: string;
};

function loadOrCreate(): Keypair {
  mkdirSync(join(ROOT, "deployments"), { recursive: true });
  if (existsSync(KEY_PATH)) {
    return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(KEY_PATH, "utf8"))));
  }
  const keypair = Keypair.generate();
  writeFileSync(KEY_PATH, JSON.stringify(Array.from(keypair.secretKey)));
  return keypair;
}

function writeStatus(extra: Record<string, unknown>) {
  const deployed = {
    network: "devnet",
    pool: IDS.lacuna_pool,
    relay: IDS.lacuna_relay,
    dummyAmm: IDS.dummy_amm,
    note: "Upgrade authority is the deployer. Not audited. Not mainnet.",
    ...extra,
  };
  writeFileSync(join(ROOT, "deployments/devnet.json"), JSON.stringify(deployed, null, 2) + "\n");
  return deployed;
}

function copyBuilt(name: string) {
  const from = join(ROOT, "target/sbf-solana-solana/release", `${name}.so`);
  const to = join(ROOT, "target/deploy", `${name}.so`);
  if (existsSync(from)) copyFileSync(from, to);
  if (!existsSync(to)) throw new Error(`Missing ${to}. Build with cargo-build-sbf --tools-version v1.48.`);
}

function solana(args: string, deployer: Keypair) {
  const solanaBin = `${process.env.HOME}/.local/share/solana/install/active_release/bin/solana`;
  execSync(`${solanaBin} ${args} --url ${RPC} --keypair ${KEY_PATH}`, {
    cwd: ROOT,
    stdio: "inherit",
    env: process.env,
  });
  void deployer;
}

async function airdrop(connection: Connection, pubkey: PublicKey) {
  try {
    const sig = await connection.requestAirdrop(pubkey, 2 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig, "confirmed");
  } catch (error) {
    console.warn("Devnet airdrop failed:", error instanceof Error ? error.message : error);
  }
}

async function initialize(connection: Connection, deployer: Keypair) {
  const wallet = new anchor.Wallet(deployer);
  const provider = new anchor.AnchorProvider(connection, wallet, { commitment: "confirmed" });
  const poolIdl = JSON.parse(readFileSync(join(ROOT, "target/idl/lacuna_pool.json"), "utf8"));
  const relayIdl = JSON.parse(readFileSync(join(ROOT, "target/idl/lacuna_relay.json"), "utf8"));
  const pool = new anchor.Program(poolIdl, provider) as any;
  const relay = new anchor.Program(relayIdl, provider) as any;
  const hasher = await getHasher();
  const empty = new NoteTree(hasher).emptyRoot();
  const [emptyRoot] = PublicKey.findProgramAddressSync(
    [Buffer.from("root"), Buffer.from(empty.toString(16).padStart(64, "0"), "hex")],
    pool.programId,
  );
  const [config] = configPda();
  const [relayKey] = relayPda();
  if (!(await connection.getAccountInfo(config))) {
    await pool.methods
      .initialize(deployer.publicKey)
      .accounts({
        payer: deployer.publicKey,
        emptyRoot,
        programData: programDataPda(pool.programId),
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }
  if (!(await connection.getAccountInfo(relayKey))) {
    await relay.methods
      .initialize(pool.programId)
      .accounts({ payer: deployer.publicKey, programData: programDataPda(relay.programId) })
      .rpc();
  }
  await pool.account.config.fetch(config);
}

async function main() {
  const deployer = loadOrCreate();
  console.log("Deployer", deployer.publicKey.toBase58());
  const connection = new Connection(RPC, "confirmed");
  let balance = await connection.getBalance(deployer.publicKey);
  if (balance < 0.5 * LAMPORTS_PER_SOL) {
    await airdrop(connection, deployer.publicKey);
    balance = await connection.getBalance(deployer.publicKey);
  }
  console.log("Balance", balance / LAMPORTS_PER_SOL, "SOL");
  if (balance < 0.5 * LAMPORTS_PER_SOL) {
    writeStatus({
      status: "awaiting-deployer-funds",
      deployer: deployer.publicKey.toBase58(),
      note: `Send about 2 SOL on Solana Devnet to ${deployer.publicKey.toBase58()}, then run npm run deploy:devnet again. Upgrade authority stays with the deployer. Not audited. Not mainnet.`,
    });
    throw new Error(`Deployer ${deployer.publicKey.toBase58()} needs Devnet SOL`);
  }
  for (const name of ["lacuna_pool", "lacuna_relay", "dummy_amm"]) copyBuilt(name);
  solana(
    `program deploy ${join(ROOT, "target/deploy/lacuna_pool.so")} --program-id ${join(ROOT, "deployments/lacuna_pool-keypair.json")}`,
    deployer,
  );
  solana(
    `program deploy ${join(ROOT, "target/deploy/lacuna_relay.so")} --program-id ${join(ROOT, "deployments/lacuna_relay-keypair.json")}`,
    deployer,
  );
  solana(
    `program deploy ${join(ROOT, "target/deploy/dummy_amm.so")} --program-id ${join(ROOT, "deployments/dummy_amm-keypair.json")}`,
    deployer,
  );
  await initialize(connection, deployer);
  const freeze = process.env.LACUNA_FREEZE_UPGRADE === "1";
  if (freeze) {
    for (const name of ["lacuna_pool", "lacuna_relay", "dummy_amm"]) {
      solana(`program set-upgrade-authority ${IDS[name as keyof typeof IDS]} --final`, deployer);
    }
  }
  const out = writeStatus({
    status: "deployed",
    deployer: deployer.publicKey.toBase58(),
    treasury: deployer.publicKey.toBase58(),
    config: configPda()[0].toBase58(),
    vault: vaultPda()[0].toBase58(),
    tree: treePda()[0].toBase58(),
    relayPda: relayPda()[0].toBase58(),
    upgradeAuthority: freeze ? "frozen" : "deployer",
    note: freeze
      ? "Upgrade authority is frozen. Not audited. Not mainnet."
      : "Upgrade authority is the deployer. Set LACUNA_FREEZE_UPGRADE=1 to call set-upgrade-authority --final. Not audited. Not mainnet.",
  });
  console.log(JSON.stringify(out, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
