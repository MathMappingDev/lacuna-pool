pub const LEVELS: usize = 16;
pub const TREE_CAPACITY: u64 = 1 << LEVELS;
pub const MAX_FEE_BPS: u16 = 100;
pub const BPS_DENOMINATOR: u128 = 10_000;
pub const DEFAULT_FEE_BPS: u16 = 20;
pub const MAX_CIPHERTEXT: usize = 1024;
pub const MAX_EXIT_PAUSE_SECS: i64 = 3 * 24 * 60 * 60;
/// Default exclusive-refund window (~80s). Owner may set 150–300 slots.
pub const DEFAULT_REFUND_DELAY_SLOTS: u64 = 200;
pub const MIN_REFUND_DELAY_SLOTS: u64 = 150;
pub const MAX_REFUND_DELAY_SLOTS: u64 = 300;
pub const EXIT_PAUSE_COOLDOWN_SECS: i64 = 7 * 24 * 60 * 60;
pub const PROOF_A_SIZE: usize = 64;
pub const PROOF_B_SIZE: usize = 128;
pub const PROOF_C_SIZE: usize = 64;
pub const PUBLIC_INPUTS: usize = 17;
pub const PROOF_BUFFER_SIZE: usize = PROOF_A_SIZE + PROOF_B_SIZE + PROOF_C_SIZE + PUBLIC_INPUTS * 32;

pub const SEED_CONFIG: &[u8] = b"config";
pub const SEED_VAULT: &[u8] = b"vault";
pub const SEED_TREE: &[u8] = b"tree";
pub const SEED_TOKEN: &[u8] = b"token";
pub const SEED_NULLIFIER: &[u8] = b"nullifier";
pub const SEED_COMMITMENT: &[u8] = b"commitment";
pub const SEED_ROOT: &[u8] = b"root";
pub const SEED_NOTE: &[u8] = b"note";
pub const SEED_BUFFER: &[u8] = b"buffer";
pub const SEED_ESCROW: &[u8] = b"escrow";

/// BN254 scalar field, big-endian.
pub const FIELD: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];
