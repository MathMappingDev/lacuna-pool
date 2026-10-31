use crate::constants::{LEVELS, MAX_CIPHERTEXT};
use anchor_lang::prelude::*;

#[account]
pub struct Config {
    pub owner: Pubkey,
    pub treasury: Pubkey,
    pub vault: Pubkey,
    /// Allowlisted hop (Jupiter or the dummy AMM in tests). Default = none.
    pub swap_program: Pubkey,
    pub shield_fee_bps: u16,
    pub unshield_fee_bps: u16,
    pub swap_fee_bps: u16,
    pub tree_number: u64,
    pub bump: u8,
    pub vault_bump: u8,
    pub paused_deposits: bool,
    pub paused_private: bool,
    pub paused_swaps: bool,
    pub exit_pause_until: i64,
    pub last_exit_pause: i64,
    pub refund_delay_slots: u64,
}

impl Config {
    pub const SIZE: usize = 8 + 32 + 32 + 32 + 32 + 2 + 2 + 2 + 8 + 1 + 1 + 1 + 1 + 1 + 8 + 8 + 8;
}

#[account]
pub struct Tree {
    pub tree_number: u64,
    pub next_index: u64,
    pub current_root: [u8; 32],
    pub filled_subtrees: [[u8; 32]; LEVELS],
    pub zeros: [[u8; 32]; LEVELS],
}

impl Tree {
    pub const SIZE: usize = 8 + 8 + 8 + 32 + 32 * LEVELS + 32 * LEVELS;
}

#[account]
pub struct TokenState {
    pub token_id: [u8; 32],
    pub mint: Pubkey,
    pub is_native: bool,
    pub is_nft: bool,
    pub pool_balance: u128,
    pub fee_balance: u128,
}

impl TokenState {
    pub const SIZE: usize = 8 + 32 + 32 + 1 + 1 + 16 + 16;
}

#[account]
pub struct NoteRecord {
    pub tree_number: u64,
    pub leaf_index: u64,
    pub commitment: [u8; 32],
    /// Public net for shield and swap notes. Zero for private-send outputs.
    pub net: u128,
    pub ciphertext_len: u16,
    pub ciphertext: [u8; MAX_CIPHERTEXT],
}

impl NoteRecord {
    pub const SIZE: usize = 8 + 8 + 8 + 32 + 16 + 2 + MAX_CIPHERTEXT;
}

#[account]
pub struct Marker {
    pub bump: u8,
}

impl Marker {
    pub const SIZE: usize = 8 + 1;
}

#[account]
pub struct ProofBuffer {
    pub authority: Pubkey,
    pub filled: u32,
    pub payload: [u8; crate::constants::PROOF_BUFFER_SIZE],
}

impl ProofBuffer {
    pub const SIZE: usize = 8 + 32 + 4 + crate::constants::PROOF_BUFFER_SIZE;
}

#[account]
pub struct CipherBuffer {
    pub authority: Pubkey,
    pub filled: u32,
    pub payload: [u8; MAX_CIPHERTEXT],
}

impl CipherBuffer {
    pub const SIZE: usize = 8 + 32 + 4 + MAX_CIPHERTEXT;
}

/// Isolated swap escrow. Holds one input mint until execute or refund.
/// The hop may only sign for this PDA against `escrow_ata`; no other escrow-owned ATAs.
#[account]
pub struct SwapEscrow {
    pub bump: u8,
    pub mint_in: Pubkey,
    pub mint_out: Pubkey,
    pub hop: Pubkey,
    pub amount_in: u64,
    pub min_out: u64,
    pub owner_hash: [u8; 32],
    pub out_owner_hash: [u8; 32],
    pub token_in: [u8; 32],
    pub token_out: [u8; 32],
    pub nullifier0: [u8; 32],
    pub preparer: Pubkey,
    pub prepared_slot: u64,
    pub out_cipher_hash: [u8; 32],
    pub refund_cipher_hash: [u8; 32],
}

impl SwapEscrow {
    pub const SIZE: usize = 8
        + 1
        + 32
        + 32
        + 32
        + 8
        + 8
        + 32
        + 32
        + 32
        + 32
        + 32
        + 32
        + 32
        + 8
        + 32
        + 32;
}

/// Native SOL sentinel. Matches Ethereum token id 0.
pub fn native_token_id() -> [u8; 32] {
    [0u8; 32]
}
