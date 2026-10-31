use crate::constants::FIELD;
use crate::error::LacunaError;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;

pub fn ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.as_slice() >= b.as_slice()
}

pub fn sub_be(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let av = a[i] as u16;
        let bv = b[i] as u16 + borrow;
        if av < bv {
            a[i] = (av + 256 - bv) as u8;
            borrow = 1;
        } else {
            a[i] = (av - bv) as u8;
            borrow = 0;
        }
    }
}

pub fn reduce_field(mut n: [u8; 32]) -> [u8; 32] {
    while ge(&n, &FIELD) {
        sub_be(&mut n, &FIELD);
    }
    n
}

pub fn keccak_field(data: &[u8]) -> [u8; 32] {
    reduce_field(keccak::hash(data).0)
}

pub fn pubkey_field(key: &Pubkey) -> [u8; 32] {
    keccak_field(key.as_ref())
}

pub fn mint_field(mint: &Pubkey) -> Result<[u8; 32]> {
    let field = pubkey_field(mint);
    require!(field != [0u8; 32], LacunaError::BadValue);
    Ok(field)
}

pub fn is_zero(value: &[u8; 32]) -> bool {
    value.iter().all(|b| *b == 0)
}

pub fn lt_field(value: &[u8; 32]) -> bool {
    !ge(value, &FIELD)
}

pub fn field_u128(value: &[u8; 32]) -> Result<u128> {
    require!(value[..16].iter().all(|b| *b == 0), LacunaError::BadValue);
    Ok(u128::from_be_bytes(value[16..32].try_into().unwrap()))
}

pub fn u128_field(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

pub fn fee_of(gross: u128, bps: u16) -> Result<u128> {
    Ok(gross
        .checked_mul(bps as u128)
        .ok_or(LacunaError::BadValue)?
        / crate::constants::BPS_DENOMINATOR)
}

pub fn check_unshield_fee(amount: u128, fee: u128, relay_fee: u128, bps: u16) -> Result<()> {
    let leaving = amount
        .checked_add(fee)
        .and_then(|v| v.checked_add(relay_fee))
        .ok_or(LacunaError::BadValue)?;
    let required = leaving
        .checked_mul(bps as u128)
        .ok_or(LacunaError::BadValue)?
        / crate::constants::BPS_DENOMINATOR;
    require!(fee >= required, LacunaError::BadFee);
    Ok(())
}

pub fn ciphertext_commitment(first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + first.len() + second.len());
    buf.extend_from_slice(&(first.len() as u32).to_le_bytes());
    buf.extend_from_slice(first);
    buf.extend_from_slice(&(second.len() as u32).to_le_bytes());
    buf.extend_from_slice(second);
    keccak_field(&buf)
}

pub fn swap_commitment(
    hop: &Pubkey,
    mint_out: &Pubkey,
    min_out: u64,
    out_owner_hash: &[u8; 32],
    refund_owner_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 32 + 8 + 32 + 32);
    buf.extend_from_slice(hop.as_ref());
    buf.extend_from_slice(mint_out.as_ref());
    buf.extend_from_slice(&min_out.to_le_bytes());
    buf.extend_from_slice(out_owner_hash);
    buf.extend_from_slice(refund_owner_hash);
    keccak_field(&buf)
}
