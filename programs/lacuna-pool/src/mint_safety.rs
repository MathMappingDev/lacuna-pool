use crate::error::LacunaError;
use anchor_lang::prelude::*;
use anchor_spl::token_interface::Mint;
use spl_token_2022::extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions};
use spl_token_2022::state::Mint as SplMint;

/// Token-2022 types that let an issuer freeze, close, hook, or otherwise seize notes.
/// 26 is Pausable; this crate's ExtensionType enum may predate that variant.
const BLOCKED_EXTENSIONS: &[u16] = &[
    ExtensionType::MintCloseAuthority as u16,
    ExtensionType::ConfidentialTransferMint as u16,
    ExtensionType::DefaultAccountState as u16,
    ExtensionType::NonTransferable as u16,
    ExtensionType::PermanentDelegate as u16,
    ExtensionType::TransferHook as u16,
    ExtensionType::InterestBearingConfig as u16,
    26,
];

pub fn assert_mint_safe(mint: &InterfaceAccount<Mint>) -> Result<()> {
    let info = mint.to_account_info();
    if info.owner == &anchor_spl::token::ID {
        return Ok(());
    }
    require!(
        info.owner == &anchor_spl::token_2022::ID,
        LacunaError::BadMint
    );
    let data = info.try_borrow_data()?;
    let parsed = StateWithExtensions::<SplMint>::unpack(&data).map_err(|_| error!(LacunaError::BadMint))?;
    let types = parsed
        .get_extension_types()
        .map_err(|_| error!(LacunaError::BadMint))?;
    for ext in types {
        require!(
            !BLOCKED_EXTENSIONS.contains(&(ext as u16)),
            LacunaError::BadMint
        );
    }
    reject_unknown_blocked(&data)
}

/// Swap hop and refund cannot price a withheld transfer fee. Refuse those mints for swaps only.
pub fn assert_mint_no_transfer_fee(mint: &InterfaceAccount<Mint>) -> Result<()> {
    let info = mint.to_account_info();
    if info.owner == &anchor_spl::token::ID {
        return Ok(());
    }
    require!(
        info.owner == &anchor_spl::token_2022::ID,
        LacunaError::BadMint
    );
    let data = info.try_borrow_data()?;
    let parsed = StateWithExtensions::<SplMint>::unpack(&data).map_err(|_| error!(LacunaError::BadMint))?;
    let types = parsed
        .get_extension_types()
        .map_err(|_| error!(LacunaError::BadMint))?;
    for ext in types {
        require!(
            ext != ExtensionType::TransferFeeConfig,
            LacunaError::FeeOnTransfer
        );
    }
    Ok(())
}

/// Newer Token-2022 builds can add Pausable (26) after this crate's enum.
fn reject_unknown_blocked(data: &[u8]) -> Result<()> {
    const TLV: usize = 166;
    if data.len() < TLV {
        return Ok(());
    }
    let mut offset = TLV;
    while offset.saturating_add(4) <= data.len() {
        let ext_type = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
        let ext_len = u16::from_le_bytes(data[offset + 2..offset + 4].try_into().unwrap()) as usize;
        if ext_type == 0 {
            break;
        }
        require!(
            !BLOCKED_EXTENSIONS.contains(&ext_type),
            LacunaError::BadMint
        );
        offset = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(ext_len))
            .ok_or(LacunaError::BadMint)?;
    }
    Ok(())
}
