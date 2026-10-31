use anchor_lang::prelude::*;

#[error_code]
pub enum LacunaError {
    #[msg("Bad value")]
    BadValue,
    #[msg("Unknown Merkle root")]
    BadRoot,
    #[msg("Invalid proof")]
    BadProof,
    #[msg("Invalid proof point")]
    BadProofPoint,
    #[msg("Pairing check failed")]
    BadPairing,
    #[msg("Fee is below the unshield floor")]
    BadFee,
    #[msg("Not the owner")]
    NotOwner,
    #[msg("Already spent")]
    DoubleSpend,
    #[msg("Ciphertext is too large")]
    CiphertextTooLarge,
    #[msg("Not the treasury")]
    NotTreasury,
    #[msg("Token transfer delivered a different amount")]
    FeeOnTransfer,
    #[msg("Swap program is missing or not allowlisted")]
    BadSwapProgram,
    #[msg("Buffer is incomplete")]
    BadBuffer,
    #[msg("Tree next_index moved; rebuild insert PDAs")]
    StaleTree,
    #[msg("This instruction is paused")]
    Paused,
    #[msg("Mint has a hook, permanent delegate, or other unsafe extension")]
    BadMint,
    #[msg("Swap escrow is invalid or hop is not allowlisted")]
    BadSwap,
    #[msg("Swap output is below min_out")]
    Slippage,
}
