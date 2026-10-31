use anchor_lang::prelude::*;
use anchor_lang::solana_program::bpf_loader_upgradeable;

declare_id!("BGWyueTRXKDyq2j1KbCT1LGYj6kegwEVEUFzbjPqgtA7");

/// Relayers are off-chain fee payers. Swaps live in the pool as isolated escrows.
#[program]
pub mod lacuna_relay {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, pool: Pubkey) -> Result<()> {
        require!(pool != Pubkey::default(), RelayError::BadCall);
        if let Some(authority) = ctx.accounts.program_data.upgrade_authority_address {
            if authority != Pubkey::default() {
                require!(authority == ctx.accounts.payer.key(), RelayError::BadCall);
            }
        }
        ctx.accounts.relay.pool = pool;
        ctx.accounts.relay.bump = ctx.bumps.relay;
        Ok(())
    }
}

#[account]
pub struct Relay {
    pub pool: Pubkey,
    pub bump: u8,
}

impl Relay {
    pub const SIZE: usize = 8 + 32 + 1;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = Relay::SIZE,
        seeds = [b"relay"],
        bump
    )]
    pub relay: Account<'info, Relay>,
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::ID
    )]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum RelayError {
    #[msg("Bad relay call")]
    BadCall,
}
