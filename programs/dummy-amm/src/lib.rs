use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

declare_id!("3t95TV1mKuYTnUdV6snomdNKUG9dBSTMSgVYNVGgoTah");

#[program]
pub mod dummy_amm {
    use super::*;

    pub fn ping(_ctx: Context<Ping>) -> Result<()> {
        Ok(())
    }

    pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
        require!(amount_in > 0, ErrorCode::BadAmount);
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.user_source.to_account_info(),
                    mint: ctx.accounts.mint_in.to_account_info(),
                    to: ctx.accounts.amm_source.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount_in,
            ctx.accounts.mint_in.decimals,
        )?;
        let bump = [ctx.bumps.amm_authority];
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.amm_dest.to_account_info(),
                    mint: ctx.accounts.mint_out.to_account_info(),
                    to: ctx.accounts.user_dest.to_account_info(),
                    authority: ctx.accounts.amm_authority.to_account_info(),
                },
                &[&[b"amm", bump.as_ref()]],
            ),
            amount_in,
            ctx.accounts.mint_out.decimals,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Ping {}

#[derive(Accounts)]
pub struct Swap<'info> {
    pub user: Signer<'info>,
    /// CHECK: PDA that owns the AMM vaults
    #[account(seeds = [b"amm"], bump)]
    pub amm_authority: UncheckedAccount<'info>,
    pub mint_in: InterfaceAccount<'info, Mint>,
    pub mint_out: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub user_source: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub user_dest: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub amm_source: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub amm_dest: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Amount must be positive")]
    BadAmount,
}
