use anchor_lang::prelude::*;
use anchor_lang::solana_program::bpf_loader_upgradeable;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};
use anchor_lang::system_program;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::{self, CloseAccount, Mint, TokenAccount, TokenInterface, TransferChecked};

pub mod constants;
pub mod error;
pub mod field;
pub mod merkle;
pub mod mint_safety;
pub mod pda;
pub mod state;
pub mod verify;
pub mod verifying_key;

use constants::*;
use error::LacunaError;
use field::*;
use mint_safety::{assert_mint_no_transfer_fee, assert_mint_safe};
use state::*;
use verify::{parse_proof, verify_proof};

declare_id!("2JNUVMq3Qg3DM5SUFDXXaW1zjxDUkt8WMNtMAwJmJPiH");

#[program]
pub mod lacuna_pool {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, treasury: Pubkey) -> Result<()> {
        if let Some(authority) = ctx.accounts.program_data.upgrade_authority_address {
            if authority != Pubkey::default() {
                require!(authority == ctx.accounts.payer.key(), LacunaError::NotOwner);
            }
        }
        require!(treasury != Pubkey::default(), LacunaError::BadValue);
        let (zeros, root) = merkle::build_zeros()?;
        let config = &mut ctx.accounts.config;
        config.owner = ctx.accounts.payer.key();
        config.treasury = treasury;
        config.vault = ctx.accounts.vault.key();
        config.swap_program = Pubkey::default();
        config.shield_fee_bps = DEFAULT_FEE_BPS;
        config.unshield_fee_bps = DEFAULT_FEE_BPS;
        config.swap_fee_bps = DEFAULT_FEE_BPS;
        config.tree_number = 0;
        config.bump = ctx.bumps.config;
        config.vault_bump = ctx.bumps.vault;
        config.paused_deposits = false;
        config.paused_private = false;
        config.paused_swaps = false;
        config.exit_pause_until = 0;
        config.last_exit_pause = 0;
        config.refund_delay_slots = DEFAULT_REFUND_DELAY_SLOTS;

        let tree = &mut ctx.accounts.tree;
        tree.tree_number = 0;
        tree.next_index = 0;
        tree.current_root = root;
        tree.filled_subtrees = zeros;
        tree.zeros = zeros;

        pda::create_marker(
            ctx.program_id,
            &ctx.accounts.payer.to_account_info(),
            &ctx.accounts.empty_root.to_account_info(),
            &[SEED_ROOT, &root],
        )?;
        Ok(())
    }

    pub fn create_proof_buffer(ctx: Context<CreateProofBuffer>) -> Result<()> {
        let buffer = &mut ctx.accounts.buffer;
        buffer.authority = ctx.accounts.payer.key();
        buffer.filled = 0;
        buffer.payload = [0u8; PROOF_BUFFER_SIZE];
        Ok(())
    }

    pub fn write_proof_buffer(ctx: Context<WriteProofBuffer>, offset: u32, data: Vec<u8>) -> Result<()> {
        let buffer = &mut ctx.accounts.buffer;
        let start = offset as usize;
        let end = start
            .checked_add(data.len())
            .ok_or(LacunaError::BadBuffer)?;
        require!(end <= PROOF_BUFFER_SIZE, LacunaError::BadBuffer);
        buffer.payload[start..end].copy_from_slice(&data);
        buffer.filled = buffer.filled.max(end as u32);
        Ok(())
    }

    pub fn create_cipher_buffer(ctx: Context<CreateCipherBuffer>, _slot: u8) -> Result<()> {
        let buffer = &mut ctx.accounts.buffer;
        buffer.authority = ctx.accounts.payer.key();
        buffer.filled = 0;
        buffer.payload = [0u8; MAX_CIPHERTEXT];
        Ok(())
    }

    pub fn write_cipher_buffer(ctx: Context<WriteCipherBuffer>, offset: u32, data: Vec<u8>) -> Result<()> {
        let buffer = &mut ctx.accounts.buffer;
        let start = offset as usize;
        let end = start
            .checked_add(data.len())
            .ok_or(LacunaError::BadBuffer)?;
        require!(end <= MAX_CIPHERTEXT, LacunaError::CiphertextTooLarge);
        buffer.payload[start..end].copy_from_slice(&data);
        buffer.filled = if start == 0 {
            end as u32
        } else {
            buffer.filled.max(end as u32)
        };
        Ok(())
    }

    pub fn close_proof_buffer(_ctx: Context<CloseProofBuffer>) -> Result<()> {
        Ok(())
    }

    pub fn close_cipher_buffer(_ctx: Context<CloseCipherBuffer>) -> Result<()> {
        Ok(())
    }

    pub fn set_shield_fee_bps(ctx: Context<Admin>, bps: u16) -> Result<()> {
        require!(ctx.accounts.payer.key() == ctx.accounts.config.owner, LacunaError::NotOwner);
        require!(bps <= MAX_FEE_BPS, LacunaError::BadFee);
        ctx.accounts.config.shield_fee_bps = bps;
        Ok(())
    }

    pub fn set_unshield_fee_bps(ctx: Context<Admin>, bps: u16) -> Result<()> {
        require!(ctx.accounts.payer.key() == ctx.accounts.config.owner, LacunaError::NotOwner);
        require!(bps <= MAX_FEE_BPS, LacunaError::BadFee);
        ctx.accounts.config.unshield_fee_bps = bps;
        Ok(())
    }

    pub fn set_swap_fee_bps(ctx: Context<Admin>, bps: u16) -> Result<()> {
        require!(ctx.accounts.payer.key() == ctx.accounts.config.owner, LacunaError::NotOwner);
        require!(bps <= MAX_FEE_BPS, LacunaError::BadFee);
        ctx.accounts.config.swap_fee_bps = bps;
        Ok(())
    }

    pub fn set_swap_program(ctx: Context<Admin>, hop: Pubkey) -> Result<()> {
        require!(ctx.accounts.payer.key() == ctx.accounts.config.owner, LacunaError::NotOwner);
        require!(hop != Pubkey::default() && hop != crate::ID, LacunaError::BadSwapProgram);
        ctx.accounts.config.swap_program = hop;
        Ok(())
    }

    pub fn set_refund_delay_slots(ctx: Context<Admin>, slots: u64) -> Result<()> {
        require!(ctx.accounts.payer.key() == ctx.accounts.config.owner, LacunaError::NotOwner);
        require!(
            slots >= MIN_REFUND_DELAY_SLOTS && slots <= MAX_REFUND_DELAY_SLOTS,
            LacunaError::BadValue
        );
        ctx.accounts.config.refund_delay_slots = slots;
        Ok(())
    }

    pub fn set_paused(
        ctx: Context<Admin>,
        deposits: bool,
        private_sends: bool,
        swaps: bool,
    ) -> Result<()> {
        require!(ctx.accounts.payer.key() == ctx.accounts.config.owner, LacunaError::NotOwner);
        ctx.accounts.config.paused_deposits = deposits;
        ctx.accounts.config.paused_private = private_sends;
        ctx.accounts.config.paused_swaps = swaps;
        Ok(())
    }

    pub fn pause_exits(ctx: Context<Admin>, seconds: i64) -> Result<()> {
        require!(ctx.accounts.payer.key() == ctx.accounts.config.owner, LacunaError::NotOwner);
        require!(seconds > 0 && seconds <= MAX_EXIT_PAUSE_SECS, LacunaError::BadValue);
        let now = Clock::get()?.unix_timestamp;
        let config = &mut ctx.accounts.config;
        if config.last_exit_pause != 0 {
            require!(
                now >= config
                    .last_exit_pause
                    .saturating_add(EXIT_PAUSE_COOLDOWN_SECS),
                LacunaError::Paused
            );
        }
        config.exit_pause_until = now.saturating_add(seconds);
        config.last_exit_pause = now;
        Ok(())
    }

    pub fn shield_sol(
        ctx: Context<ShieldSol>,
        owner_hash: [u8; 32],
        lamports: u64,
        expected_index: u64,
    ) -> Result<()> {
        require!(!ctx.accounts.config.paused_deposits, LacunaError::Paused);
        require!(lamports > 0, LacunaError::BadValue);
        require!(
            ctx.accounts.tree.next_index == expected_index,
            LacunaError::StaleTree
        );
        let fee = fee_of(lamports as u128, ctx.accounts.config.shield_fee_bps)? as u64;
        let net = lamports - fee;
        let source = ctx.accounts.source.to_account_info();
        require!(*source.owner == system_program::ID, LacunaError::BadValue);
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: source,
                    to: ctx.accounts.vault.to_account_info(),
                },
            ),
            lamports,
        )?;
        insert_shield(
            ctx.program_id,
            &ctx.accounts.payer.to_account_info(),
            &mut ctx.accounts.config,
            &mut ctx.accounts.tree,
            &mut ctx.accounts.token_state,
            &ctx.accounts.commitment.to_account_info(),
            &ctx.accounts.root.to_account_info(),
            &ctx.accounts.note.to_account_info(),
            native_token_id(),
            Pubkey::default(),
            true,
            false,
            owner_hash,
            net as u128,
            cipher(&ctx.accounts.ciphertext),
        )?;
        ctx.accounts.token_state.fee_balance = ctx
            .accounts
            .token_state
            .fee_balance
            .checked_add(fee as u128)
            .ok_or(LacunaError::BadValue)?;
        emit!(Shielded {
            from: ctx.accounts.payer.key(),
            mint: Pubkey::default(),
            gross: lamports as u128,
            fee: fee as u128,
        });
        Ok(())
    }

    pub fn shield_spl(
        ctx: Context<ShieldSpl>,
        owner_hash: [u8; 32],
        amount: u64,
        token_id: [u8; 32],
        expected_index: u64,
    ) -> Result<()> {
        require!(!ctx.accounts.config.paused_deposits, LacunaError::Paused);
        require!(amount > 0, LacunaError::BadValue);
        require!(
            ctx.accounts.tree.next_index == expected_index,
            LacunaError::StaleTree
        );
        require!(token_id == mint_field(&ctx.accounts.mint.key())?, LacunaError::BadValue);
        assert_mint_safe(&ctx.accounts.mint)?;
        let before = ctx.accounts.vault_ata.amount;
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.payer_ata.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.vault_ata.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;
        ctx.accounts.vault_ata.reload()?;
        let received = ctx
            .accounts
            .vault_ata
            .amount
            .checked_sub(before)
            .ok_or(LacunaError::BadValue)?;
        require!(received > 0, LacunaError::FeeOnTransfer);
        let fee = fee_of(received as u128, ctx.accounts.config.shield_fee_bps)?;
        let net = received as u128 - fee;
        insert_shield(
            ctx.program_id,
            &ctx.accounts.payer.to_account_info(),
            &mut ctx.accounts.config,
            &mut ctx.accounts.tree,
            &mut ctx.accounts.token_state,
            &ctx.accounts.commitment.to_account_info(),
            &ctx.accounts.root.to_account_info(),
            &ctx.accounts.note.to_account_info(),
            token_id,
            ctx.accounts.mint.key(),
            false,
            false,
            owner_hash,
            net,
            cipher(&ctx.accounts.ciphertext),
        )?;
        ctx.accounts.token_state.fee_balance = ctx
            .accounts
            .token_state
            .fee_balance
            .checked_add(fee)
            .ok_or(LacunaError::BadValue)?;
        emit!(Shielded {
            from: ctx.accounts.payer.key(),
            mint: ctx.accounts.mint.key(),
            gross: received as u128,
            fee,
        });
        Ok(())
    }

    pub fn shield_nft(
        ctx: Context<ShieldSpl>,
        owner_hash: [u8; 32],
        amount: u64,
        token_id: [u8; 32],
        expected_index: u64,
    ) -> Result<()> {
        require!(!ctx.accounts.config.paused_deposits, LacunaError::Paused);
        require!(
            ctx.accounts.tree.next_index == expected_index,
            LacunaError::StaleTree
        );
        require!(amount == 1, LacunaError::BadValue);
        require!(ctx.accounts.mint.decimals == 0, LacunaError::BadValue);
        assert_mint_safe(&ctx.accounts.mint)?;
        require!(ctx.accounts.mint.supply == 1, LacunaError::BadValue);
        require!(token_id == mint_field(&ctx.accounts.mint.key())?, LacunaError::BadValue);
        let before = ctx.accounts.vault_ata.amount;
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.payer_ata.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.vault_ata.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            1,
            ctx.accounts.mint.decimals,
        )?;
        ctx.accounts.vault_ata.reload()?;
        require!(
            ctx.accounts.vault_ata.amount.checked_sub(before) == Some(1),
            LacunaError::FeeOnTransfer
        );
        insert_shield(
            ctx.program_id,
            &ctx.accounts.payer.to_account_info(),
            &mut ctx.accounts.config,
            &mut ctx.accounts.tree,
            &mut ctx.accounts.token_state,
            &ctx.accounts.commitment.to_account_info(),
            &ctx.accounts.root.to_account_info(),
            &ctx.accounts.note.to_account_info(),
            token_id,
            ctx.accounts.mint.key(),
            false,
            true,
            owner_hash,
            1,
            cipher(&ctx.accounts.ciphertext),
        )?;
        emit!(Shielded {
            from: ctx.accounts.payer.key(),
            mint: ctx.accounts.mint.key(),
            gross: 1,
            fee: 0,
        });
        Ok(())
    }

    pub fn withdraw_fees(ctx: Context<WithdrawFees>) -> Result<()> {
        require!(
            ctx.accounts.payer.key() == ctx.accounts.config.treasury,
            LacunaError::NotTreasury
        );
        let amount = ctx.accounts.token_state.fee_balance;
        require!(amount > 0, LacunaError::BadValue);
        ctx.accounts.token_state.fee_balance = 0;
        pay(
            &ctx.accounts.config,
            &ctx.accounts.token_state,
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.destination.to_account_info(),
            &ctx.accounts.vault_ata,
            &ctx.accounts.destination_ata,
            &ctx.accounts.mint,
            &ctx.accounts.token_program,
            amount,
        )?;
        Ok(())
    }

    pub fn transact(mut ctx: Context<Transact>, expected_index: u64) -> Result<()> {
        run_transact(&mut ctx.accounts, ctx.program_id, expected_index, false)?;
        Ok(())
    }

    pub fn swap_prepare(
        ctx: Context<SwapPrepare>,
        expected_index: u64,
        min_out: u64,
        out_owner_hash: [u8; 32],
        refund_owner_hash: [u8; 32],
        nullifier0: [u8; 32],
        out_cipher_hash: [u8; 32],
        refund_cipher_hash: [u8; 32],
    ) -> Result<()> {
        require!(
            ctx.accounts.payer.key() == ctx.accounts.transact.payer.key(),
            LacunaError::BadValue
        );
        require!(!ctx.accounts.transact.config.paused_swaps, LacunaError::Paused);
        require!(min_out > 0, LacunaError::BadValue);
        require!(!is_zero(&out_owner_hash) && lt_field(&out_owner_hash), LacunaError::BadValue);
        require!(!is_zero(&refund_owner_hash) && lt_field(&refund_owner_hash), LacunaError::BadValue);
        require!(!is_zero(&out_cipher_hash), LacunaError::BadValue);
        require!(!is_zero(&refund_cipher_hash), LacunaError::BadValue);
        require!(
            ctx.accounts.hop_program.key() == ctx.accounts.transact.config.swap_program
                && ctx.accounts.transact.config.swap_program != Pubkey::default()
                && ctx.accounts.hop_program.key() != crate::ID,
            LacunaError::BadSwapProgram
        );
        require!(
            ctx.accounts
                .transact
                .recipient_ata0
                .as_ref()
                .map(|account| account.key())
                == Some(ctx.accounts.escrow_ata.key()),
            LacunaError::BadSwap
        );
        assert_mint_safe(&ctx.accounts.mint_in)?;
        assert_mint_safe(&ctx.accounts.mint_out)?;
        assert_mint_no_transfer_fee(&ctx.accounts.mint_in)?;
        assert_mint_no_transfer_fee(&ctx.accounts.mint_out)?;
        require!(ctx.accounts.escrow_ata.amount == 0, LacunaError::BadSwap);
        let signals = run_transact(
            &mut ctx.accounts.transact,
            ctx.program_id,
            expected_index,
            true,
        )?;
        require!(signals.nullifier0 == nullifier0, LacunaError::BadValue);
        require!(
            pubkey_field(&ctx.accounts.escrow.key()) == signals.recipient,
            LacunaError::BadSwap
        );
        let expected = swap_commitment(
            &ctx.accounts.hop_program.key(),
            &ctx.accounts.mint_out.key(),
            min_out,
            &out_owner_hash,
            &refund_owner_hash,
            &out_cipher_hash,
            &refund_cipher_hash,
        );
        require!(signals.external == expected, LacunaError::BadProof);
        let amount_in: u64 = field_u128(&signals.amount0)?
            .try_into()
            .map_err(|_| LacunaError::BadValue)?;
        require!(amount_in > 0 && is_zero(&signals.token1), LacunaError::BadSwap);
        let token_in = signals.token0;
        let token_out = mint_field(&ctx.accounts.mint_out.key())?;
        let token_state_in = ctx
            .accounts
            .transact
            .token_state0
            .as_ref()
            .ok_or(LacunaError::BadValue)?;
        require!(
            !token_state_in.is_native && !token_state_in.is_nft,
            LacunaError::BadSwap
        );
        require!(
            token_state_in.mint == ctx.accounts.mint_in.key(),
            LacunaError::BadSwap
        );
        let mint_in = token_state_in.mint;
        require!(mint_in != ctx.accounts.mint_out.key(), LacunaError::BadSwap);
        ctx.accounts.escrow_ata.reload()?;
        let received = ctx.accounts.escrow_ata.amount;
        require!(received > 0, LacunaError::BadSwap);
        let escrow = &mut ctx.accounts.escrow;
        escrow.bump = ctx.bumps.escrow;
        escrow.mint_in = mint_in;
        escrow.mint_out = ctx.accounts.mint_out.key();
        escrow.hop = ctx.accounts.hop_program.key();
        escrow.amount_in = received;
        escrow.min_out = min_out;
        escrow.owner_hash = refund_owner_hash;
        escrow.out_owner_hash = out_owner_hash;
        escrow.token_in = token_in;
        escrow.token_out = token_out;
        escrow.nullifier0 = nullifier0;
        escrow.preparer = ctx.accounts.payer.key();
        escrow.prepared_slot = Clock::get()?.slot;
        escrow.out_cipher_hash = out_cipher_hash;
        escrow.refund_cipher_hash = refund_cipher_hash;
        Ok(())
    }

    pub fn swap_execute<'info>(
        ctx: Context<'_, '_, '_, 'info, SwapExecute<'info>>,
        expected_index: u64,
        hop_data: Vec<u8>,
    ) -> Result<()> {
        require!(!ctx.accounts.config.paused_swaps, LacunaError::Paused);
        require!(
            ctx.accounts.tree.next_index == expected_index,
            LacunaError::StaleTree
        );
        let escrow = &ctx.accounts.escrow;
        require!(
            ctx.accounts.hop_program.key() == escrow.hop
                && escrow.hop == ctx.accounts.config.swap_program
                && escrow.hop != crate::ID,
            LacunaError::BadSwap
        );
        require!(ctx.accounts.mint_out.key() == escrow.mint_out, LacunaError::BadSwap);
        require!(ctx.accounts.mint_in.key() == escrow.mint_in, LacunaError::BadSwap);
        require!(
            ctx.accounts.escrow_ata.owner == escrow.key()
                && ctx.accounts.escrow_ata.mint == escrow.mint_in,
            LacunaError::BadSwap
        );
        require!(
            ctx.accounts.vault_ata_out.owner == ctx.accounts.config.vault
                && ctx.accounts.vault_ata_out.mint == escrow.mint_out,
            LacunaError::BadSwap
        );
        require!(
            ctx.accounts.vault_ata_in.owner == ctx.accounts.config.vault
                && ctx.accounts.vault_ata_in.mint == escrow.mint_in,
            LacunaError::BadSwap
        );
        require!(hop_data.len() >= 8, LacunaError::BadSwap);
        reject_extra_escrow_token_accounts(
            ctx.remaining_accounts,
            &ctx.accounts.escrow.key(),
            &ctx.accounts.escrow_ata.key(),
        )?;
        let before_in = ctx.accounts.escrow_ata.amount;
        let before_out = ctx.accounts.vault_ata_out.amount;
        require!(before_in >= escrow.amount_in, LacunaError::BadSwap);

        let bump = [escrow.bump];
        let seeds: &[&[u8]] = &[SEED_ESCROW, &escrow.nullifier0, &bump];
        let remaining = ctx.remaining_accounts;
        require!(!remaining.is_empty(), LacunaError::BadSwap);
        let mut infos = Vec::with_capacity(remaining.len() + 1);
        infos.push(ctx.accounts.hop_program.to_account_info());
        infos.extend_from_slice(remaining);
        invoke_signed(
            &Instruction {
                program_id: ctx.accounts.hop_program.key(),
                accounts: hop_metas(remaining, &ctx.accounts.escrow.key()),
                data: hop_data,
            },
            &infos,
            &[seeds],
        )?;

        ctx.accounts.escrow_ata.reload()?;
        ctx.accounts.vault_ata_out.reload()?;
        let leftover = ctx.accounts.escrow_ata.amount;
        if leftover > 0 {
            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.escrow_ata.to_account_info(),
                        mint: ctx.accounts.mint_in.to_account_info(),
                        to: ctx.accounts.vault_ata_in.to_account_info(),
                        authority: ctx.accounts.escrow.to_account_info(),
                    },
                    &[seeds],
                ),
                leftover,
                ctx.accounts.mint_in.decimals,
            )?;
            ctx.accounts.escrow_ata.reload()?;
        }
        require!(ctx.accounts.escrow_ata.amount == 0, LacunaError::BadSwap);
        let gained = ctx
            .accounts
            .vault_ata_out
            .amount
            .checked_sub(before_out)
            .ok_or(LacunaError::BadSwap)?;
        require!(gained >= escrow.min_out, LacunaError::Slippage);
        let credited = escrow.min_out as u128;
        let fee = fee_of(credited, ctx.accounts.config.swap_fee_bps)?;
        let net = credited - fee;
        require!(net > 0, LacunaError::BadValue);
        let surplus = (gained as u128)
            .checked_sub(net)
            .ok_or(LacunaError::BadValue)?;
        require_cipher_hash(&ctx.accounts.ciphertext, &escrow.out_cipher_hash)?;
        insert_shield(
            ctx.program_id,
            &ctx.accounts.payer.to_account_info(),
            &mut ctx.accounts.config,
            &mut ctx.accounts.tree,
            &mut ctx.accounts.token_state_out,
            &ctx.accounts.commitment.to_account_info(),
            &ctx.accounts.root.to_account_info(),
            &ctx.accounts.note.to_account_info(),
            escrow.token_out,
            escrow.mint_out,
            false,
            false,
            escrow.out_owner_hash,
            net,
            cipher(&ctx.accounts.ciphertext),
        )?;
        ctx.accounts.token_state_out.fee_balance = ctx
            .accounts
            .token_state_out
            .fee_balance
            .checked_add(surplus)
            .ok_or(LacunaError::BadValue)?;
        close_escrow_ata(
            &ctx.accounts.token_program,
            &ctx.accounts.escrow_ata,
            &ctx.accounts.preparer.to_account_info(),
            &ctx.accounts.escrow.to_account_info(),
            seeds,
        )?;
        Ok(())
    }

    /// Refund stays available while swaps are paused so a parked escrow can return to a note.
    pub fn swap_refund(ctx: Context<SwapRefund>, expected_index: u64) -> Result<()> {
        require!(
            ctx.accounts.tree.next_index == expected_index,
            LacunaError::StaleTree
        );
        let escrow = &ctx.accounts.escrow;
        require!(ctx.accounts.mint_in.key() == escrow.mint_in, LacunaError::BadSwap);
        require!(
            ctx.accounts.escrow_ata.owner == escrow.key()
                && ctx.accounts.escrow_ata.mint == escrow.mint_in,
            LacunaError::BadSwap
        );
        require!(
            ctx.accounts.vault_ata.owner == ctx.accounts.config.vault
                && ctx.accounts.vault_ata.mint == escrow.mint_in,
            LacunaError::BadSwap
        );
        let slot = Clock::get()?.slot;
        if slot <= escrow.prepared_slot.saturating_add(ctx.accounts.config.refund_delay_slots) {
            require!(
                ctx.accounts.payer.key() == escrow.preparer,
                LacunaError::BadSwap
            );
        }
        let leftover = ctx.accounts.escrow_ata.amount;
        require!(leftover > 0, LacunaError::BadValue);
        let bump = [escrow.bump];
        let seeds: &[&[u8]] = &[SEED_ESCROW, &escrow.nullifier0, &bump];
        let before_vault = ctx.accounts.vault_ata.amount;
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.escrow_ata.to_account_info(),
                    mint: ctx.accounts.mint_in.to_account_info(),
                    to: ctx.accounts.vault_ata.to_account_info(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                &[seeds],
            ),
            leftover,
            ctx.accounts.mint_in.decimals,
        )?;
        ctx.accounts.vault_ata.reload()?;
        let received = ctx
            .accounts
            .vault_ata
            .amount
            .checked_sub(before_vault)
            .ok_or(LacunaError::BadSwap)?;
        require!(received > 0, LacunaError::FeeOnTransfer);
        let fee = fee_of(received as u128, ctx.accounts.config.swap_fee_bps)?;
        let net = received as u128 - fee;
        require!(net > 0, LacunaError::BadValue);
        require_cipher_hash(&ctx.accounts.ciphertext, &escrow.refund_cipher_hash)?;
        insert_shield(
            ctx.program_id,
            &ctx.accounts.payer.to_account_info(),
            &mut ctx.accounts.config,
            &mut ctx.accounts.tree,
            &mut ctx.accounts.token_state,
            &ctx.accounts.commitment.to_account_info(),
            &ctx.accounts.root.to_account_info(),
            &ctx.accounts.note.to_account_info(),
            escrow.token_in,
            escrow.mint_in,
            false,
            false,
            escrow.owner_hash,
            net,
            cipher(&ctx.accounts.ciphertext),
        )?;
        ctx.accounts.token_state.fee_balance = ctx
            .accounts
            .token_state
            .fee_balance
            .checked_add(fee)
            .ok_or(LacunaError::BadValue)?;
        close_escrow_ata(
            &ctx.accounts.token_program,
            &ctx.accounts.escrow_ata,
            &ctx.accounts.preparer.to_account_info(),
            &ctx.accounts.escrow.to_account_info(),
            seeds,
        )?;
        Ok(())
    }
}

fn cipher<'a>(buffer: &'a Account<CipherBuffer>) -> &'a [u8] {
    &buffer.payload[..buffer.filled as usize]
}

fn require_cipher_hash(buffer: &Account<CipherBuffer>, expected: &[u8; 32]) -> Result<()> {
    let data = cipher(buffer);
    require!(!data.is_empty(), LacunaError::BadProof);
    require!(cipher_hash(data) == *expected, LacunaError::BadProof);
    Ok(())
}

/// Only inspects remaining accounts present at the start of the hop. An allowlisted
/// hop that creates a new escrow-owned ATA mid-CPI is not visible here; keep `min_out`
/// tight so that hop cannot siphon value.
fn reject_extra_escrow_token_accounts(
    remaining: &[AccountInfo],
    escrow: &Pubkey,
    escrow_ata: &Pubkey,
) -> Result<()> {
    for account in remaining {
        if account.key == escrow_ata {
            continue;
        }
        let owner = account.owner;
        if owner != &anchor_spl::token::ID && owner != &anchor_spl::token_2022::ID {
            continue;
        }
        let data = account.try_borrow_data()?;
        if data.len() < 64 {
            continue;
        }
        let token_owner = Pubkey::try_from(&data[32..64]).map_err(|_| LacunaError::BadSwap)?;
        require!(token_owner != *escrow, LacunaError::BadSwap);
    }
    Ok(())
}

fn hop_metas(accounts: &[AccountInfo], extra_signer: &Pubkey) -> Vec<AccountMeta> {
    accounts
        .iter()
        .map(|account| {
            let signer = account.is_signer || account.key == extra_signer;
            if account.is_writable {
                AccountMeta::new(*account.key, signer)
            } else {
                AccountMeta::new_readonly(*account.key, signer)
            }
        })
        .collect()
}

fn exits_open(config: &Config) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    require!(now >= config.exit_pause_until, LacunaError::Paused);
    Ok(())
}

struct TransactSignals {
    nullifier0: [u8; 32],
    recipient: [u8; 32],
    amount0: [u8; 32],
    token0: [u8; 32],
    token1: [u8; 32],
    external: [u8; 32],
}

fn run_transact(
    accounts: &mut Transact,
    program_id: &Pubkey,
    expected_index: u64,
    allow_swap: bool,
) -> Result<TransactSignals> {
    require!(
        accounts.tree.next_index == expected_index,
        LacunaError::StaleTree
    );
    require!(
        accounts.proof.filled as usize >= PROOF_BUFFER_SIZE,
        LacunaError::BadBuffer
    );
    let parsed = parse_proof(&accounts.proof.payload)?;
    require!(
        !(is_zero(&parsed.public_inputs[1]) && is_zero(&parsed.public_inputs[2])),
        LacunaError::BadValue
    );
    let amount0 = field_u128(&parsed.public_inputs[5])?;
    let amount1 = field_u128(&parsed.public_inputs[6])?;
    let relay_fee = field_u128(&parsed.public_inputs[11])?;
    let public_exit = amount0 > 0 || amount1 > 0 || relay_fee > 0;
    if allow_swap {
        require!(!accounts.config.paused_swaps, LacunaError::Paused);
        require!(public_exit, LacunaError::BadSwap);
        exits_open(&accounts.config)?;
    } else {
        require!(is_zero(&parsed.public_inputs[15]), LacunaError::BadValue);
        if public_exit {
            exits_open(&accounts.config)?;
        } else {
            require!(!accounts.config.paused_private, LacunaError::Paused);
        }
    }
    verify_proof(&parsed)?;
    let c0 = cipher(&accounts.ciphertext0);
    let c1 = cipher(&accounts.ciphertext1);
    require!(
        ciphertext_commitment(c0, c1) == parsed.public_inputs[16],
        LacunaError::BadProof
    );
    check_public(accounts, program_id, &parsed.public_inputs, allow_swap)?;
    require!(
        is_zero(&parsed.public_inputs[1]) || parsed.public_inputs[1] != parsed.public_inputs[2],
        LacunaError::DoubleSpend
    );
    spend(
        program_id,
        &accounts.payer.to_account_info(),
        &accounts.nullifier0.to_account_info(),
        &parsed.public_inputs[1],
    )?;
    spend(
        program_id,
        &accounts.payer.to_account_info(),
        &accounts.nullifier1.to_account_info(),
        &parsed.public_inputs[2],
    )?;
    insert_output(
        program_id,
        &accounts.payer.to_account_info(),
        &mut accounts.config,
        &mut accounts.tree,
        &accounts.commitment0.to_account_info(),
        &accounts.root0.to_account_info(),
        &accounts.note0.to_account_info(),
        parsed.public_inputs[3],
        0,
        c0,
    )?;
    insert_output(
        program_id,
        &accounts.payer.to_account_info(),
        &mut accounts.config,
        &mut accounts.tree,
        &accounts.commitment1.to_account_info(),
        &accounts.root1.to_account_info(),
        &accounts.note1.to_account_info(),
        parsed.public_inputs[4],
        0,
        c1,
    )?;
    exit_leg(accounts, &parsed.public_inputs, 0)?;
    exit_leg(accounts, &parsed.public_inputs, 1)?;
    Ok(TransactSignals {
        nullifier0: parsed.public_inputs[1],
        recipient: parsed.public_inputs[7],
        amount0: parsed.public_inputs[5],
        token0: parsed.public_inputs[8],
        token1: parsed.public_inputs[9],
        external: parsed.public_inputs[15],
    })
}

fn close_escrow_ata<'info>(
    token_program: &Interface<'info, TokenInterface>,
    escrow_ata: &InterfaceAccount<'info, TokenAccount>,
    payer: &AccountInfo<'info>,
    escrow: &AccountInfo<'info>,
    seeds: &[&[u8]],
) -> Result<()> {
    token_interface::close_account(
        CpiContext::new_with_signer(
            token_program.to_account_info(),
            CloseAccount {
                account: escrow_ata.to_account_info(),
                destination: payer.clone(),
                authority: escrow.clone(),
            },
            &[seeds],
        ),
    )
}


fn roll_if_needed(config: &mut Config, tree: &mut Tree) {
    if tree.next_index >= TREE_CAPACITY {
        tree.filled_subtrees = tree.zeros;
        tree.next_index = 0;
        tree.tree_number += 1;
        config.tree_number = tree.tree_number;
    }
}

fn insert_shield<'info>(
    program_id: &Pubkey,
    payer: &AccountInfo<'info>,
    config: &mut Config,
    tree: &mut Tree,
    token_state: &mut TokenState,
    commitment_ai: &AccountInfo<'info>,
    root_ai: &AccountInfo<'info>,
    note_ai: &AccountInfo<'info>,
    token_id: [u8; 32],
    mint: Pubkey,
    is_native: bool,
    is_nft: bool,
    owner_hash: [u8; 32],
    net: u128,
    ciphertext: &[u8],
) -> Result<()> {
    require!(!is_zero(&owner_hash) && lt_field(&owner_hash), LacunaError::BadValue);
    require!(net > 0, LacunaError::BadValue);
    let net_field = u128_field(net);
    let inner = merkle::hash2(&net_field, &token_id)?;
    let commitment = merkle::hash2(&inner, &owner_hash)?;
    let uninitialized = token_state.mint == Pubkey::default()
        && !token_state.is_native
        && token_state.pool_balance == 0
        && token_state.fee_balance == 0;
    if uninitialized {
        token_state.token_id = token_id;
        token_state.mint = mint;
        token_state.is_native = is_native;
        token_state.is_nft = is_nft;
    } else {
        require!(token_state.token_id == token_id, LacunaError::BadValue);
        require!(token_state.mint == mint, LacunaError::BadValue);
        require!(token_state.is_native == is_native, LacunaError::BadValue);
        require!(token_state.is_nft == is_nft, LacunaError::BadValue);
    }
    if !is_nft {
        token_state.pool_balance = token_state
            .pool_balance
            .checked_add(net)
            .ok_or(LacunaError::BadValue)?;
    }
    insert_output(
        program_id,
        payer,
        config,
        tree,
        commitment_ai,
        root_ai,
        note_ai,
        commitment,
        net,
        ciphertext,
    )
}

fn insert_output<'info>(
    program_id: &Pubkey,
    payer: &AccountInfo<'info>,
    config: &mut Config,
    tree: &mut Tree,
    commitment_ai: &AccountInfo<'info>,
    root_ai: &AccountInfo<'info>,
    note_ai: &AccountInfo<'info>,
    commitment: [u8; 32],
    recorded_net: u128,
    ciphertext: &[u8],
) -> Result<()> {
    if is_zero(&commitment) {
        return Ok(());
    }
    require!(lt_field(&commitment), LacunaError::BadValue);
    roll_if_needed(config, tree);
    let index = tree.next_index;
    let tree_number = tree.tree_number;
    pda::create_marker(program_id, payer, commitment_ai, &[SEED_COMMITMENT, &commitment])?;
    let root = merkle::insert(tree, commitment)?;
    pda::create_marker(program_id, payer, root_ai, &[SEED_ROOT, &root])?;
    pda::write_note(
        program_id,
        payer,
        note_ai,
        tree_number,
        index,
        commitment,
        recorded_net,
        ciphertext,
    )?;
    emit!(NoteEvent {
        tree_number,
        leaf_index: index,
        commitment,
    });
    Ok(())
}

fn spend<'info>(
    program_id: &Pubkey,
    payer: &AccountInfo<'info>,
    nullifier_ai: &AccountInfo<'info>,
    nullifier: &[u8; 32],
) -> Result<()> {
    if is_zero(nullifier) {
        return Ok(());
    }
    pda::create_marker(program_id, payer, nullifier_ai, &[SEED_NULLIFIER, nullifier])?;
    emit!(Nullified { nullifier: *nullifier });
    Ok(())
}

fn check_public(
    accounts: &Transact,
    program_id: &Pubkey,
    pub_inputs: &[[u8; 32]; PUBLIC_INPUTS],
    allow_swap: bool,
) -> Result<()> {
    require!(!is_zero(&pub_inputs[0]), LacunaError::BadRoot);
    require!(
        accounts.known_root.key()
            == Pubkey::find_program_address(&[SEED_ROOT, &pub_inputs[0]], program_id).0,
        LacunaError::BadRoot
    );
    if let (Some(first), Some(second)) = (&accounts.token_state0, &accounts.token_state1) {
        require!(first.key() != second.key(), LacunaError::BadValue);
    }
    if let Some(state) = accounts.token_state0.as_ref() {
        require!(
            state.key()
                == Pubkey::find_program_address(&[SEED_TOKEN, &state.token_id], program_id).0,
            LacunaError::BadValue
        );
    }
    if let Some(state) = accounts.token_state1.as_ref() {
        require!(
            state.key()
                == Pubkey::find_program_address(&[SEED_TOKEN, &state.token_id], program_id).0,
            LacunaError::BadValue
        );
    }
    let two = field_u128(&pub_inputs[10])?;
    require!(two <= 1, LacunaError::BadValue);
    let amount0 = field_u128(&pub_inputs[5])?;
    let amount1 = field_u128(&pub_inputs[6])?;
    let relay_fee = field_u128(&pub_inputs[11])?;
    let fee0 = field_u128(&pub_inputs[12])?;
    let fee1 = field_u128(&pub_inputs[13])?;
    if two == 0 {
        require!(
            is_zero(&pub_inputs[9]) && amount1 == 0 && fee1 == 0,
            LacunaError::BadValue
        );
    }
    if allow_swap {
        require!(
            two == 0 && amount1 == 0 && fee0 == 0 && fee1 == 0 && relay_fee == 0,
            LacunaError::BadFee
        );
    } else {
        check_unshield_fee(amount0, fee0, relay_fee, accounts.config.unshield_fee_bps)?;
        check_unshield_fee(amount1, fee1, 0, accounts.config.unshield_fee_bps)?;
    }
    if relay_fee == 0 {
        require!(is_zero(&pub_inputs[14]), LacunaError::BadValue);
    } else {
        let dest = accounts.relay_recipient.as_ref().ok_or(LacunaError::BadValue)?;
        require!(pubkey_field(dest.key) == pub_inputs[14], LacunaError::BadValue);
    }
    if !is_zero(&pub_inputs[15]) {
        require!(allow_swap, LacunaError::BadValue);
    }
    if amount0 == 0 && amount1 == 0 {
        require!(is_zero(&pub_inputs[7]), LacunaError::BadValue);
    } else {
        let dest = accounts.recipient.as_ref().ok_or(LacunaError::BadValue)?;
        require!(pubkey_field(dest.key) == pub_inputs[7], LacunaError::BadValue);
    }
    Ok(())
}

fn exit_leg(accounts: &mut Transact, pub_inputs: &[[u8; 32]; PUBLIC_INPUTS], leg: usize) -> Result<()> {
    let token = pub_inputs[if leg == 0 { 8 } else { 9 }];
    let amount = field_u128(&pub_inputs[if leg == 0 { 5 } else { 6 }])?;
    let fee = field_u128(&pub_inputs[if leg == 0 { 12 } else { 13 }])?;
    let relay_fee = if leg == 0 {
        field_u128(&pub_inputs[11])?
    } else {
        0
    };
    if amount == 0 && fee == 0 && relay_fee == 0 {
        return Ok(());
    }
    let token_state = if leg == 0 {
        accounts.token_state0.as_mut().ok_or(LacunaError::BadValue)?
    } else {
        accounts.token_state1.as_mut().ok_or(LacunaError::BadValue)?
    };
    require!(token_state.token_id == token, LacunaError::BadValue);
    if token_state.is_nft {
        require!(relay_fee == 0 && amount == 1 && fee == 0, LacunaError::BadValue);
        pay(
            &accounts.config,
            token_state,
            &accounts.vault.to_account_info(),
            accounts.recipient.as_ref().ok_or(LacunaError::BadValue)?,
            if leg == 0 {
                &accounts.vault_ata0
            } else {
                &accounts.vault_ata1
            },
            if leg == 0 {
                &accounts.recipient_ata0
            } else {
                &accounts.recipient_ata1
            },
            if leg == 0 {
                &accounts.mint0
            } else {
                &accounts.mint1
            },
            &accounts.token_program,
            1,
        )?;
        emit!(PublicExit {
            mint: token_state.mint,
            to: accounts.recipient.as_ref().unwrap().key(),
            amount: 1,
            protocol_fee: 0,
            relay_fee: 0,
        });
        return Ok(());
    }
    let payout = amount
        .checked_add(fee)
        .and_then(|v| v.checked_add(relay_fee))
        .ok_or(LacunaError::BadValue)?;
    require!(token_state.pool_balance >= payout, LacunaError::BadValue);
    token_state.pool_balance -= payout;
    token_state.fee_balance = token_state
        .fee_balance
        .checked_add(fee)
        .ok_or(LacunaError::BadValue)?;
    if relay_fee > 0 {
        let tip_to = accounts.relay_recipient.as_ref().ok_or(LacunaError::BadValue)?;
        pay(
            &accounts.config,
            token_state,
            &accounts.vault.to_account_info(),
            tip_to,
            &accounts.vault_ata0,
            &accounts.relay_ata,
            &accounts.mint0,
            &accounts.token_program,
            relay_fee,
        )?;
    }
    let paid_to = if amount > 0 {
        let recipient = accounts.recipient.as_ref().ok_or(LacunaError::BadValue)?;
        pay(
            &accounts.config,
            token_state,
            &accounts.vault.to_account_info(),
            recipient,
            if leg == 0 {
                &accounts.vault_ata0
            } else {
                &accounts.vault_ata1
            },
            if leg == 0 {
                &accounts.recipient_ata0
            } else {
                &accounts.recipient_ata1
            },
            if leg == 0 {
                &accounts.mint0
            } else {
                &accounts.mint1
            },
            &accounts.token_program,
            amount,
        )?;
        recipient.key()
    } else {
        accounts
            .relay_recipient
            .as_ref()
            .map(|account| account.key())
            .unwrap_or_default()
    };
    emit!(PublicExit {
        mint: token_state.mint,
        to: paid_to,
        amount,
        protocol_fee: fee,
        relay_fee,
    });
    Ok(())
}

fn pay<'info>(
    config: &Config,
    token_state: &TokenState,
    vault: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    vault_ata: &Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    destination_ata: &Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    mint: &Option<Box<InterfaceAccount<'info, Mint>>>,
    token_program: &Option<Interface<'info, TokenInterface>>,
    amount: u128,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let amount_u64: u64 = amount.try_into().map_err(|_| LacunaError::BadValue)?;
    if token_state.is_native {
        **vault.try_borrow_mut_lamports()? = vault
            .lamports()
            .checked_sub(amount_u64)
            .ok_or(LacunaError::BadValue)?;
        **destination.try_borrow_mut_lamports()? = destination
            .lamports()
            .checked_add(amount_u64)
            .ok_or(LacunaError::BadValue)?;
        return Ok(());
    }
    let vault_ata = vault_ata.as_ref().ok_or(LacunaError::BadValue)?;
    let destination_ata = destination_ata.as_ref().ok_or(LacunaError::BadValue)?;
    let mint = mint.as_ref().ok_or(LacunaError::BadValue)?;
    let token_program = token_program.as_ref().ok_or(LacunaError::BadValue)?;
    require!(mint.key() == token_state.mint, LacunaError::BadValue);
    require!(vault_ata.mint == token_state.mint, LacunaError::BadValue);
    require!(vault_ata.owner == config.vault, LacunaError::BadValue);
    require!(destination_ata.mint == token_state.mint, LacunaError::BadValue);
    require!(destination_ata.owner == destination.key(), LacunaError::BadValue);
    let bump = [config.vault_bump];
    let seeds: &[&[u8]] = &[SEED_VAULT, &bump];
    token_interface::transfer_checked(
        CpiContext::new_with_signer(
            token_program.to_account_info(),
            TransferChecked {
                from: vault_ata.to_account_info(),
                mint: mint.to_account_info(),
                to: destination_ata.to_account_info(),
                authority: vault.clone(),
            },
            &[seeds],
        ),
        amount_u64,
        mint.decimals,
    )
}

#[event]
pub struct NoteEvent {
    pub tree_number: u64,
    pub leaf_index: u64,
    pub commitment: [u8; 32],
}

#[event]
pub struct Nullified {
    pub nullifier: [u8; 32],
}

#[event]
pub struct Shielded {
    pub from: Pubkey,
    pub mint: Pubkey,
    pub gross: u128,
    pub fee: u128,
}

#[event]
pub struct PublicExit {
    pub mint: Pubkey,
    pub to: Pubkey,
    pub amount: u128,
    pub protocol_fee: u128,
    pub relay_fee: u128,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = Config::SIZE,
        seeds = [SEED_CONFIG],
        bump
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(
        init,
        payer = payer,
        space = Marker::SIZE,
        seeds = [SEED_VAULT],
        bump
    )]
    pub vault: Account<'info, Marker>,
    #[account(
        init,
        payer = payer,
        space = Tree::SIZE,
        seeds = [SEED_TREE],
        bump
    )]
    pub tree: Box<Account<'info, Tree>>,
    /// CHECK: empty-root marker, created in handler
    #[account(mut)]
    pub empty_root: UncheckedAccount<'info>,
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::ID
    )]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseProofBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, close = payer, constraint = buffer.authority == payer.key() @ LacunaError::BadValue)]
    pub buffer: Box<Account<'info, ProofBuffer>>,
}

#[derive(Accounts)]
pub struct CloseCipherBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, close = payer, constraint = buffer.authority == payer.key() @ LacunaError::BadValue)]
    pub buffer: Box<Account<'info, CipherBuffer>>,
}

#[derive(Accounts)]
pub struct CreateProofBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = ProofBuffer::SIZE,
        seeds = [SEED_BUFFER, b"proof", payer.key().as_ref()],
        bump
    )]
    pub buffer: Box<Account<'info, ProofBuffer>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WriteProofBuffer<'info> {
    pub payer: Signer<'info>,
    #[account(mut, constraint = buffer.authority == payer.key() @ LacunaError::BadValue)]
    pub buffer: Box<Account<'info, ProofBuffer>>,
}

#[derive(Accounts)]
#[instruction(slot: u8)]
pub struct CreateCipherBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = CipherBuffer::SIZE,
        seeds = [SEED_BUFFER, b"cipher", payer.key().as_ref(), &[slot]],
        bump
    )]
    pub buffer: Box<Account<'info, CipherBuffer>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WriteCipherBuffer<'info> {
    pub payer: Signer<'info>,
    #[account(mut, constraint = buffer.authority == payer.key() @ LacunaError::BadValue)]
    pub buffer: Box<Account<'info, CipherBuffer>>,
}

#[derive(Accounts)]
pub struct Admin<'info> {
    pub payer: Signer<'info>,
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
}

#[derive(Accounts)]
pub struct ShieldSol<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// SOL source: the user wallet that pays the shield.
    #[account(mut)]
    pub source: Signer<'info>,
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: vault
    #[account(mut, seeds = [SEED_VAULT], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [SEED_TREE], bump)]
    pub tree: Box<Account<'info, Tree>>,
    #[account(
        init_if_needed,
        payer = payer,
        space = TokenState::SIZE,
        seeds = [SEED_TOKEN, &native_token_id()],
        bump
    )]
    pub token_state: Box<Account<'info, TokenState>>,
    pub ciphertext: Box<Account<'info, CipherBuffer>>,
    /// CHECK: commitment marker
    #[account(mut)]
    pub commitment: UncheckedAccount<'info>,
    /// CHECK: root marker
    #[account(mut)]
    pub root: UncheckedAccount<'info>,
    /// CHECK: note record
    #[account(mut)]
    pub note: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(owner_hash: [u8; 32], amount: u64, token_id: [u8; 32])]
pub struct ShieldSpl<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: vault
    #[account(mut, seeds = [SEED_VAULT], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [SEED_TREE], bump)]
    pub tree: Box<Account<'info, Tree>>,
    pub authority: Signer<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(
        mut,
        token::mint = mint,
        token::authority = authority
    )]
    pub payer_ata: InterfaceAccount<'info, TokenAccount>,
    #[account(
        mut,
        token::mint = mint,
        token::authority = vault
    )]
    pub vault_ata: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = payer,
        space = TokenState::SIZE,
        seeds = [SEED_TOKEN, token_id.as_ref()],
        bump
    )]
    pub token_state: Box<Account<'info, TokenState>>,
    pub ciphertext: Box<Account<'info, CipherBuffer>>,
    /// CHECK: commitment marker
    #[account(mut)]
    pub commitment: UncheckedAccount<'info>,
    /// CHECK: root marker
    #[account(mut)]
    pub root: UncheckedAccount<'info>,
    /// CHECK: note record
    #[account(mut)]
    pub note: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawFees<'info> {
    pub payer: Signer<'info>,
    #[account(seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: vault
    #[account(mut, seeds = [SEED_VAULT], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [SEED_TOKEN, token_state.token_id.as_ref()], bump)]
    pub token_state: Box<Account<'info, TokenState>>,
    /// CHECK: treasury destination
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    pub mint: Option<Box<InterfaceAccount<'info, Mint>>>,
    #[account(mut)]
    pub vault_ata: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    #[account(mut)]
    pub destination_ata: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    pub token_program: Option<Interface<'info, TokenInterface>>,
}

#[derive(Accounts)]
pub struct Transact<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: vault
    #[account(mut, seeds = [SEED_VAULT], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [SEED_TREE], bump)]
    pub tree: Box<Account<'info, Tree>>,
    pub proof: Box<Account<'info, ProofBuffer>>,
    pub ciphertext0: Box<Account<'info, CipherBuffer>>,
    pub ciphertext1: Box<Account<'info, CipherBuffer>>,
    pub known_root: Account<'info, Marker>,
    /// CHECK: nullifier 0
    #[account(mut)]
    pub nullifier0: UncheckedAccount<'info>,
    /// CHECK: nullifier 1
    #[account(mut)]
    pub nullifier1: UncheckedAccount<'info>,
    /// CHECK: commitment 0
    #[account(mut)]
    pub commitment0: UncheckedAccount<'info>,
    /// CHECK: commitment 1
    #[account(mut)]
    pub commitment1: UncheckedAccount<'info>,
    /// CHECK: new root 0
    #[account(mut)]
    pub root0: UncheckedAccount<'info>,
    /// CHECK: new root 1
    #[account(mut)]
    pub root1: UncheckedAccount<'info>,
    /// CHECK: note 0
    #[account(mut)]
    pub note0: UncheckedAccount<'info>,
    /// CHECK: note 1
    #[account(mut)]
    pub note1: UncheckedAccount<'info>,
    #[account(mut)]
    pub token_state0: Option<Box<Account<'info, TokenState>>>,
    #[account(mut)]
    pub token_state1: Option<Box<Account<'info, TokenState>>>,
    /// CHECK: public recipient
    #[account(mut)]
    pub recipient: Option<UncheckedAccount<'info>>,
    /// CHECK: tip recipient
    #[account(mut)]
    pub relay_recipient: Option<UncheckedAccount<'info>>,
    pub mint0: Option<Box<InterfaceAccount<'info, Mint>>>,
    pub mint1: Option<Box<InterfaceAccount<'info, Mint>>>,
    #[account(mut)]
    pub vault_ata0: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    #[account(mut)]
    pub vault_ata1: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    #[account(mut)]
    pub recipient_ata0: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    #[account(mut)]
    pub recipient_ata1: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    #[account(mut)]
    pub relay_ata: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
    pub token_program: Option<Interface<'info, TokenInterface>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(
    expected_index: u64,
    min_out: u64,
    out_owner_hash: [u8; 32],
    refund_owner_hash: [u8; 32],
    nullifier0: [u8; 32],
    out_cipher_hash: [u8; 32],
    refund_cipher_hash: [u8; 32]
)]
pub struct SwapPrepare<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = SwapEscrow::SIZE,
        seeds = [SEED_ESCROW, nullifier0.as_ref()],
        bump
    )]
    pub escrow: Box<Account<'info, SwapEscrow>>,
    pub mint_in: Box<InterfaceAccount<'info, Mint>>,
    pub mint_out: Box<InterfaceAccount<'info, Mint>>,
    /// CHECK: allowlisted hop program
    pub hop_program: UncheckedAccount<'info>,
    #[account(
        mut,
        associated_token::mint = mint_in,
        associated_token::authority = escrow,
        associated_token::token_program = token_program
    )]
    pub escrow_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub transact: Transact<'info>,
}

#[derive(Accounts)]
pub struct SwapExecute<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: vault
    #[account(mut, seeds = [SEED_VAULT], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [SEED_TREE], bump)]
    pub tree: Box<Account<'info, Tree>>,
    /// CHECK: original preparer receives escrow and ATA rent
    #[account(mut)]
    pub preparer: UncheckedAccount<'info>,
    #[account(
        mut,
        close = preparer,
        constraint = escrow.preparer == preparer.key() @ LacunaError::BadSwap,
        seeds = [SEED_ESCROW, escrow.nullifier0.as_ref()],
        bump = escrow.bump
    )]
    pub escrow: Box<Account<'info, SwapEscrow>>,
    pub mint_in: Box<InterfaceAccount<'info, Mint>>,
    pub mint_out: Box<InterfaceAccount<'info, Mint>>,
    #[account(
        mut,
        associated_token::mint = mint_in,
        associated_token::authority = escrow,
        associated_token::token_program = token_program
    )]
    pub escrow_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut)]
    pub vault_ata_in: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut)]
    pub vault_ata_out: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: allowlisted hop
    pub hop_program: UncheckedAccount<'info>,
    pub ciphertext: Box<Account<'info, CipherBuffer>>,
    /// CHECK: commitment marker
    #[account(mut)]
    pub commitment: UncheckedAccount<'info>,
    /// CHECK: root marker
    #[account(mut)]
    pub root: UncheckedAccount<'info>,
    /// CHECK: note record
    #[account(mut)]
    pub note: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        space = TokenState::SIZE,
        seeds = [SEED_TOKEN, escrow.token_out.as_ref()],
        bump
    )]
    pub token_state_out: Box<Account<'info, TokenState>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SwapRefund<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: vault
    #[account(mut, seeds = [SEED_VAULT], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut, seeds = [SEED_TREE], bump)]
    pub tree: Box<Account<'info, Tree>>,
    /// CHECK: original preparer receives escrow and ATA rent
    #[account(mut)]
    pub preparer: UncheckedAccount<'info>,
    #[account(
        mut,
        close = preparer,
        constraint = escrow.preparer == preparer.key() @ LacunaError::BadSwap,
        seeds = [SEED_ESCROW, escrow.nullifier0.as_ref()],
        bump = escrow.bump
    )]
    pub escrow: Box<Account<'info, SwapEscrow>>,
    pub mint_in: Box<InterfaceAccount<'info, Mint>>,
    #[account(
        mut,
        associated_token::mint = mint_in,
        associated_token::authority = escrow,
        associated_token::token_program = token_program
    )]
    pub escrow_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut)]
    pub vault_ata: Box<InterfaceAccount<'info, TokenAccount>>,
    pub ciphertext: Box<Account<'info, CipherBuffer>>,
    /// CHECK: commitment marker
    #[account(mut)]
    pub commitment: UncheckedAccount<'info>,
    /// CHECK: root marker
    #[account(mut)]
    pub root: UncheckedAccount<'info>,
    /// CHECK: note record
    #[account(mut)]
    pub note: UncheckedAccount<'info>,
    #[account(mut, seeds = [SEED_TOKEN, escrow.token_in.as_ref()], bump)]
    pub token_state: Box<Account<'info, TokenState>>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}
