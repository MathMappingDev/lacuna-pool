use crate::constants::*;
use crate::error::LacunaError;
use crate::state::{Marker, NoteRecord};
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    program::invoke, program::invoke_signed, system_instruction, system_program,
};

pub fn create_with_space<'info>(
    program_id: &Pubkey,
    payer: &AccountInfo<'info>,
    target: &AccountInfo<'info>,
    seeds: &[&[u8]],
    space: usize,
) -> Result<u8> {
    let (expected, bump) = Pubkey::find_program_address(seeds, program_id);
    require_keys_eq!(expected, *target.key, LacunaError::BadValue);
    require!(
        target.owner == &system_program::ID && target.data_is_empty(),
        LacunaError::DoubleSpend
    );
    let rent = Rent::get()?.minimum_balance(space);
    let bump_seed = [bump];
    let mut signer: Vec<&[u8]> = seeds.to_vec();
    signer.push(&bump_seed);
    if target.lamports() == 0 {
        invoke_signed(
            &system_instruction::create_account(
                payer.key,
                target.key,
                rent,
                space as u64,
                program_id,
            ),
            &[payer.clone(), target.clone()],
            &[signer.as_slice()],
        )?;
    } else {
        if target.lamports() < rent {
            invoke(
                &system_instruction::transfer(payer.key, target.key, rent - target.lamports()),
                &[payer.clone(), target.clone()],
            )?;
        }
        invoke_signed(
            &system_instruction::allocate(target.key, space as u64),
            &[target.clone()],
            &[signer.as_slice()],
        )?;
        invoke_signed(
            &system_instruction::assign(target.key, program_id),
            &[target.clone()],
            &[signer.as_slice()],
        )?;
    }
    Ok(bump)
}

pub fn create_marker<'info>(
    program_id: &Pubkey,
    payer: &AccountInfo<'info>,
    target: &AccountInfo<'info>,
    seeds: &[&[u8]],
) -> Result<()> {
    let bump = create_with_space(program_id, payer, target, seeds, Marker::SIZE)?;
    let mut data = target.try_borrow_mut_data()?;
    data[..8].copy_from_slice(Marker::DISCRIMINATOR);
    data[8] = bump;
    Ok(())
}

pub fn write_note<'info>(
    program_id: &Pubkey,
    payer: &AccountInfo<'info>,
    target: &AccountInfo<'info>,
    tree_number: u64,
    leaf_index: u64,
    commitment: [u8; 32],
    recorded_net: u128,
    ciphertext: &[u8],
) -> Result<()> {
    require!(
        ciphertext.len() <= MAX_CIPHERTEXT,
        LacunaError::CiphertextTooLarge
    );
    let tree_bytes = tree_number.to_le_bytes();
    let index_bytes = leaf_index.to_le_bytes();
    let seeds: [&[u8]; 3] = [SEED_NOTE, &tree_bytes, &index_bytes];
    create_with_space(program_id, payer, target, &seeds, NoteRecord::SIZE)?;
    let mut record = NoteRecord {
        tree_number,
        leaf_index,
        commitment,
        net: recorded_net,
        ciphertext_len: ciphertext.len() as u16,
        ciphertext: [0u8; MAX_CIPHERTEXT],
    };
    record.ciphertext[..ciphertext.len()].copy_from_slice(ciphertext);
    let mut data = target.try_borrow_mut_data()?;
    let mut cursor = std::io::Cursor::new(&mut data[..]);
    record.try_serialize(&mut cursor)?;
    Ok(())
}
