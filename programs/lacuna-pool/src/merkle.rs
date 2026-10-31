use crate::constants::LEVELS;
use crate::error::LacunaError;
use crate::state::Tree;
use anchor_lang::prelude::*;

pub fn hash2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    let hashed = solana_poseidon::hashv(
        solana_poseidon::Parameters::Bn254X5,
        solana_poseidon::Endianness::BigEndian,
        &[left.as_slice(), right.as_slice()],
    )
    .map_err(|_| error!(LacunaError::BadValue))?;
    Ok(hashed.to_bytes())
}

pub fn build_zeros() -> Result<([[u8; 32]; LEVELS], [u8; 32])> {
    let mut zeros = [[0u8; 32]; LEVELS];
    let mut current = [0u8; 32];
    zeros[0] = current;
    for i in 1..LEVELS {
        current = hash2(&current, &current)?;
        zeros[i] = current;
    }
    let root = hash2(&zeros[LEVELS - 1], &zeros[LEVELS - 1])?;
    Ok((zeros, root))
}

pub fn insert(tree: &mut Tree, commitment: [u8; 32]) -> Result<[u8; 32]> {
    let mut current_index = tree.next_index;
    let mut current = commitment;
    for level in 0..LEVELS {
        if current_index % 2 == 0 {
            tree.filled_subtrees[level] = current;
            current = hash2(&current, &tree.zeros[level])?;
        } else {
            current = hash2(&tree.filled_subtrees[level], &current)?;
        }
        current_index /= 2;
    }
    tree.next_index += 1;
    tree.current_root = current;
    Ok(current)
}
