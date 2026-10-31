use crate::constants::{PROOF_A_SIZE, PROOF_B_SIZE, PROOF_C_SIZE, PROOF_BUFFER_SIZE, PUBLIC_INPUTS};
use crate::error::LacunaError;
use crate::verifying_key::VERIFYING_KEY;
use anchor_lang::prelude::*;
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};

pub struct ParsedProof {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub public_inputs: [[u8; 32]; PUBLIC_INPUTS],
}

pub fn parse_proof(data: &[u8]) -> Result<Box<ParsedProof>> {
    require!(data.len() >= PROOF_BUFFER_SIZE, LacunaError::BadBuffer);
    let mut parsed = Box::new(ParsedProof {
        proof_a: [0u8; PROOF_A_SIZE],
        proof_b: [0u8; PROOF_B_SIZE],
        proof_c: [0u8; PROOF_C_SIZE],
        public_inputs: [[0u8; 32]; PUBLIC_INPUTS],
    });
    parsed.proof_a.copy_from_slice(&data[0..64]);
    parsed.proof_b.copy_from_slice(&data[64..192]);
    parsed.proof_c.copy_from_slice(&data[192..256]);
    for i in 0..PUBLIC_INPUTS {
        let start = 256 + i * 32;
        parsed.public_inputs[i].copy_from_slice(&data[start..start + 32]);
    }
    Ok(parsed)
}

fn g1_add(left: &[u8; 64], right: &[u8; 64]) -> Result<[u8; 64]> {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(left);
    input[64..].copy_from_slice(right);
    let out = alt_bn128_addition(&input).map_err(|_| error!(LacunaError::BadProofPoint))?;
    let mut point = [0u8; 64];
    point.copy_from_slice(&out);
    Ok(point)
}

fn g1_mul_add(point: &[u8; 64], scalar: &[u8; 32], acc: &[u8; 64]) -> Result<[u8; 64]> {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(scalar);
    let prod = alt_bn128_multiplication(&input).map_err(|_| error!(LacunaError::BadProofPoint))?;
    let mut prod_be = [0u8; 64];
    prod_be.copy_from_slice(&prod);
    g1_add(&prod_be, acc)
}

pub fn verify_proof(parsed: &ParsedProof) -> Result<()> {
    let mut prepared = VERIFYING_KEY.vk_ic[0];
    for (i, input) in parsed.public_inputs.iter().enumerate() {
        require!(crate::field::lt_field(input), LacunaError::BadProof);
        if crate::field::is_zero(input) {
            continue;
        }
        prepared = g1_mul_add(&VERIFYING_KEY.vk_ic[i + 1], input, &prepared)?;
    }

    let mut pairing_input = Vec::with_capacity(768);
    pairing_input.extend_from_slice(&parsed.proof_a);
    pairing_input.extend_from_slice(&parsed.proof_b);
    pairing_input.extend_from_slice(&prepared);
    pairing_input.extend_from_slice(&VERIFYING_KEY.vk_gamma_g2);
    pairing_input.extend_from_slice(&parsed.proof_c);
    pairing_input.extend_from_slice(&VERIFYING_KEY.vk_delta_g2);
    pairing_input.extend_from_slice(&VERIFYING_KEY.vk_alpha_g1);
    pairing_input.extend_from_slice(&VERIFYING_KEY.vk_beta_g2);

    let pairing_res = alt_bn128_pairing(&pairing_input).map_err(|_| error!(LacunaError::BadPairing))?;
    require!(pairing_res.last() == Some(&1), LacunaError::BadPairing);
    Ok(())
}
