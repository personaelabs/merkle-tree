use ark_secp256k1::Fq;
use num_bigint::BigUint;
use poseidon::constants::secp256k1_w3;
use wasm_bindgen::prelude::*;

use crate::get_proofs::get_proofs;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn secp256k1_get_proofs(leaf_bytes: &[u8], depth: usize) -> Vec<String> {
    let leaves = leaf_bytes
        .chunks(32)
        .map(|chunk| Fq::from(BigUint::from_bytes_be(chunk)))
        .collect();

    let proofs = get_proofs(leaves, depth, secp256k1_w3());

    proofs.iter().map(|proof| proof.to_json()).collect()
}
