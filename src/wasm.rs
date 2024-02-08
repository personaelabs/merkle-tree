use crate::{get_proofs::get_proofs, tree::MerkleTree};
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_secp256k1::Fq;
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use poseidon::constants::secp256k1_w3;
pub use std::sync::Mutex;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

const WIDTH: usize = 3;
static SECP256K1_TREE: Lazy<Mutex<MerkleTree<Fq, WIDTH>>> =
    Lazy::new(|| Mutex::new(MerkleTree::new(secp256k1_w3())));

#[wasm_bindgen]
pub fn secp256k1_init_tree(leaf_bytes: &[u8], depth: usize) -> String {
    let mut tree = SECP256K1_TREE.lock().unwrap();

    // Initialize the tree
    *tree = MerkleTree::new(secp256k1_w3());

    let leaves = leaf_bytes
        .chunks(32)
        .map(|chunk| Fq::from(BigUint::from_bytes_be(chunk)))
        .collect::<Vec<Fq>>();

    let mut padded_leaves = leaves.clone();
    // Pad the leaves to equal the size of the tree
    padded_leaves.resize(1 << depth, Fq::ZERO);

    // Insert all leaves into the tree
    for leaf in &padded_leaves {
        tree.insert(*leaf);
    }

    tree.finish();

    tree.root.unwrap().into_bigint().to_string()
}

#[wasm_bindgen]
pub fn secp256k1_create_proof(leaf_bytes: &[u8]) -> String {
    let tree = SECP256K1_TREE.lock().unwrap();
    let leaf = Fq::from(BigUint::from_bytes_be(leaf_bytes));
    let proof = tree.create_proof(leaf);
    proof.to_json()
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
