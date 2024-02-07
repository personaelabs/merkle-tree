use crate::tree::{MerkleProof, MerkleTree};
use ark_ff::PrimeField;
use poseidon::PoseidonConstants;

/**
 * Build a Merkle tree from the given leaves and return Merkle proofs for all leaves
 */
pub fn get_proofs<F: PrimeField>(
    leaves: Vec<F>,
    depth: usize,
    constants: PoseidonConstants<F>,
) -> Vec<MerkleProof<F>> {
    let leaves = leaves;

    let mut padded_leaves = leaves.clone();
    // Pad the leaves to equal the size of the tree
    padded_leaves.resize(1 << depth, F::ZERO);

    // Construct the tree
    const ARTY: usize = 2;
    const WIDTH: usize = ARTY + 1;

    let mut tree = MerkleTree::<F, WIDTH>::new(constants);
    // Insert all leaves into the tree
    for leaf in &padded_leaves {
        tree.insert(*leaf);
    }

    tree.finish();

    // Create proofs
    let proofs = leaves
        .iter()
        .map(|address| tree.create_proof(*address))
        .collect();

    proofs
}
