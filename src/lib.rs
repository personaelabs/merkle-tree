#![allow(non_snake_case)]
use ark_ff::PrimeField;
use poseidon::{Poseidon, PoseidonConstants};
use rayon::{prelude::ParallelIterator, slice::ParallelSlice};

pub struct MerkleTree<F: PrimeField, const WIDTH: usize> {
    _marker: std::marker::PhantomData<F>,
    leaves: Vec<F>,
    poseidon: Poseidon<F, WIDTH>,
    is_tree_ready: bool,
    layers: Vec<Vec<F>>,
    depth: Option<usize>,
    pub root: Option<F>,
}

#[derive(Debug)]
pub struct MerkleProof<F: PrimeField> {
    pub leaf: F,
    pub siblings: Vec<F>,
    pub path_indices: Vec<usize>,
    pub root: F,
}

impl<F: PrimeField, const WIDTH: usize> MerkleTree<F, WIDTH> {
    pub fn new(constants: PoseidonConstants<F>) -> Self {
        let arty = WIDTH - 1;

        assert_eq!(arty, 2, "Only arity 2 is supported at the moment");

        let mut poseidon = Poseidon::new(constants);
        poseidon.state[0] = F::from(3u32);

        Self {
            poseidon,
            leaves: Vec::new(),
            _marker: std::marker::PhantomData,
            is_tree_ready: false,
            layers: Vec::new(),
            depth: None,
            root: None,
        }
    }

    pub fn insert(&mut self, leaf: F) {
        // Add the leaf to the bottom-most layer
        self.leaves.push(leaf);
    }

    fn hash(poseidon: &mut Poseidon<F, WIDTH>, nodes: &[F]) -> F {
        assert_eq!(nodes.len(), poseidon.state.len() - 1);
        for i in 0..nodes.len() {
            poseidon.state[i + 1] = nodes[i];
        }

        poseidon.permute();
        let out = poseidon.state[1];

        poseidon.reset();
        poseidon.state[0] = F::from(3u32);

        out
    }

    pub fn finish(&mut self) {
        // Pad the leaves to a power of 2
        let padded_len = self.leaves.len().next_power_of_two();
        self.leaves.resize(padded_len, F::ZERO);

        let depth = (padded_len as f64).log2() as usize;

        self.depth = Some(depth);

        self.is_tree_ready = true;

        // Calculate the root
        let root = self.calculate_root();
        self.root = Some(root);
    }

    pub fn calculate_root(&mut self) -> F {
        if !self.is_tree_ready {
            panic!("Tree is not ready");
        }

        self.layers.push(self.leaves.clone());
        let mut current_layer = self.layers[0].clone();

        for _ in 0..self.depth.unwrap() {
            let layer_above = current_layer
                .par_chunks(self.arity())
                .map(|nodes| {
                    let mut poseidon = self.poseidon.clone();
                    Self::hash(&mut poseidon, nodes)
                })
                .collect::<Vec<F>>();

            self.layers.push(layer_above.clone());
            current_layer = layer_above;
        }

        // Sanity check
        assert_eq!(current_layer.len(), 1);

        current_layer[0]
    }

    pub fn arity(&self) -> usize {
        WIDTH - 1
    }

    pub fn create_proof(&self, leaf: F) -> MerkleProof<F> {
        if !self.is_tree_ready {
            panic!("Tree is not ready");
        }

        let mut siblings = vec![];
        let mut path_indices = vec![];

        let mut current_layer = &self.layers[0];

        let mut leaf_index = self
            .leaves
            .iter()
            .position(|&x| x == leaf)
            .expect("Leaf not found");

        for i in 0..self.depth.unwrap() {
            let sibling_index = if leaf_index % 2 == 0 {
                leaf_index + 1
            } else {
                leaf_index - 1
            };

            let sibling = current_layer[sibling_index];
            siblings.push(sibling);
            path_indices.push(leaf_index & 1);

            leaf_index /= 2;
            current_layer = &self.layers[i + 1];
        }

        MerkleProof {
            leaf,
            siblings,
            path_indices,
            root: self.root.unwrap(),
        }
    }

    pub fn verify_proof(&mut self, root: F, proof: &MerkleProof<F>) -> bool {
        let mut node = proof.leaf;
        for (sibling, node_index) in proof.siblings.iter().zip(proof.path_indices.iter()) {
            let is_node_index_even = node_index & 1 == 0;
            let nodes = if is_node_index_even {
                [node, *sibling]
            } else {
                [*sibling, node]
            };

            node = Self::hash(&mut self.poseidon, &nodes);
        }

        node == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{end_timer, start_timer};
    use poseidon::constants::secp256k1_w3;

    type F = ark_secp256k1::Fq;

    #[test]
    fn test_tree() {
        const ARTY: usize = 2;
        const WIDTH: usize = ARTY + 1;

        let mut tree = MerkleTree::<F, WIDTH>::new(secp256k1_w3());

        let depth = 10;
        let num_leaves = 1 << depth;
        let leaves = (0..num_leaves)
            .map(|i| F::from(i as u32))
            .collect::<Vec<F>>();

        // Insert leaves
        let insert_leaves_timer = start_timer!(|| "Insert leaves");
        for leaf in leaves.iter() {
            tree.insert(*leaf);
        }
        end_timer!(insert_leaves_timer);

        tree.finish();

        let proof = tree.create_proof(leaves[0]);
        assert!(tree.verify_proof(tree.root.unwrap(), &proof));
    }
}
