use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::iterable::Iterable;
use poseidon::{Poseidon, PoseidonConstants};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use serde::Serialize;

#[derive(Debug)]
pub struct MerkleProof<F: PrimeField> {
    pub leaf: F,
    pub siblings: Vec<F>,
    pub path_indices: Vec<usize>,
    pub root: F,
}

#[derive(CanonicalSerialize, Serialize)]
pub struct MerkleProofJson {
    siblings: Vec<[String; 1]>,
    pathIndices: Vec<String>,
    root: String,
    leaf: String,
}

impl<F: PrimeField> MerkleProof<F> {
    /**
     * Convert the proof to a JSON string
     */
    pub fn to_json(&self) -> String {
        let json = MerkleProofJson {
            leaf: self.leaf.to_string(),
            root: self.root.to_string(),
            siblings: self
                .siblings
                .iter()
                .map(|sibling| [sibling.to_string()])
                .collect::<Vec<[String; 1]>>(),
            pathIndices: self
                .path_indices
                .iter()
                .map(|path_index| path_index.to_string())
                .collect::<Vec<String>>(),
        };

        serde_json::to_string(&json).unwrap()
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleTree<F: PrimeField, const WIDTH: usize> {
    leaves: Vec<F>,
    poseidon: Poseidon<F, WIDTH>,
    is_tree_ready: bool,
    layers: Vec<Vec<F>>,
    depth: Option<usize>,
    pub root: Option<F>,
}

impl<F: PrimeField, const WIDTH: usize> MerkleTree<F, WIDTH> {
    /// Create a new Merkle tree with the given Poseidon constants
    pub fn new(constants: PoseidonConstants<F>) -> Self {
        let arty = WIDTH - 1;

        assert_eq!(arty, 2, "Only arity 2 is supported at the moment");

        let mut poseidon = Poseidon::new(constants);
        poseidon.state[0] = F::from(3u32);

        Self {
            poseidon,
            leaves: Vec::new(),
            is_tree_ready: false,
            layers: Vec::new(),
            depth: None,
            root: None,
        }
    }

    /// Insert a leaf into the tree
    pub fn insert(&mut self, leaf: F) {
        // Add the leaf to the bottom-most layer
        self.leaves.push(leaf);
    }

    /// Hash the given nodes and return the output
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

    /// Mark `is_tree_ready` as true and calculate the Merkle root of the tree
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

    fn calculate_root(&mut self) -> F {
        if !self.is_tree_ready {
            panic!("Tree is not ready");
        }

        self.layers.push(self.leaves.clone());
        let mut current_layer = self.layers[0].clone();

        let mut precomputed = vec![F::ZERO];
        for i in 0..self.depth.unwrap() {
            let hash = Self::hash(&mut self.poseidon, &[precomputed[i]; 2]);
            precomputed.push(hash);
        }

        for i in 0..self.depth.unwrap() {
            let layer_above = current_layer
                .par_chunks(self.arity())
                .map(|nodes| {
                    if nodes.iter().all(|&x| x == precomputed[i]) {
                        precomputed[i + 1]
                    } else {
                        let mut poseidon = self.poseidon.clone();
                        Self::hash(&mut poseidon, nodes)
                    }
                })
                .collect::<Vec<F>>();

            self.layers.push(layer_above.clone());
            current_layer = layer_above;
        }

        // Sanity check
        assert_eq!(current_layer.len(), 1);

        current_layer[0]
    }

    /**
     * Return the arity of the tree
     */
    fn arity(&self) -> usize {
        WIDTH - 1
    }

    /**
     * Create a proof for the given leaf
     */
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

    /**
     * Verify the proof against the given root
     */
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

    /// Serialize the tree
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];

        self.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Deserialize the tree
    pub fn from_compressed_bytes(bytes: &[u8]) -> Self {
        Self::deserialize_compressed(bytes).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_std::{end_timer, start_timer};
    use poseidon::constants::secp256k1_w3;

    type F = ark_secp256k1::Fq;

    #[test]
    fn test_tree() {
        const ARTY: usize = 2;
        const WIDTH: usize = ARTY + 1;

        let mut tree = MerkleTree::<F, WIDTH>::new(secp256k1_w3());

        let depth = 18;
        let num_leaves = 10000;
        let leaves = (0..num_leaves)
            .map(|i| F::from(i as u32))
            .collect::<Vec<F>>();

        let mut padded_leaves = leaves.clone();
        // Pad the leaves to equal the size of the tree
        padded_leaves.resize(1 << depth, F::ZERO);

        // Insert leaves
        let build_tree_timer = start_timer!(|| "Build tree");
        for leaf in leaves.iter() {
            tree.insert(*leaf);
        }

        tree.finish();
        end_timer!(build_tree_timer);

        let proof = tree.create_proof(leaves[0]);
        assert!(tree.verify_proof(tree.root.unwrap(), &proof));
    }
}
