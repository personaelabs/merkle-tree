#![allow(non_snake_case)]
use ark_ff::{BigInteger, Field, PrimeField};
use ark_secp256k1;
use csv::ReaderBuilder;
use merkle_tree::{MerkleProof, MerkleTree};
use num_bigint::BigUint;
use poseidon::constants::secp256k1_w3;
use serde::Serialize;
use std::fs;
use std::{
    env,
    fs::File,
    io::{Read, Write},
    path::Path,
};

#[derive(Serialize)]
pub struct MerkleProofJson {
    siblings: Vec<[String; 1]>,
    pathIndices: Vec<String>,
}

#[derive(Serialize)]
pub struct MerkleProofJsonWithAddress {
    address: String,
    merkleProof: MerkleProofJson,
}

trait ToJson {
    fn to_json(&self) -> MerkleProofJsonWithAddress;
}

impl<F: PrimeField> ToJson for MerkleProof<F> {
    fn to_json(&self) -> MerkleProofJsonWithAddress {
        let address_bytes = &self.leaf.into_bigint().to_bytes_be()[12..];
        MerkleProofJsonWithAddress {
            address: format!("0x{}", hex::encode(address_bytes)),
            merkleProof: MerkleProofJson {
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
            },
        }
    }
}

fn main() {
    type F = ark_secp256k1::Fq;

    // The depth of the tree
    let depth = 15;
    let args: Vec<String> = env::args().collect();

    // Input file path
    let csv_file = &args[1];

    // Output file name
    let out_file = &args[2];

    // Open the csv file
    let mut file = File::open(csv_file).unwrap();

    // Read all lines into `contents`
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let mut rdr = ReaderBuilder::new().from_reader(contents.as_bytes());

    let mut addresses = vec![];

    // Store the addresses in a vector
    for result in rdr.records() {
        let record = result.unwrap();
        let record_hex = hex::decode(record.get(0).unwrap().replace("0x", "")).unwrap();
        let leaf = F::from(BigUint::from_bytes_be(&record_hex));
        addresses.push(leaf);
    }

    let mut leaves = addresses.clone();
    // Pad the leaves to equal the size of the tree
    leaves.resize(1 << depth, F::ZERO);

    const ARTY: usize = 2;
    const WIDTH: usize = ARTY + 1;

    let mut tree = MerkleTree::<F, WIDTH>::new(secp256k1_w3());
    // Insert all leaves into the tree
    for leaf in leaves {
        tree.insert(leaf);
    }

    tree.finish();

    // Transform the proofs into json
    let proofs = addresses
        .iter()
        .map(|address| tree.create_proof(*address).to_json())
        .collect::<Vec<MerkleProofJsonWithAddress>>();

    // Construct the json string
    let json = serde_json::to_string(&proofs).unwrap();

    // Create the out directory if it doesn't exist
    if fs::read_dir("out/").is_err() {
        fs::create_dir("out/").unwrap();
    }

    let out_path = Path::new("./out/").join(format!("{}.json", out_file));
    let mut file = File::create(out_path).unwrap();

    // Write the json to the file
    file.write_all(json.as_bytes()).unwrap();
}
