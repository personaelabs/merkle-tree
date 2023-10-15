#![allow(non_snake_case)]
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1;
use csv::ReaderBuilder;
use merkle_tree::{MerkleProof, MerkleTree};
use num_bigint::BigUint;
use poseidon::constants::secp256k1_w3;
use serde::Serialize;
use std::fs;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

#[derive(Serialize)]
pub struct MerkleProofJson {
    siblings: Vec<[String; 1]>,
    pathIndices: Vec<String>,
    root: String,
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
            },
        }
    }
}

const DEV_ACCOUNTS: [&str; 2] = [
    // dantehrani.eth
    "0x400EA6522867456E988235675b9Cb5b1Cf5b79C8",
    // personaelabs.eth
    "0x141b63D93DaF55bfb7F396eEe6114F3A5d4A90B2",
];

fn save_tree<F: PrimeField>(leaves: Vec<F>, depth: usize, out_file: &str) -> F {
    let leaves = leaves.clone();

    let mut padded_leaves = leaves.clone();
    // Pad the leaves to equal the size of the tree
    padded_leaves.resize(1 << depth, F::ZERO);

    // Construct the tree
    const ARTY: usize = 2;
    const WIDTH: usize = ARTY + 1;

    let mut tree = MerkleTree::<F, WIDTH>::new(secp256k1_w3());
    // Insert all leaves into the tree
    for leaf in &padded_leaves {
        tree.insert(*leaf);
    }

    tree.finish();

    // Create proofs and convert then into json
    let proofs = leaves
        .iter()
        .map(|address| tree.create_proof(*address).to_json())
        .collect::<Vec<MerkleProofJsonWithAddress>>();

    // Construct the json string of proofs
    let proofs_json = serde_json::to_string(&proofs).unwrap();

    // Create the out/ directory if it doesn't exist
    if fs::read_dir("out/").is_err() {
        fs::create_dir("out/").unwrap();
    }

    let proofs_out_path = Path::new("./out/").join(format!("{}.json", out_file));
    let mut proofs_file = File::create(proofs_out_path).unwrap();

    // Write the proofs to a file
    proofs_file.write_all(proofs_json.as_bytes()).unwrap();

    // Construct the json string of addresses
    let addresses_json = serde_json::to_string(
        &leaves
            .iter()
            .map(|leaf| leaf.to_string())
            .collect::<Vec<String>>(),
    )
    .unwrap();

    let addresses_out_path = Path::new("./out/").join(format!("{}.addresses.json", out_file));
    let mut addresses_file = File::create(addresses_out_path).unwrap();

    // Write the addresses to a file
    addresses_file.write_all(addresses_json.as_bytes()).unwrap();

    tree.root.unwrap()
}

fn main() {
    type F = ark_secp256k1::Fq;

    // The depth of the tree
    let depth = 15;

    // Read all files in csv/
    let files = fs::read_dir("./csv/").unwrap();

    let mut roots: Vec<(F, String)> = vec![];

    for file in files {
        let path = file.unwrap().path();

        // Open the csv file
        let mut file = File::open(path.clone()).unwrap();

        // Extract the file name.
        // This will be used as the name of the output file
        let file_name = path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .replace(".csv", "");

        let file_name_dev = format!("{}.dev", file_name);

        println!("Processing {}... ", file_name);

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

        let mut addresses_dev = addresses.clone();

        // Add the dev accounts
        for dev_account in DEV_ACCOUNTS.iter() {
            let dev_account_hex = hex::decode(dev_account.replace("0x", "")).unwrap();
            let leaf = F::from(BigUint::from_bytes_be(&dev_account_hex));
            addresses_dev.push(leaf);
        }

        let root = save_tree(addresses, depth, &file_name);
        let root_dev = save_tree(addresses_dev, depth, &file_name_dev);

        roots.push((root, file_name));
        roots.push((root_dev, file_name_dev));
    }

    // Save the root to set name mapping as JSON
    let mut root_to_label_mapping = "{\n".to_string();
    for (i, (root, name)) in roots.iter().enumerate() {
        if i == roots.len() - 1 {
            root_to_label_mapping += &format!("\"{}\": \"{}\"\n", root, name);
        } else {
            root_to_label_mapping += &format!("\"{}\": \"{}\",\n", root, name);
        }
    }
    root_to_label_mapping += "}";

    let mut file = File::create("out/root_to_label_mapping.json").unwrap();
    file.write_all(root_to_label_mapping.as_bytes()).unwrap();
}
