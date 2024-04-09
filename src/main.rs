extern crate crypto;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
//use std::vec;

#[derive(Deserialize, PartialEq, PartialOrd, Ord, Eq, Debug)]
struct JsonValues {
    address: String,
    earnings: String,
    reasons: String,
}

type Hash = String;
#[derive(Debug)]
struct MerkleTree {
    elements: Result<Vec<Vec<String>>, String>,
    levels: usize,
}

impl MerkleTree {
    fn new(input: Vec<Hash>) -> Self {
        let (vector, levels) = MerkleTree::generate_merkle_tree(input);

        MerkleTree {
            elements: vector,
            levels,
        }
    }

    fn generate_merkle_tree(input: Vec<Hash>) -> (Result<Vec<Vec<Hash>>, String>, usize) {
        if input.len() == 0 {
            return (Err("The list is empty!".to_string()), 0);
        }

        let mut layers: Vec<Vec<Hash>> = Vec::new();
        layers.push(input);

        while layers[layers.len() - 1].len() > 1 {
            let next_layer = Self::get_next_layer(layers[layers.len() - 1].clone());
            layers.push(next_layer);
        }

        return (Ok(layers.clone()), layers.len());
    }

    fn get_next_layer(layer: Vec<Hash>) -> Vec<Hash> {
        let mut hash_value = Vec::new();

        if layer.len() % 2 == 0 {
            for val in 0..layer.len() - 1 {
                if val % 2 == 0 {
                    hash_value = Self::sort_and_hash(layer.clone(), val, &mut hash_value).to_vec();
                }
            }
        } else {
            let last_value = layer.len() - 1;
            for val in 0..layer.len() - 1 {
                if val % 2 == 0 {
                    hash_value = Self::sort_and_hash(layer.clone(), val, &mut hash_value).to_vec();
                }
            }
            hash_value.push(layer[last_value].clone());
        }

        return hash_value;
    }

    fn get_proof(
        element: String,
        address_list: HashMap<String, usize>,
        tree: Vec<Vec<Hash>>,
    ) -> Vec<Hash> {
        let mut proof: Vec<String> = Vec::new();

        match address_list.get(&element) {
            Some(&index) => {
                let mut level = 0;
                let (mut pair, mut next_index): (String, usize) = ("".to_string(), index);

                while level < tree.len() - 1 {
                    let layer = tree[level].clone();
                    (pair, next_index) = Self::get_pair(next_index, layer);
                    level += 1;
                    proof.push(pair);
                }
            }
            _ => println!("Address not found!"),
        }
        return proof;
    }

    fn get_pair(index: usize, tree: Vec<Hash>) -> (String, usize) {
        let mut pair = String::new();

        if tree.len() % 2 == 0 {
            if index % 2 == 0 {
                pair = tree[index + 1].clone();
            } else {
                pair = tree[index - 1].clone();
            }
        } else {
            if index == tree.len() - 1 {
                pair = tree[index].clone();
            } else {
                if index % 2 == 0 {
                    pair = tree[index + 1].clone();
                } else {
                    pair = tree[index - 1].clone();
                }
            }
        }

        let next_index = index / 2;
        return (pair, next_index);
    }

    fn verify_proof(value_to_verify: Hash, proof: Vec<Hash>, root: Vec<Hash>) -> bool {
        let mut verification = value_to_verify;

        for i in 0..proof.len() {
            let mut value_to_sort = Vec::new();
            value_to_sort.push(verification);
            value_to_sort.push(proof[i].clone());
            value_to_sort.sort();
            verification = value_to_sort[0].clone() + &value_to_sort[1];
            let mut hasher = Sha3::keccak256();
            hasher.input_str(&verification);
            verification = hasher.result_str();
        }

        println!("compare value: {} ", verification);

        if root[0] == verification {
            return true;
        } else {
            return false;
        }
    }

    fn sort_and_hash(layer: Vec<Hash>, val: usize, hash_value: &mut Vec<Hash>) -> &mut Vec<Hash> {
        let mut values_to_sort = Vec::new();
        values_to_sort.push(layer[val].clone());
        values_to_sort.push(layer[val + 1].clone());
        values_to_sort.sort();
        let concat_values = values_to_sort[0].clone() + &values_to_sort[1];
        let mut hasher = Sha3::keccak256();
        hasher.input_str(&concat_values);
        hash_value.push(hasher.result_str());
        return hash_value;
    }
}

fn main() {
    // Read file
    let file_name = "addresses_2.json";
    let file = File::open(file_name).unwrap();
    let reader = BufReader::new(file);
    let mut addresses: Vec<JsonValues> = serde_json::from_reader(reader).unwrap();

    // Sort
    addresses.sort();

    // Remove duplicates
    addresses.dedup();

    //Create an index for all elements
    let mut element_index = HashMap::new();

    let mut index = 0;
    for element in &addresses {
        element_index.insert(element.address.clone(), index);
        index += 1;
    }

    // Generate hash of elements
    let mut hashed_elements = Vec::new();

    for i in 0..addresses.len() {
        match element_index.get(&addresses[i].address) {
            Some(&index) => {
                let concat_values = index.to_string()
                    + &addresses[i].address.clone()
                    + &addresses[i].earnings.clone();
                let mut hasher = Sha3::keccak256();
                hasher.input_str(&concat_values);
                hashed_elements.push(hasher.result_str());
            }
            _ => println!("Address not found!"),
        }
    }

    // Generate merkle tree
    let merkle_tree = MerkleTree::new(hashed_elements);
    let mut merkle_tree_levels = Vec::new();

    match merkle_tree.elements {
        Ok(val) => merkle_tree_levels = val,
        Err(err) => println!("Merkle not found!"),
    }

    for i in 0..merkle_tree_levels.len() {
        println!("LEVEL [{}]: {:?} \n", i, merkle_tree_levels[i]);
    }

    //Get proof
    let address_claim = "0xa1d3c765e9a9655e8838bc4a9b16d5e6af024321".to_string();
    //"0x3b16821a5dbbff86e4a88ea0621ec6be016cd79a".to_string();
    //"0x08d816526bdc9d077dd685bd9fa49f58a5ab8e48".to_string();
    //"0xa1d3c765e9a9655e8838bc4a9b16d5e6af024321".to_string();
    let proof = MerkleTree::get_proof(
        address_claim.clone(),
        element_index.clone(),
        merkle_tree_levels.clone(),
    );
    println!("\nProof vector: {:?}", proof);

    //Verify proof
    let mut hash_value_to_verify = String::new();

    match element_index.get(&address_claim) {
        Some(&index) => {
            let concat_values =
                index.to_string() + &address_claim.clone() + &addresses[index].earnings.clone();
            let mut hasher = Sha3::keccak256();
            hasher.input_str(&concat_values);
            hash_value_to_verify = hasher.result_str();
        }
        _ => println!("Address not found!"),
    }

    let root = merkle_tree_levels[merkle_tree_levels.len() - 1].clone();
    println!("el root es: {:?}", root);
    let allow_to_claim = MerkleTree::verify_proof(hash_value_to_verify, proof, root.clone());

    if allow_to_claim == true {
        println!("ALLOW TO CLAIM!");
    } else {
        println!("YOU CAN'T CLAIM");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obtain_next_layer() {
        let vec_1 = vec![
            "1a4aaf8b295baef8985b3047eeb86b15be4de4137fec1858dc7651144eab3d84".to_string(),
            "a646efa7c78bed6e12c9db82b1d9e941e61ea645e0946aebe7b42530bd431405".to_string(),
            "b62bcfa20423ea9b87cc11c5b38cc89e898bdc0bd4f1d51401fb3128d6acc031".to_string(),
            "682ee7a79874a08675f518a7072f0bb4a711113c12fb48f5ee1f2d6c4febcd3a".to_string(),
        ];

        let next_level = vec![
            "4ad27e1a52ab16943ed61fe90ee3602a35c83838a7064d578450bbd6059455de".to_string(),
            "55667db136e25bfd631f32123fb27b933ceeef933eff0e3f5abbd5172aabf7b5".to_string(),
        ];
        let next_level_function = MerkleTree::get_next_layer(vec_1);
        assert!(next_level_function
            .iter()
            .all(|item| next_level.contains(item)));
    }
}
