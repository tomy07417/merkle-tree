use crate::merkle_errors::MerkleError;
use std::error::Error;

use crate::merkle_proof::MerkleProof;
use crate::merkle_proof_step::MerkleProofStep;

use sha2::{Digest, Sha256};

type Hash = [u8; 32];

pub struct MerkleTree {
    layers: Vec<Vec<Hash>>,
}

impl MerkleTree {
    pub fn new<T: AsRef<[u8]>>(data: Vec<T>) -> Self {
        let leaves: Vec<Hash> = data
            .iter()
            .map(|d| {
                let mut hasher = Sha256::new();
                hasher.update(d.as_ref());
                hasher.finalize().into()
            })
            .collect();

        if leaves.is_empty() || leaves.len() == 1 {
            return MerkleTree {
                layers: vec![leaves],
            };
        }

        let mut layers = Vec::new();
        let mut current_layer = MerkleTree::build_layer(&leaves);
        layers.push(leaves);

        while current_layer.len() > 1 {
            let new_layer = MerkleTree::build_layer(&current_layer);
            layers.push(current_layer);
            current_layer = new_layer;
        }

        layers.push(current_layer);

        MerkleTree { layers }
    }

    pub fn push<T: AsRef<[u8]>>(&mut self, new_data: Vec<T>) {
        let new_data_hashes: Vec<Hash> = new_data
            .iter()
            .map(|d| {
                let mut hasher = Sha256::new();
                hasher.update(d.as_ref());
                hasher.finalize().into()
            })
            .collect();

        self.layers[0].extend(new_data_hashes);
        self.rebuild_tree();
    }

    pub fn get_root(&self) -> Option<Hash> {
        self.layers.last().and_then(|layer| layer.first().cloned())
    }

    pub fn generate_merkle_proof(&self, index: usize) -> Result<MerkleProof, Box<dyn Error>> {
        let depth = self.layers.len();

        if index >= self.layers[0].len() {
            return Err(Box::new(MerkleError::IndexOutOfBounds));
        }

        if depth == 0 {
            return Ok(MerkleProof::new(vec![]));
        }

        let mut proof = Vec::new();
        let mut current_index = index;

        for level in 0..(depth - 1) {
            let layer = &self.layers[level];

            if layer.len() % 2 == 1 && current_index == layer.len() - 1 {
                proof.push(MerkleProofStep::new(layer[current_index], false));
                current_index = self.layers[level + 1].len() - 1;
            } else if current_index.is_multiple_of(2) {
                proof.push(MerkleProofStep::new(layer[current_index + 1], true));
                current_index /= 2;
            } else {
                proof.push(MerkleProofStep::new(layer[current_index - 1], false));
                current_index = (current_index - 1) / 2;
            }
        }

        proof.push(MerkleProofStep::new(self.get_root().unwrap(), false));
        Ok(MerkleProof::new(proof))
    }

    fn rebuild_tree(&mut self) {
        // Keep only the leaf layer (first layer)
        let leaves = self.layers[0].clone();

        // Clear all layers except leaves
        self.layers.clear();
        self.layers.push(leaves);

        // Rebuild the tree from scratch
        if self.layers[0].is_empty() || self.layers[0].len() == 1 {
            return;
        }

        let mut current_layer = MerkleTree::build_layer(&self.layers[0]);

        while current_layer.len() > 1 {
            let new_layer = MerkleTree::build_layer(&current_layer);
            self.layers.push(current_layer);
            current_layer = new_layer;
        }

        self.layers.push(current_layer);
    }

    fn build_layer(previous_layer: &[Hash]) -> Vec<Hash> {
        let layer: Vec<[u8; 32]> = previous_layer
            .chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();

                if pair.len() == 1 {
                    hasher.update(pair[0]);
                    hasher.update(pair[0]);
                    hasher.finalize().into()
                } else {
                    hasher.update(pair[0]);
                    hasher.update(pair[1]);
                    hasher.finalize().into()
                }
            })
            .collect::<Vec<Hash>>();

        layer
    }
}

impl PartialEq for MerkleTree {
    fn eq(&self, other: &Self) -> bool {
        self.get_root() == other.get_root()
    }
}
