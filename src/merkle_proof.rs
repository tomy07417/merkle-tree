use crate::merkle_proof_step::MerkleProofStep;

#[derive(Debug)]
pub struct MerkleProof {
    steps: Vec<MerkleProofStep>,
}

impl MerkleProof {
    pub fn new(steps: Vec<MerkleProofStep>) -> Self {
        MerkleProof { steps }
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn steps(&self) -> &[MerkleProofStep] {
        &self.steps
    }

    pub fn verify(&self, hash: [u8; 32]) -> bool {
        if self.steps.is_empty() {
            return false;
        }

        if self.steps.len() == 1 {
            return self.steps[0].compare_hash(hash);
        }

        let mut current_hash = hash;
        
        for i in 0..(self.steps.len() - 1) {
            let step = &self.steps[i];

            current_hash = step.generate_hash(current_hash);
        }

        let last_step = &self.steps[self.steps.len() - 1];
        last_step.compare_hash(current_hash)
    }
}

impl PartialEq for MerkleProof {
    fn eq(&self, other: &Self) -> bool {
        self.steps == other.steps
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::merkle_tree::MerkleTree;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_verify_valid_proof_single_leaf() {
        let tree = MerkleTree::new(vec!["A"]);
        let proof = tree.generate_merkle_proof(0).unwrap();
        let leaf_hash = Sha256::digest(b"A");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_two_leaves_left() {
        let tree = MerkleTree::new(vec!["A", "B"]);
        let proof = tree.generate_merkle_proof(0).unwrap();
        let leaf_hash = Sha256::digest(b"A");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_two_leaves_right() {
        let tree = MerkleTree::new(vec!["A", "B"]);
        let proof = tree.generate_merkle_proof(1).unwrap();
        let leaf_hash = Sha256::digest(b"B");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_four_leaves_first() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(0).unwrap();
        let leaf_hash = Sha256::digest(b"A");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_four_leaves_second() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(1).unwrap();
        let leaf_hash = Sha256::digest(b"B");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_four_leaves_third() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(2).unwrap();
        let leaf_hash = Sha256::digest(b"C");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_four_leaves_last() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(3).unwrap();
        let leaf_hash = Sha256::digest(b"D");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_odd_leaves_first() {
        let tree = MerkleTree::new(vec!["A", "B", "C"]);
        let proof = tree.generate_merkle_proof(0).unwrap();
        let leaf_hash = Sha256::digest(b"A");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_odd_leaves_middle() {
        let tree = MerkleTree::new(vec!["A", "B", "C"]);
        let proof = tree.generate_merkle_proof(1).unwrap();
        let leaf_hash = Sha256::digest(b"B");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_odd_leaves_last() {
        let tree = MerkleTree::new(vec!["A", "B", "C"]);
        let proof = tree.generate_merkle_proof(2).unwrap();
        let leaf_hash = Sha256::digest(b"C");

        assert!(proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_large_tree() {
        let data: Vec<&str> = vec![
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
        ];
        let tree = MerkleTree::new(data);

        // Test various indices
        for i in 0..16 {
            let proof = tree.generate_merkle_proof(i).unwrap();
            let leaf_data = format!("{}", (b'A' + i as u8) as char);
            let leaf_hash = Sha256::digest(leaf_data.as_bytes());
            assert!(
                proof.verify(leaf_hash.into()),
                "Proof verification failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_verify_invalid_proof_wrong_leaf() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(0).unwrap();
        let wrong_leaf_hash = Sha256::digest(b"X"); // Wrong data

        assert!(!proof.verify(wrong_leaf_hash.into()));
    }

    #[test]
    fn test_verify_invalid_proof_tampered_sibling() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(0).unwrap();

        // Tamper with the proof by modifying a step
        let tampered_steps: Vec<MerkleProofStep> = proof
            .steps()
            .iter()
            .enumerate()
            .map(|(i, step)| {
                if i == 0 {
                    // Tamper the first sibling hash
                    let mut tampered_hash = step.hash;
                    tampered_hash[0] ^= 0xFF; // Flip bits
                    MerkleProofStep::new(tampered_hash, step.side)
                } else {
                    MerkleProofStep::new(step.hash, step.side)
                }
            })
            .collect();

        let tampered_proof = MerkleProof::new(tampered_steps);
        let leaf_hash = Sha256::digest(b"A");

        assert!(!tampered_proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_invalid_proof_wrong_side() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(0).unwrap();

        // Create proof with flipped side
        let flipped_steps: Vec<MerkleProofStep> = proof
            .steps()
            .iter()
            .enumerate()
            .map(|(i, step)| {
                if i == 0 {
                    // Flip the side of the first step
                    MerkleProofStep::new(step.hash, !step.side)
                } else {
                    MerkleProofStep::new(step.hash, step.side)
                }
            })
            .collect();

        let flipped_proof = MerkleProof::new(flipped_steps);
        let leaf_hash = Sha256::digest(b"A");

        assert!(!flipped_proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_invalid_proof_missing_step() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(0).unwrap();

        // Create proof with missing step
        let truncated_steps: Vec<MerkleProofStep> = proof
            .steps()
            .iter()
            .take(proof.len() - 2) // Remove one step before root
            .map(|step| MerkleProofStep::new(step.hash, step.side))
            .collect();

        let truncated_proof = MerkleProof::new(truncated_steps);
        let leaf_hash = Sha256::digest(b"A");

        // This should fail because the proof is incomplete
        assert!(!truncated_proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_valid_proof_all_indices_small_tree() {
        let data = vec!["Alice", "Bob", "Charlie", "David", "Eve"];
        let tree = MerkleTree::new(data.clone());

        for (i, name) in data.iter().enumerate() {
            let proof = tree.generate_merkle_proof(i).unwrap();
            let leaf_hash = Sha256::digest(name.as_bytes());
            assert!(
                proof.verify(leaf_hash.into()),
                "Proof verification failed for index {} ({})",
                i,
                name
            );
        }
    }

    #[test]
    fn test_verify_stateless_with_only_root() {
        // This test demonstrates that verification works with only proof, leaf, and root
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let root = tree.get_root().unwrap();
        let proof = tree.generate_merkle_proof(2).unwrap();
        let leaf_hash = Sha256::digest(b"C");

        // Verify the proof
        assert!(proof.verify(leaf_hash.into()));

        // Check that the proof leads to the expected root
        let last_step = proof.steps().last().unwrap();
        assert_eq!(last_step.hash, root);
    }

    #[test]
    fn test_verify_proof_with_binary_data() {
        let data: Vec<Vec<u8>> = vec![
            vec![0, 1, 2, 3],
            vec![4, 5, 6, 7],
            vec![8, 9, 10, 11],
            vec![12, 13, 14, 15],
        ];
        let tree = MerkleTree::new(data.clone());

        for (i, bytes) in data.iter().enumerate() {
            let proof = tree.generate_merkle_proof(i).unwrap();
            let leaf_hash = Sha256::digest(bytes);
            assert!(
                proof.verify(leaf_hash.into()),
                "Binary data proof verification failed for index {}",
                i
            );
        }
    }

    #[test]
    fn test_verify_proof_seven_leaves() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D", "E", "F", "G"]);

        for i in 0..7 {
            let proof = tree.generate_merkle_proof(i).unwrap();
            let leaf_data = format!("{}", (b'A' + i as u8) as char);
            let leaf_hash = Sha256::digest(leaf_data.as_bytes());
            assert!(
                proof.verify(leaf_hash.into()),
                "Proof verification failed for index {} in 7-leaf tree",
                i
            );
        }
    }

    #[test]
    fn test_verify_invalid_proof_swapped_siblings() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof0 = tree.generate_merkle_proof(0).unwrap();
        let proof1 = tree.generate_merkle_proof(1).unwrap();

        // Try to verify proof0 with leaf from proof1
        let leaf_hash_1 = Sha256::digest(b"B");
        assert!(!proof0.verify(leaf_hash_1.into()));

        // Try to verify proof1 with leaf from proof0
        let leaf_hash_0 = Sha256::digest(b"A");
        assert!(!proof1.verify(leaf_hash_0.into()));
    }

    #[test]
    fn test_verify_empty_proof() {
        let empty_proof = MerkleProof::new(vec![]);
        let leaf_hash = Sha256::digest(b"A");

        // An empty proof should fail
        assert!(!empty_proof.verify(leaf_hash.into()));
    }

    #[test]
    fn test_verify_proof_deterministic() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof1 = tree.generate_merkle_proof(0).unwrap();
        let proof2 = tree.generate_merkle_proof(0).unwrap();
        let leaf_hash = Sha256::digest(b"A");

        // Both proofs should verify the same way
        assert_eq!(proof1.verify(leaf_hash.into()), proof2.verify(leaf_hash.into()));
        assert!(proof1.verify(leaf_hash.into()));
    }
}