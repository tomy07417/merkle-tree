use sha2::{Digest, Sha256};
use crate::merkle_proof::MerkleProof;

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
            return MerkleTree { layers: vec![leaves] };
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

    pub fn get_root(&self) -> Option<Hash> {
        self.layers.last().and_then(|layer| layer.first().cloned())
    }

    pub fn generate_merkle_proof(&self, index: usize) -> Vec<MerkleProof> {
        let depth = self.layers.len();

        if depth == 0 {
            return vec![];
        }
        
        let mut proof = Vec::new();
        let mut current_index = index;

        for level in 0..(depth - 1) {
            let layer = &self.layers[level];
            
            if layer.len() % 2 == 1 && current_index == layer.len() - 1 {
                // Odd index and no sibling (last element)
                proof.push(MerkleProof::new(layer[current_index], false));
                current_index = self.layers[level + 1].len() - 1;
            } else if current_index % 2 == 0 {
                proof.push(MerkleProof::new(layer[current_index + 1], true));
                current_index /= 2;
            } else {
                proof.push(MerkleProof::new(layer[current_index - 1], false));
                current_index = (current_index - 1) / 2;
            }
        }
        
        proof.push(MerkleProof::new(self.get_root().unwrap(), false));
        proof
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

mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new::<&[u8]>(vec![]);
        assert!(tree.get_root().is_none());
    }

    #[test]
    fn test_create_tree_with_array_of_bytes() {
        let data = vec![b"A", b"B", b"C", b"D"];
        let tree = MerkleTree::new(data);

        assert!(tree.get_root().is_some());
    }

    #[test]
    fn test_single_leaf() {
        let tree = MerkleTree::new(vec!["A"]);

        let expected_root = Sha256::digest(b"A");

        let root = tree.get_root().unwrap();
        assert_eq!(root, expected_root.as_slice());
    }

    #[test]
    fn test_multiple_leaves() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);

        // Manually compute the expected root
        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");
        let hash_c = Sha256::digest(b"C");
        let hash_d = Sha256::digest(b"D");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let hash_ab = hasher.finalize_reset();

        hasher.update(&hash_c);
        hasher.update(&hash_d);
        let hash_cd = hasher.finalize_reset();

        hasher.update(&hash_ab);
        hasher.update(&hash_cd);
        let expected_root = hasher.finalize();

        let root = tree.get_root().unwrap();

        assert_eq!(root, expected_root.as_slice());
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let tree = MerkleTree::new(vec!["A", "B", "C"]);

        // Manually compute the expected root
        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");
        let hash_c = Sha256::digest(b"C");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let hash_ab = hasher.finalize_reset();

        hasher.update(&hash_c);
        hasher.update(&hash_c);
        let hash_cc = hasher.finalize_reset();

        hasher.update(&hash_ab);
        hasher.update(&hash_cc);
        let expected_root = hasher.finalize();

        let root = tree.get_root().unwrap();
        assert_eq!(root, expected_root.as_slice());
    }

    #[test]
    fn test_diferents_leaves_generate_diferent_roots() {
        let tree1 = MerkleTree::new(vec!["A", "B", "C"]);
        let tree2 = MerkleTree::new(vec!["A", "B", "D"]);

        let root1 = tree1.get_root().unwrap();
        let root2 = tree2.get_root().unwrap();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_same_leaves_generate_same_roots() {
        let tree1 = MerkleTree::new(vec!["A", "B", "C"]);
        let tree2 = MerkleTree::new(vec!["A", "B", "C"]);

        let root1 = tree1.get_root().unwrap();
        let root2 = tree2.get_root().unwrap();

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_same_leaves_but_different_order_generate_different_roots() {
        let tree1 = MerkleTree::new(vec!["A", "B", "C"]);
        let tree2 = MerkleTree::new(vec!["C", "B", "A"]);

        let root1 = tree1.get_root().unwrap();
        let root2 = tree2.get_root().unwrap();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_generate_merkle_proof_for_2_leaves_tree() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof = tree.generate_merkle_proof(0);

        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");
        let hash_c = Sha256::digest(b"C");
        let hash_d = Sha256::digest(b"D");
        
        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let hash_ab = hasher.finalize_reset();

        hasher.update(&hash_c);
        hasher.update(&hash_d);
        let hash_cd = hasher.finalize_reset();

        hasher.update(&hash_ab);
        hasher.update(&hash_cd);
        let expected_root = hasher.finalize();

        let expected_proof = vec![
            MerkleProof::new(hash_b.into(), true),
            MerkleProof::new(hash_cd.into(), true),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof.len(), 3);
        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_proof_for_single_leaf() {
        let tree = MerkleTree::new(vec!["A"]);
        let proof = tree.generate_merkle_proof(0);

        let expected_root = Sha256::digest(b"A");

        let expected_proof = vec![
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_proof_for_two_leaves_left_node() {
        let tree = MerkleTree::new(vec!["A", "B"]);
        let proof = tree.generate_merkle_proof(0);

        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let expected_root = hasher.finalize();

        let expected_proof = vec![
            MerkleProof::new(hash_b.into(), true),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_proof_for_two_leaves_right_node() {
        let tree = MerkleTree::new(vec!["A", "B"]);
        let proof = tree.generate_merkle_proof(1);

        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let expected_root = hasher.finalize();

        let expected_proof = vec![
            MerkleProof::new(hash_a.into(), false),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_proof_for_odd_leaves_last_node() {
        let tree = MerkleTree::new(vec!["A", "B", "C"]);
        let proof = tree.generate_merkle_proof(2);

        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");
        let hash_c = Sha256::digest(b"C");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let hash_ab = hasher.finalize_reset();

        hasher.update(&hash_c);
        hasher.update(&hash_c);
        let hash_cc = hasher.finalize_reset();

        hasher.update(&hash_ab);
        hasher.update(&hash_cc);
        let expected_root = hasher.finalize();

        let expected_proof = vec![
            MerkleProof::new(hash_c.into(), false),
            MerkleProof::new(hash_ab.into(), false),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert!(proof.len() > 0);
        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_proof_for_odd_leaves_first_node() {
        let tree = MerkleTree::new(vec!["A", "B", "C"]);
        let proof = tree.generate_merkle_proof(0);

        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");
        let hash_c = Sha256::digest(b"C");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let hash_ab = hasher.finalize_reset();

        hasher.update(&hash_c);
        hasher.update(&hash_c);
        let hash_cc = hasher.finalize_reset();

        hasher.update(&hash_ab);
        hasher.update(&hash_cc);
        let expected_root = hasher.finalize();

        let expected_proof = vec![
            MerkleProof::new(hash_b.into(), true),
            MerkleProof::new(hash_cc.into(), true),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_proof_length_matches_tree_depth() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D", "E", "F", "G", "H"]);
        let proof = tree.generate_merkle_proof(0);

        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");
        let hash_c = Sha256::digest(b"C");
        let hash_d = Sha256::digest(b"D");
        let hash_e = Sha256::digest(b"E");
        let hash_f = Sha256::digest(b"F");
        let hash_g = Sha256::digest(b"G");
        let hash_h = Sha256::digest(b"H");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let hash_ab = hasher.finalize_reset();

        hasher.update(&hash_c);
        hasher.update(&hash_d);
        let hash_cd = hasher.finalize_reset();

        hasher.update(&hash_e);
        hasher.update(&hash_f);
        let hash_ef = hasher.finalize_reset();

        hasher.update(&hash_g);
        hasher.update(&hash_h);
        let hash_gh = hasher.finalize_reset();

        hasher.update(&hash_ab);
        hasher.update(&hash_cd);
        let hash_abcd = hasher.finalize_reset();

        hasher.update(&hash_ef);
        hasher.update(&hash_gh);
        let hash_efgh = hasher.finalize_reset();

        hasher.update(&hash_abcd);
        hasher.update(&hash_efgh);
        let expected_root = hasher.finalize();

        let expected_proof = vec![
            MerkleProof::new(hash_b.into(), true),
            MerkleProof::new(hash_cd.into(), true),
            MerkleProof::new(hash_efgh.into(), true),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_proof_consistency_same_index() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D", "E"]);
        let proof1 = tree.generate_merkle_proof(2);
        let proof2 = tree.generate_merkle_proof(2);

        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");
        let hash_c = Sha256::digest(b"C");
        let hash_d = Sha256::digest(b"D");
        let hash_e = Sha256::digest(b"E");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let hash_ab = hasher.finalize_reset();

        hasher.update(&hash_c);
        hasher.update(&hash_d);
        let hash_cd = hasher.finalize_reset();

        hasher.update(&hash_e);
        hasher.update(&hash_e);
        let hash_ee = hasher.finalize_reset();

        hasher.update(&hash_ab);
        hasher.update(&hash_cd);
        let hash_abcd = hasher.finalize_reset();

        hasher.update(&hash_ee);
        hasher.update(&hash_ee);
        let hash_eeee = hasher.finalize_reset();

        hasher.update(&hash_abcd);
        hasher.update(&hash_eeee);
        let expected_root = hasher.finalize();

        let expected_proof = vec![
            MerkleProof::new(hash_d.into(), true),
            MerkleProof::new(hash_ab.into(), false),
            MerkleProof::new(hash_eeee.into(), true),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof1, expected_proof);
        assert_eq!(proof2, expected_proof);
    }

    #[test]
    fn test_proof_different_for_different_indices() {
        let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
        let proof0 = tree.generate_merkle_proof(0);
        let proof1 = tree.generate_merkle_proof(1);

        let hash_a = Sha256::digest(b"A");
        let hash_b = Sha256::digest(b"B");
        let hash_c = Sha256::digest(b"C");
        let hash_d = Sha256::digest(b"D");

        let mut hasher = Sha256::new();
        hasher.update(&hash_a);
        hasher.update(&hash_b);
        let hash_ab = hasher.finalize_reset();

        hasher.update(&hash_c);
        hasher.update(&hash_d);
        let hash_cd = hasher.finalize_reset();

        hasher.update(&hash_ab);
        hasher.update(&hash_cd);
        let expected_root = hasher.finalize();

        let expected_proof0 = vec![
            MerkleProof::new(hash_b.into(), true),
            MerkleProof::new(hash_cd.into(), true),
            MerkleProof::new(expected_root.into(), false),
        ];

        let expected_proof1 = vec![
            MerkleProof::new(hash_a.into(), false),
            MerkleProof::new(hash_cd.into(), true),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof0, expected_proof0);
        assert_eq!(proof1, expected_proof1);
        assert_ne!(proof0, proof1);
    }

    #[test]
    fn test_proof_for_large_tree() {
        let data: Vec<&str> = vec!["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P"];
        let tree = MerkleTree::new(data);
        let proof = tree.generate_merkle_proof(0);

        let h = |s: &[u8]| Sha256::digest(s);
        let mut hasher = Sha256::new();

        hasher.update(&h(b"A"));
        hasher.update(&h(b"B"));
        let h_ab = hasher.finalize_reset();

        hasher.update(&h(b"C"));
        hasher.update(&h(b"D"));
        let h_cd = hasher.finalize_reset();

        hasher.update(&h(b"E"));
        hasher.update(&h(b"F"));
        let h_ef = hasher.finalize_reset();

        hasher.update(&h(b"G"));
        hasher.update(&h(b"H"));
        let h_gh = hasher.finalize_reset();

        hasher.update(&h(b"I"));
        hasher.update(&h(b"J"));
        let h_ij = hasher.finalize_reset();

        hasher.update(&h(b"K"));
        hasher.update(&h(b"L"));
        let h_kl = hasher.finalize_reset();

        hasher.update(&h(b"M"));
        hasher.update(&h(b"N"));
        let h_mn = hasher.finalize_reset();

        hasher.update(&h(b"O"));
        hasher.update(&h(b"P"));
        let h_op = hasher.finalize_reset();

        hasher.update(&h_ab);
        hasher.update(&h_cd);
        let h_abcd = hasher.finalize_reset();

        hasher.update(&h_ef);
        hasher.update(&h_gh);
        let h_efgh = hasher.finalize_reset();

        hasher.update(&h_ij);
        hasher.update(&h_kl);
        let h_ijkl = hasher.finalize_reset();

        hasher.update(&h_mn);
        hasher.update(&h_op);
        let h_mnop = hasher.finalize_reset();

        hasher.update(&h_abcd);
        hasher.update(&h_efgh);
        let h_abcdefgh = hasher.finalize_reset();

        hasher.update(&h_ijkl);
        hasher.update(&h_mnop);
        let h_ijklmnop = hasher.finalize_reset();

        hasher.update(&h_abcdefgh);
        hasher.update(&h_ijklmnop);
        let expected_root = hasher.finalize();

        let expected_proof = vec![
            MerkleProof::new(h(b"B").into(), true),
            MerkleProof::new(h_cd.into(), true),
            MerkleProof::new(h_efgh.into(), true),
            MerkleProof::new(h_ijklmnop.into(), true),
            MerkleProof::new(expected_root.into(), false),
        ];

        assert_eq!(proof, expected_proof);
    }
    
}
