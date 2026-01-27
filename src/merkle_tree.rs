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

    pub fn build_layer(previous_layer: &[Hash]) -> Vec<Hash> {
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
}
