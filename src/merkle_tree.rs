use sha2::{Sha256, Digest};

type Hash = [u8; 32]; 

pub struct MerkleTree {
    layers: Vec<Vec<Hash>>
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree {
            layers: Vec::new()
        }
    }

    pub fn get_root(&self) -> Option<Hash> {
        self.layers.last().and_then(|layer| layer.first().cloned())
    }

}

mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new();
        assert!(tree.get_root().is_none());
    }
}