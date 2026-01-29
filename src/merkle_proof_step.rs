use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct MerkleProofStep {
    pub hash: [u8; 32],
    pub side: bool,
}

impl MerkleProofStep {
    pub fn new(hash: [u8; 32], side: bool) -> Self {
        MerkleProofStep { hash, side }
    }

    pub fn get_hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn get_side(&self) -> bool {
        self.side
    }

    pub fn compare_hash(&self, other_hash: [u8; 32]) -> bool {
        self.hash == other_hash
    }

    pub fn generate_hash(&self, hash: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();

        if self.side {
            // Right side
            hasher.update(hash);
            hasher.update(self.hash);
        } else {
            // Left side
            hasher.update(self.hash);
            hasher.update(hash);
        }

        hasher.finalize().into()
    }
}

impl PartialEq for MerkleProofStep {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.side == other.side
    }
}
