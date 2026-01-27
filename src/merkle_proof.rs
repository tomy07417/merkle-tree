#[derive(Debug)]
pub struct MerkleProof {
    pub hash: [u8; 32],
    pub side: bool,
}

impl MerkleProof {
    pub fn new(hash: [u8; 32], side: bool) -> Self {
        MerkleProof { hash, side }
    }

    pub fn get_hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn get_side(&self) -> bool {
        self.side
    }
}

impl PartialEq for MerkleProof {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.side == other.side
    }
}
