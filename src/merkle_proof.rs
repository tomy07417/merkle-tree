
#[derive(Debug)]
pub struct MerkleProof {
    hash: [u8; 32],
    side: bool,
}

impl MerkleProof {
    pub fn new(hash: [u8; 32], side: bool) -> Self {
        MerkleProof { hash, side }
    }
}

impl PartialEq for MerkleProof {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.side == other.side
    }
}