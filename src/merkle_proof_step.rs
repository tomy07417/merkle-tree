use sha2::{Digest, Sha256};

/// A single step in a Merkle inclusion proof.
///
/// `hash` is the sibling hash at this level, and `side` indicates whether the
/// current hash is on the left (`false`) or right (`true`) when hashing.
#[derive(Debug)]
pub struct MerkleProofStep {
    pub hash: [u8; 32],
    pub side: bool,
}

impl MerkleProofStep {
    /// Creates a new proof step with the given hash and side.
    pub fn new(hash: [u8; 32], side: bool) -> Self {
        MerkleProofStep { hash, side }
    }

    /// Returns the sibling hash for this step.
    pub fn get_hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Returns the side flag for this step.
    ///
    /// `true` means the current hash is on the right when hashing.
    pub fn get_side(&self) -> bool {
        self.side
    }

    /// Returns `true` if `other_hash` matches this step's hash.
    pub fn compare_hash(&self, other_hash: [u8; 32]) -> bool {
        self.hash == other_hash
    }

    /// Computes the parent hash for this step given the current hash.
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
