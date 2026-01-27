use std::error::Error;

#[derive(Debug)]
pub enum MerkleError {
    IndexOutOfBounds,
    EmptyTree,
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MerkleError::IndexOutOfBounds => write!(f, "Index out of bounds"),
            MerkleError::EmptyTree => write!(f, "Empty tree"),
        }
    }
}

impl Error for MerkleError {}
