use crate::merkle_proof::MerkleProof;
use crate::merkle_proof_step::MerkleProofStep;
use crate::merkle_tree::MerkleTree;

use sha2::{Digest, Sha256};

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
    let proof = tree.generate_merkle_proof(0).unwrap();

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

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(hash_b.into(), true),
        MerkleProofStep::new(hash_cd.into(), true),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof.len(), 3);
    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_for_single_leaf() {
    let tree = MerkleTree::new(vec!["A"]);
    let proof = tree.generate_merkle_proof(0).unwrap();

    let expected_root = Sha256::digest(b"A");

    let expected_proof = MerkleProof::new(vec![MerkleProofStep::new(expected_root.into(), false)]);

    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_for_two_leaves_left_node() {
    let tree = MerkleTree::new(vec!["A", "B"]);
    let proof = tree.generate_merkle_proof(0).unwrap();

    let hash_a = Sha256::digest(b"A");
    let hash_b = Sha256::digest(b"B");

    let mut hasher = Sha256::new();
    hasher.update(&hash_a);
    hasher.update(&hash_b);
    let expected_root = hasher.finalize();

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(hash_b.into(), true),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_for_two_leaves_right_node() {
    let tree = MerkleTree::new(vec!["A", "B"]);
    let proof = tree.generate_merkle_proof(1).unwrap();

    let hash_a = Sha256::digest(b"A");
    let hash_b = Sha256::digest(b"B");

    let mut hasher = Sha256::new();
    hasher.update(&hash_a);
    hasher.update(&hash_b);
    let expected_root = hasher.finalize();

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(hash_a.into(), false),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_for_odd_leaves_last_node() {
    let tree = MerkleTree::new(vec!["A", "B", "C"]);
    let proof = tree.generate_merkle_proof(2).unwrap();

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

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(hash_c.into(), false),
        MerkleProofStep::new(hash_ab.into(), false),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert!(proof.len() > 0);
    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_for_odd_leaves_first_node() {
    let tree = MerkleTree::new(vec!["A", "B", "C"]);
    let proof = tree.generate_merkle_proof(0).unwrap();

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

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(hash_b.into(), true),
        MerkleProofStep::new(hash_cc.into(), true),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_length_matches_tree_depth() {
    let tree = MerkleTree::new(vec!["A", "B", "C", "D", "E", "F", "G", "H"]);
    let proof = tree.generate_merkle_proof(0).unwrap();

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

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(hash_b.into(), true),
        MerkleProofStep::new(hash_cd.into(), true),
        MerkleProofStep::new(hash_efgh.into(), true),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_consistency_same_index() {
    let tree = MerkleTree::new(vec!["A", "B", "C", "D", "E"]);
    let proof1 = tree.generate_merkle_proof(2).unwrap();
    let proof2 = tree.generate_merkle_proof(2).unwrap();

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

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(hash_d.into(), true),
        MerkleProofStep::new(hash_ab.into(), false),
        MerkleProofStep::new(hash_eeee.into(), true),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof1, expected_proof);
    assert_eq!(proof2, expected_proof);
}

#[test]
fn test_proof_different_for_different_indices() {
    let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
    let proof0 = tree.generate_merkle_proof(0).unwrap();
    let proof1 = tree.generate_merkle_proof(1).unwrap();

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

    let expected_proof0 = MerkleProof::new(vec![
        MerkleProofStep::new(hash_b.into(), true),
        MerkleProofStep::new(hash_cd.into(), true),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    let expected_proof1 = MerkleProof::new(vec![
        MerkleProofStep::new(hash_a.into(), false),
        MerkleProofStep::new(hash_cd.into(), true),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof0, expected_proof0);
    assert_eq!(proof1, expected_proof1);
    assert_ne!(proof0, proof1);
}

#[test]
fn test_proof_for_large_tree() {
    let data: Vec<&str> = vec![
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
    ];
    let tree = MerkleTree::new(data);
    let proof = tree.generate_merkle_proof(0).unwrap();

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

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(h(b"B").into(), true),
        MerkleProofStep::new(h_cd.into(), true),
        MerkleProofStep::new(h_efgh.into(), true),
        MerkleProofStep::new(h_ijklmnop.into(), true),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_for_index_out_of_bounds() {
    let tree = MerkleTree::new(vec!["A", "B", "C"]);
    let result = tree.generate_merkle_proof(5);

    assert!(result.is_err());
}

#[test]
fn test_proof_for_middle_element_odd_tree() {
    let tree = MerkleTree::new(vec!["A", "B", "C", "D", "E"]);
    let proof = tree.generate_merkle_proof(1).unwrap();

    assert!(proof.len() > 0);
}

#[test]
fn test_tree_with_identical_leaves() {
    let tree1 = MerkleTree::new(vec!["A", "A", "A", "A"]);
    let tree2 = MerkleTree::new(vec!["A", "A", "A", "A"]);

    assert_eq!(tree1.get_root(), tree2.get_root());
}

#[test]
fn test_tree_with_different_data_types() {
    let data1: Vec<&[u8]> = vec![b"hello", b"world"];
    let tree1 = MerkleTree::new(data1);

    let data2: Vec<String> = vec!["hello".to_string(), "world".to_string()];
    let tree2 = MerkleTree::new(data2);

    assert_eq!(tree1.get_root(), tree2.get_root());
}

#[test]
fn test_proof_for_last_element_even_tree() {
    let tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
    let proof = tree.generate_merkle_proof(3).unwrap();

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

    let expected_proof = MerkleProof::new(vec![
        MerkleProofStep::new(hash_c.into(), false),
        MerkleProofStep::new(hash_ab.into(), false),
        MerkleProofStep::new(expected_root.into(), false),
    ]);

    assert_eq!(proof, expected_proof);
}

#[test]
fn test_proof_for_middle_indices() {
    let tree = MerkleTree::new(vec!["A", "B", "C", "D", "E", "F", "G", "H"]);

    let proof_3 = tree.generate_merkle_proof(3);
    let proof_4 = tree.generate_merkle_proof(4);

    assert!(proof_3.is_ok());
    assert!(proof_4.is_ok());
    assert_ne!(proof_3.unwrap(), proof_4.unwrap());
}

#[test]
fn test_seven_leaves_tree() {
    let tree = MerkleTree::new(vec!["A", "B", "C", "D", "E", "F", "G"]);
    let root = tree.get_root();

    assert!(root.is_some());

    for i in 0..7 {
        let proof = tree.generate_merkle_proof(i);
        assert!(proof.is_ok(), "Proof for index {} should succeed", i);
    }
}

#[test]
fn test_large_odd_tree() {
    let data: Vec<String> = (0..15).map(|i| format!("data_{}", i)).collect();
    let tree = MerkleTree::new(data);

    let root = tree.get_root();
    assert!(root.is_some());

    let proof_first = tree.generate_merkle_proof(0);
    let proof_last = tree.generate_merkle_proof(14);

    assert!(proof_first.is_ok());
    assert!(proof_last.is_ok());
    assert_ne!(proof_first.unwrap(), proof_last.unwrap());
}

#[test]
fn test_tree_with_binary_data() {
    let data: Vec<Vec<u8>> = vec![vec![0, 1, 2, 3], vec![4, 5, 6, 7], vec![8, 9, 10, 11]];
    let tree = MerkleTree::new(data);

    assert!(tree.get_root().is_some());
}

#[test]
fn test_proof_verification_path_length() {
    let tree_2 = MerkleTree::new(vec!["A", "B"]);
    let tree_4 = MerkleTree::new(vec!["A", "B", "C", "D"]);
    let tree_8 = MerkleTree::new(vec!["A", "B", "C", "D", "E", "F", "G", "H"]);

    let proof_2 = tree_2.generate_merkle_proof(0).unwrap();
    let proof_4 = tree_4.generate_merkle_proof(0).unwrap();
    let proof_8 = tree_8.generate_merkle_proof(0).unwrap();

    // Proof length should increase with tree depth
    assert!(proof_2.len() < proof_4.len());
    assert!(proof_4.len() < proof_8.len());
}

#[test]
fn test_push_single_element_to_tree() {
    let mut tree = MerkleTree::new(vec!["A", "B"]);
    let root_before = tree.get_root().unwrap();

    tree.push(vec!["C"]);
    let root_after = tree.get_root().unwrap();

    // Root should change after insertion
    assert_ne!(root_before, root_after);

    // Tree should have 3 leaves now
    let expected_tree = MerkleTree::new(vec!["A", "B", "C"]);
    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_push_multiple_elements() {
    let mut tree = MerkleTree::new(vec!["A", "B"]);
    tree.push(vec!["C", "D"]);

    let expected_tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_push_to_empty_tree() {
    let mut tree = MerkleTree::new::<&str>(vec![]);
    tree.push(vec!["A", "B"]);

    let expected_tree = MerkleTree::new(vec!["A", "B"]);
    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_push_to_single_leaf_tree() {
    let mut tree = MerkleTree::new(vec!["A"]);
    tree.push(vec!["B"]);

    let expected_tree = MerkleTree::new(vec!["A", "B"]);
    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_push_to_odd_number_tree() {
    let mut tree = MerkleTree::new(vec!["A", "B", "C"]);
    tree.push(vec!["D"]);

    let expected_tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_push_multiple_times() {
    let mut tree = MerkleTree::new(vec!["A"]);
    tree.push(vec!["B"]);
    tree.push(vec!["C"]);
    tree.push(vec!["D"]);

    let expected_tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_push_large_batch() {
    let mut tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
    tree.push(vec!["E", "F", "G", "H", "I", "J", "K", "L"]);

    let expected_tree = MerkleTree::new(vec!["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L"]);
    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_proof_after_push() {
    let mut tree = MerkleTree::new(vec!["A", "B"]);
    tree.push(vec!["C", "D"]);

    // Generate proof for original element
    let proof_a = tree.generate_merkle_proof(0);
    assert!(proof_a.is_ok());

    // Generate proof for newly added element
    let proof_d = tree.generate_merkle_proof(3);
    assert!(proof_d.is_ok());

    // Verify proofs work correctly
    let leaf_hash_a = Sha256::digest(b"A");
    let leaf_hash_d = Sha256::digest(b"D");
    
    assert!(proof_a.unwrap().verify(leaf_hash_a.into()));
    assert!(proof_d.unwrap().verify(leaf_hash_d.into()));
}

#[test]
fn test_push_maintains_tree_validity() {
    let mut tree = MerkleTree::new(vec!["A", "B", "C"]);
    tree.push(vec!["D", "E"]);

    // All indices should generate valid proofs
    for i in 0..5 {
        let proof = tree.generate_merkle_proof(i);
        assert!(proof.is_ok(), "Proof generation failed for index {}", i);
    }
}

#[test]
fn test_push_root_changes_correctly() {
    let mut tree = MerkleTree::new(vec!["A", "B", "C", "D"]);
    
    let root1 = tree.get_root().unwrap();
    tree.push(vec!["E"]);
    let root2 = tree.get_root().unwrap();
    tree.push(vec!["F"]);
    let root3 = tree.get_root().unwrap();

    // Each push should produce a different root
    assert_ne!(root1, root2);
    assert_ne!(root2, root3);
    assert_ne!(root1, root3);
}

#[test]
fn test_push_with_binary_data() {
    let mut tree = MerkleTree::new(vec![vec![0u8, 1, 2], vec![3, 4, 5]]);
    tree.push(vec![vec![6, 7, 8], vec![9, 10, 11]]);

    let expected_tree = MerkleTree::new(vec![
        vec![0u8, 1, 2],
        vec![3, 4, 5],
        vec![6, 7, 8],
        vec![9, 10, 11],
    ]);

    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_push_identical_elements() {
    let mut tree = MerkleTree::new(vec!["A", "A"]);
    tree.push(vec!["A", "A"]);

    let expected_tree = MerkleTree::new(vec!["A", "A", "A", "A"]);
    assert_eq!(tree.get_root(), expected_tree.get_root());
}

#[test]
fn test_push_empty_batch() {
    let mut tree = MerkleTree::new(vec!["A", "B", "C"]);
    let root_before = tree.get_root().unwrap();
    
    tree.push::<&str>(vec![]);
    let root_after = tree.get_root().unwrap();

    // Root should remain the same when pushing empty batch
    assert_eq!(root_before, root_after);
}

#[test]
fn test_push_builds_balanced_tree() {
    let mut tree = MerkleTree::new(vec!["A", "B"]);
    tree.push(vec!["C", "D", "E", "F"]);

    // Verify that proofs for all indices work
    let data = vec!["A", "B", "C", "D", "E", "F"];
    for (i, item) in data.iter().enumerate() {
        let proof = tree.generate_merkle_proof(i).unwrap();
        let leaf_hash = Sha256::digest(item.as_bytes());
        assert!(
            proof.verify(leaf_hash.into()),
            "Proof verification failed for index {} after push",
            i
        );
    }
}
