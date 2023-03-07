use dep::std;

global LEVELS = 20;
global EXPECTED_VALUE = 11954255677048767585730959529592939615262310191150853775895456173962480955685; // keccak256("allowed") % p

fn main(
    root : pub Field,
    subset_root : pub Field,
    nullifier : pub Field,
    asset_metadata : pub Field,
    withdraw_metadata : pub Field,
    secret : Field,
    path : Field,
    main_proof : [Field; LEVELS],
    subset_proof : [Field; LEVELS]
) -> pub Field {
    // Check nullifier
    let hasher = commitment_nullifier_hasher(secret, path, asset_metadata);
    constrain hasher[0] == nullifier;

    let double_tree = double_merkle_proof(hasher[1], path, main_proof, subset_proof);
    constrain double_tree[0] == root;
    constrain double_tree[1] == subset_root;

    withdraw_metadata
}

fn commitment_nullifier_hasher(
    secret : Field,
    path : Field,
    asset_metadata : Field
) -> [Field; 2] {
    // TODO: ameen uses poseidon to hash but noir does not support it yet
    let secret_hash = std::hash::pedersen([secret]);

    let commitment = std::hash::pedersen([secret_hash[0], asset_metadata]);

    let nullifier = std::hash::pedersen([secret, 1, path]);
    
    [nullifier[0], commitment[0]]
}

fn double_merkle_proof(
    leaf : Field,
    path : Field,
    main_proof : [Field; LEVELS],
    subset_proof : [Field; LEVELS]
) -> [Field; 2] {
    let path_bits = path.to_le_bits(LEVELS as u32);
    let mut current_main = leaf;
    let mut current_subset = EXPECTED_VALUE;
    for i in 0..LEVELS {
        let path_bit = path_bits[i] as bool;
        let (hash_left_main, hash_right_main) = if path_bit {
            (main_proof[i], current_main)
        } else {
            (current_main, main_proof[i])
        };

        let (hash_left_subset, hash_right_subset) = if path_bit {
            (subset_proof[i], current_subset)
        } else {
            (current_subset, subset_proof[i])
        };

        current_main = std::hash::pedersen([hash_left_main, hash_right_main])[0];
        current_subset = std::hash::pedersen([hash_left_subset, hash_right_subset])[0];
    };
    [current_main, current_subset]
}

