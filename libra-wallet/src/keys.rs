//! generate keys for V7 forward with vendor specific keygen

// In libra we have a very specific key generation process that is not compatible with BIP-44. It's a similar HKDF. Any wallet will need to implement
// our key gen process, which is quite simple if you are already using BIP-44. 

// Different from vendor, we prioritize making the mnemonic seed known to all users, and then derive all possible keys from there. Currently this applies to ed25519 keys. Vendor's keygen also includes BLS keys, which are used specifically for consensus. As such those are not relevant to end-user account holders.
use zapatos_types::transaction::authenticator::AuthenticationKey;
use zapatos_crypto::bls12381;

use zapatos_genesis::keys::{
  // generate_key_objects,
  PublicIdentity,
  PrivateIdentity,
  // IdentityBlob,
  
};
use zapatos_config::{
  config::IdentityBlob,
  keys::ConfigKey,
};
use zapatos_crypto::traits::PrivateKey;
// use zapatos_genesis::keys::PublicIdentity;
use zapatos_keygen::KeyGen;
use std::{
  path::Path,
//   fs::OpenOptions,
//   os::unix::fs::OpenOptionsExt,
//   io::Write,
};

// const PRIVATE_KEYS_FILE: &str = "private-keys.yaml";
// pub const PUBLIC_KEYS_FILE: &str = "public-keys.yaml";
// const VALIDATOR_FILE: &str = "validator-identity.yaml";
// const VFN_FILE: &str = "validator-full-node-identity.yaml";

pub fn validator_keygen() ->  anyhow::Result<()>{
        // // let output_dir = dir_default_to_current(self.output_dir.clone())?;

        // let private_keys_file = output_dir.join(PRIVATE_KEYS_FILE);
        // let public_keys_file = output_dir.join(PUBLIC_KEYS_FILE);
        // let validator_file = output_dir.join(VALIDATOR_FILE);
        // let vfn_file = output_dir.join(VFN_FILE);
        // // check_if_file_exists(private_keys_file.as_path(), self.prompt_options)?;
        // // check_if_file_exists(public_keys_file.as_path(), self.prompt_options)?;
        // // check_if_file_exists(validator_file.as_path(), self.prompt_options)?;
        // // check_if_file_exists(vfn_file.as_path(), self.prompt_options)?;

        let mut key_generator = KeyGen::from_os_rng();
        let (mut validator_blob, mut _vfn_blob, _private_identity, _public_identity) =
            generate_key_objects(&mut key_generator)?;

        dbg!(&validator_blob.account_address);
        // // Allow for the owner to be different than the operator
        // if let Some(pool_address) = self.pool_address_args.pool_address {
        //     validator_blob.account_address = Some(pool_address);
        //     vfn_blob.account_address = Some(pool_address);
        // }

        // // Create the directory if it doesn't exist
        // create_dir_if_not_exist(output_dir.as_path())?;

        // write_to_user_only_file(
        //     private_keys_file.as_path(),
        //     PRIVATE_KEYS_FILE,
        //     to_yaml(&private_identity)?.as_bytes(),
        // )?;
        // write_to_user_only_file(
        //     public_keys_file.as_path(),
        //     PUBLIC_KEYS_FILE,
        //     to_yaml(&public_identity)?.as_bytes(),
        // )?;
        // write_to_user_only_file(
        //     validator_file.as_path(),
        //     VALIDATOR_FILE,
        //     to_yaml(&validator_blob)?.as_bytes(),
        // )?;
        // write_to_user_only_file(vfn_file.as_path(), VFN_FILE, to_yaml(&vfn_blob)?.as_bytes())?;

        Ok(())
    }


// /// Write a User only read / write file
// pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
//     let mut opts = OpenOptions::new();
//     #[cfg(unix)]
//     opts.mode(0o600);
//     write_to_file_with_opts(path, name, bytes, &mut opts)
// }

// /// Write a `&[u8]` to a file with the given options
// pub fn write_to_file_with_opts(
//     path: &Path,
//     name: &str,
//     bytes: &[u8],
//     opts: &mut OpenOptions,
// ) -> anyhow::Result<()> {
//     let mut file = opts
//         .write(true)
//         .create(true)
//         .truncate(true)
//         .open(path)?;
//         // .map_err(|e| CliError::IO(name.to_string(), e))?;
//     Ok(file.write_all(bytes)?)
//         // .map_err(|e| CliError::IO(name.to_string(), e))
// }


/// Generates objects used for a user in genesis
pub fn generate_key_objects(
    keygen: &mut KeyGen,
) -> anyhow::Result<(IdentityBlob, IdentityBlob, PrivateIdentity, PublicIdentity)> {
    let account_key = ConfigKey::new(keygen.generate_ed25519_private_key());
    let consensus_key = ConfigKey::new(keygen.generate_bls12381_private_key());
    let validator_network_key = ConfigKey::new(keygen.generate_x25519_private_key()?);
    let full_node_network_key = ConfigKey::new(keygen.generate_x25519_private_key()?);

    let account_address = AuthenticationKey::ed25519(&account_key.public_key()).derived_address();

    // Build these for use later as node identity
    let validator_blob = IdentityBlob {
        account_address: Some(account_address),
        account_private_key: Some(account_key.private_key()),
        consensus_private_key: Some(consensus_key.private_key()),
        network_private_key: validator_network_key.private_key(),
    };
    let vfn_blob = IdentityBlob {
        account_address: Some(account_address),
        account_private_key: None,
        consensus_private_key: None,
        network_private_key: full_node_network_key.private_key(),
    };

    let private_identity = PrivateIdentity {
        account_address,
        account_private_key: account_key.private_key(),
        consensus_private_key: consensus_key.private_key(),
        full_node_network_private_key: full_node_network_key.private_key(),
        validator_network_private_key: validator_network_key.private_key(),
    };

    let public_identity = PublicIdentity {
        account_address,
        account_public_key: account_key.public_key(),
        consensus_public_key: Some(private_identity.consensus_private_key.public_key()),
        consensus_proof_of_possession: Some(bls12381::ProofOfPossession::create(
            &private_identity.consensus_private_key,
        )),
        full_node_network_public_key: Some(full_node_network_key.public_key()),
        validator_network_public_key: Some(validator_network_key.public_key()),
    };

    Ok((validator_blob, vfn_blob, private_identity, public_identity))
}
