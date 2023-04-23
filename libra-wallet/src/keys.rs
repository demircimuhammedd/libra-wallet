//! generate keys for V7 forward with vendor specific keygen

// In libra we have a very specific key generation process that is not compatible with BIP-44. It's a similar HKDF. Any wallet will need to implement
// our key gen process, which is quite simple if you are already using BIP-44. 
// Different from vendor, we prioritize making the mnemonic seed known to all users, and then derive all possible keys from there. Currently this applies to ed25519 keys. Vendor's keygen also includes BLS keys, which are used specifically for consensus. As such those are not relevant to end-user account holders.

use ol_keys::wallet;
use zapatos_types::transaction::authenticator::AuthenticationKey;
use zapatos_crypto::{
  bls12381,
  ed25519::Ed25519PrivateKey, x25519,
};

use zapatos_genesis::keys::{
  PublicIdentity,
  PrivateIdentity,  
};
use zapatos_config::{
  config::IdentityBlob,
  keys::ConfigKey,
};
use zapatos_crypto::traits::PrivateKey;
// use zapatos_genesis::keys::PublicIdentity;
// use zapatos_keygen::KeyGen;

use crate::utils::*;
use anyhow::anyhow;
use crate::legacy::LegacyKeys;
use std::path::PathBuf;

const PRIVATE_KEYS_FILE: &str = "private-keys.yaml";
pub const PUBLIC_KEYS_FILE: &str = "public-keys.yaml";
const VALIDATOR_FILE: &str = "validator-identity.yaml";
const VFN_FILE: &str = "validator-full-node-identity.yaml";

// NOTE: Devs: this is copied from zapatos_genesis::keys::generate_key_objects()  and modified to use our legacy keygen process.
pub fn validator_keygen(output_opt: Option<PathBuf>) ->  anyhow::Result<()>{



        let output_dir = dir_default_to_current(&output_opt)?;

        let private_keys_file = output_dir.join(PRIVATE_KEYS_FILE);
        let public_keys_file = output_dir.join(PUBLIC_KEYS_FILE);
        let validator_file = output_dir.join(VALIDATOR_FILE);
        let vfn_file = output_dir.join(VFN_FILE);
        check_if_file_exists(private_keys_file.as_path())?;
        check_if_file_exists(public_keys_file.as_path())?;
        check_if_file_exists(validator_file.as_path())?;
        check_if_file_exists(vfn_file.as_path())?;

        let (_auth_key, _account, wallet, _mnem) = wallet::keygen();
        let legacy_keys = LegacyKeys::new(&wallet)?;
        
        let (validator_blob, vfn_blob, private_identity, public_identity) = generate_key_objects_from_legacy(legacy_keys)?;

        // Create the directory if it doesn't exist
        create_dir_if_not_exist(output_dir.as_path())?;

        write_to_user_only_file(
            private_keys_file.as_path(),
            PRIVATE_KEYS_FILE,
            to_yaml(&private_identity)?.as_bytes(),
        )?;
        write_to_user_only_file(
            public_keys_file.as_path(),
            PUBLIC_KEYS_FILE,
            to_yaml(&public_identity)?.as_bytes(),
        )?;
        write_to_user_only_file(
            validator_file.as_path(),
            VALIDATOR_FILE,
            to_yaml(&validator_blob)?.as_bytes(),
        )?;
        write_to_user_only_file(vfn_file.as_path(), VFN_FILE, to_yaml(&vfn_blob)?.as_bytes())?;

        Ok(())
    }





/// Generates objects used for a user in genesis
pub fn generate_key_objects_from_legacy(
    legacy_keys: LegacyKeys,
) -> anyhow::Result<(IdentityBlob, IdentityBlob, PrivateIdentity, PublicIdentity)> {
    
    // let account_key = ConfigKey::new(keygen.generate_ed25519_private_key());
    let account_key: ConfigKey<Ed25519PrivateKey> = ConfigKey::from_encoded_string(&legacy_keys.child_0_owner.pri_key)?;

    // consensus key needs to be generated anew as it is not part of the legacy keys
    // let keygen = KeyGen::from_os_rng();
    let consensus_key = ConfigKey::new(bls_generate_key(&legacy_keys.seed)?);

    let vnk = network_keys_x25519_from_ed25519(&legacy_keys.child_2_val_network.pri_key)?;
    let validator_network_key = ConfigKey::new(vnk);


    let fnk = network_keys_x25519_from_ed25519(&legacy_keys.child_3_fullnode_network.pri_key)?;

    let full_node_network_key = ConfigKey::new(fnk);

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

    // todo!("legacy keys");
    Ok((validator_blob, vfn_blob, private_identity, public_identity))
}

/// Testing deterministic hkdf for bls

fn bls_generate_key(ikm: &[u8]) -> anyhow::Result<bls12381::PrivateKey> {
  let priv_key = blst::min_pk::SecretKey::key_gen(ikm, &[])
    .map_err(|e| anyhow!("blst key gen failed: {:?}", e))?;

    let serialized: &[u8] = &priv_key.to_bytes();

    Ok(bls12381::PrivateKey::try_from(serialized)?)
    // .map_err(|e| anyhow!("bls private key from bytes failed: {:?}", e))
}

/// get a network key in x25519 format from a ed25519 key
pub fn network_keys_x25519_from_ed25519(pri_key_str: &str) -> anyhow::Result<x25519::PrivateKey>{
    let pri_key_bytes = hex::decode(pri_key_str)?;
    let key = x25519::PrivateKey::from_ed25519_private_bytes(&pri_key_bytes)?;
    Ok(key)
}

#[test]
// checks we can get deterministic bls keys from the seed from mnemonic.
fn deterministic_bls_from_seed() {
  use crate::keys::wallet::get_account_from_mnem;
  use zapatos_crypto::ValidCryptoMaterialStringExt;
  use crate::legacy::get_keys_from_mnem;

  let alice_mnem = "talent sunset lizard pill fame nuclear spy noodle basket okay critic grow sleep legend hurry pitch blanket clerk impose rough degree sock insane purse";
  let (_auth_key, _account, wallet) = get_account_from_mnem(alice_mnem.to_owned()).unwrap();

  let seed = wallet.get_key_factory().main();
  let l = get_keys_from_mnem(alice_mnem.to_string()).unwrap();
  assert!(seed == &l.seed);

  let prk1 = bls_generate_key(seed).unwrap();
  let prk2 = bls_generate_key(seed).unwrap();
  let prk3 = bls_generate_key(seed).unwrap();
  assert!(prk1.to_encoded_string().unwrap() == prk2.to_encoded_string().unwrap());
  assert!(prk2.to_encoded_string().unwrap() == prk3.to_encoded_string().unwrap());
}