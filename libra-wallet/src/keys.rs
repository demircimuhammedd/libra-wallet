//! generate keys for V7 forward with vendor specific keygen

// In libra we have a very specific key generation process that is not compatible with BIP-44. It's a similar HKDF. Any wallet will need to implement
// our key gen process, which is quite simple if you are already using BIP-44. 

// Different from vendor, we prioritize making the mnemonic seed known to all users, and then derive all possible keys from there. Currently this applies to ed25519 keys. Vendor's keygen also includes BLS keys, which are used specifically for consensus. As such those are not relevant to end-user account holders.

use zapatos_genesis::keys::generate_key_objects;
use zapatos_keygen::KeyGen;

pub fn validator_keygen() ->  anyhow::Result<()>{
        // let output_dir = dir_default_to_current(self.output_dir.clone())?;

        // let private_keys_file = output_dir.join(PRIVATE_KEYS_FILE);
        // let public_keys_file = output_dir.join(PUBLIC_KEYS_FILE);
        // let validator_file = output_dir.join(VALIDATOR_FILE);
        // let vfn_file = output_dir.join(VFN_FILE);
        // check_if_file_exists(private_keys_file.as_path(), self.prompt_options)?;
        // check_if_file_exists(public_keys_file.as_path(), self.prompt_options)?;
        // check_if_file_exists(validator_file.as_path(), self.prompt_options)?;
        // check_if_file_exists(vfn_file.as_path(), self.prompt_options)?;

        let mut key_generator = KeyGen::from_os_rng();
        let (mut validator_blob, mut vfn_blob, private_identity, public_identity) =
            generate_key_objects(&mut key_generator)?;

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