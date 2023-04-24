use std::{env::current_dir, path::PathBuf};

use anyhow::bail;
use zapatos_genesis::config::{HostAndPort, OperatorConfiguration, OwnerConfiguration};

use crate::{keys::PUBLIC_KEYS_FILE, utils::read_public_identity_file};

pub const DEFAULT_VALIDATOR_DIR: &str = ".libra";
pub const OPERATOR_FILE: &str = "operator.yaml";
pub const OWNER_FILE: &str = "owner.yaml";

// copied from crate/aptos/src/genesis/keys.rs
pub struct SetValidatorConfiguration {
    /// Name of the validator
    pub username: String,

    /// Host and port pair for the validator e.g. 127.0.0.1:6180 or aptoslabs.com:6180
    pub validator_host: HostAndPort,

    /// Host and port pair for the fullnode e.g. 127.0.0.1:6180 or aptoslabs.com:6180
    pub full_node_host: Option<HostAndPort>,

    /// Path to private identity generated from GenerateKeys
    pub owner_public_identity_file: Option<PathBuf>,
}

impl Default for SetValidatorConfiguration {
    fn default() -> Self {
        let file = dirs::home_dir()
            .unwrap()
            .join(DEFAULT_VALIDATOR_DIR)
            .join(PUBLIC_KEYS_FILE);

        Self {
            username: "validator".to_string(),
            validator_host: HostAndPort::local(6180).unwrap(),
            full_node_host: None,
            owner_public_identity_file: Some(file),
            // operator_public_identity_file: None,
            // voter_public_identity_file: None,
        }
    }
}

impl SetValidatorConfiguration {
    pub fn set_config_files(self) -> anyhow::Result<()> {
        // Load owner
        let owner_keys_file = if let Some(owner_keys_file) = self.owner_public_identity_file {
            owner_keys_file
        } else {
            current_dir()?.join(PUBLIC_KEYS_FILE)
        };
        let owner_identity = read_public_identity_file(owner_keys_file.as_path())?;

        // // Load voter
        // let voter_identity = if let Some(voter_keys_file) = self.voter_public_identity_file {
        //     read_public_identity_file(voter_keys_file.as_path())?
        // } else {
        //     owner_identity.clone()
        // };

        let voter_identity = owner_identity.clone();

        // // Load operator
        // let (operator_identity, operator_keys_file) =
        //     if let Some(operator_keys_file) = self.operator_public_identity_file {
        //         (
        //             read_public_identity_file(operator_keys_file.as_path())?,
        //             operator_keys_file,
        //         )
        //     } else {
        //         (owner_identity.clone(), owner_keys_file)
        //     };

        let operator_identity = owner_identity.clone();
        let operator_keys_file = owner_keys_file;

        // Extract the possible optional fields
        let consensus_public_key =
            if let Some(consensus_public_key) = operator_identity.consensus_public_key {
                consensus_public_key
            } else {
                bail!(
                    "Failed to read consensus public key from public identity file {}",
                    operator_keys_file.display()
                );
            };

        let validator_network_public_key = if let Some(validator_network_public_key) =
            operator_identity.validator_network_public_key
        {
            validator_network_public_key
        } else {
            bail!(
                "Failed to read validator network public key from public identity file {}",
                operator_keys_file.display()
            );
        };

        let consensus_proof_of_possession = if let Some(consensus_proof_of_possession) =
            operator_identity.consensus_proof_of_possession
        {
            consensus_proof_of_possession
        } else {
            bail!(
                "Failed to read consensus proof of possession from public identity file {}",
                operator_keys_file.display()
            );
        };

        // Only add the public key if there is a full node
        let full_node_network_public_key = if self.full_node_host.is_some() {
            operator_identity.full_node_network_public_key
        } else {
            None
        };

        // Build operator configuration file
        let _operator_config = OperatorConfiguration {
            operator_account_address: operator_identity.account_address.into(),
            operator_account_public_key: operator_identity.account_public_key.clone(),
            consensus_public_key,
            consensus_proof_of_possession,
            validator_network_public_key,
            validator_host: self.validator_host,
            full_node_network_public_key,
            full_node_host: self.full_node_host,
        };

        let _owner_config = OwnerConfiguration {
            owner_account_address: owner_identity.account_address.into(),
            owner_account_public_key: owner_identity.account_public_key,
            voter_account_address: voter_identity.account_address.into(),
            voter_account_public_key: voter_identity.account_public_key,
            operator_account_address: operator_identity.account_address.into(),
            operator_account_public_key: operator_identity.account_public_key,
            stake_amount: 100_000_000_000_000,
            commission_percentage: 0,
            join_during_genesis: true,
        };

        let directory = PathBuf::from(&self.username);
        let _operator_file = directory.join(OPERATOR_FILE);
        let _owner_file = directory.join(OWNER_FILE);

        // let git_client = self.git_options.get_client()?;
        // git_client.put(operator_file.as_path(), &operator_config)?;
        // git_client.put(owner_file.as_path(), &owner_config)
        Ok(())
    }
}
