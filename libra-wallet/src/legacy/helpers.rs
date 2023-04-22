//! Use ol-keys to generate or parse keys using the legacy key derivation scheme

use hex::encode;
use ol_keys::wallet::get_account_from_mnem;
use ol_keys::{scheme::KeyScheme, wallet::get_account_from_prompt};
use anyhow::Result;
use serde::Serialize;
use zapatos_types::transaction::authenticator::AuthenticationKey;
use zapatos_types::account_address::AccountAddress;
use std::str::FromStr;
use diem_wallet::WalletLibrary;
use std::path::PathBuf;

#[derive(Serialize)]
/// A Struct to store ALL the legacy keys for storage.
pub struct LegacyKeys {
  /// The main account address
  child_0_owner: AccountKeys,
  /// The operator account address
  child_1_operator: AccountKeys,
  /// The validator network identity
  child_2_val_network: AccountKeys,
  /// The fullnode network identity
  child_3_fullnode_network: AccountKeys,
  /// The consensus key
  child_4_consensus: AccountKeys,
  /// The execution key
  child_5_executor: AccountKeys,
}

/// The AccountAddress and AuthenticationKey are zapatos structs, they have the same NAME in the diem_types crate. So we need to cast them into usuable structs.
#[derive(Serialize)]
struct AccountKeys {
  account: AccountAddress,
  auth_key: AuthenticationKey,
  pri_key: String,
}


/// Get the legacy keys from the wallet
pub fn get_keys_from_prompt() -> Result<LegacyKeys> {
  let (_auth_key, _account, wallet) = get_account_from_prompt();
  LegacyKeys::new(&wallet)
}

/// for libs to get the keys from a mnemonic
pub fn get_keys_from_mnem(mnem: String) -> Result<LegacyKeys> {
  let (_auth_key, _account, wallet) = get_account_from_mnem(mnem)?;
  LegacyKeys::new(&wallet)
}

fn get_account_from_private_key(w: &WalletLibrary, n: u8) -> Result<AccountKeys> {
    let pri_keys = KeyScheme::new(&w);

    let key = match n {
      0 => pri_keys.child_0_owner,
      1 => pri_keys.child_1_operator,
      2 => pri_keys.child_2_val_network,
      3 => pri_keys.child_3_fullnode_network,
      4 => pri_keys.child_4_consensus,
      5 => pri_keys.child_5_executor,
      _ => panic!("Invalid key index"),
    };


    let auth_key = key.get_authentication_key();
    let account = key.get_address();
    Ok(AccountKeys {
      account: AccountAddress::from_hex_literal(&account.to_hex_literal())?,
      auth_key: AuthenticationKey::from_str(&auth_key.to_string())?,
      pri_key: encode(key.get_private_key().to_bytes()),
    })
}

impl LegacyKeys {
  pub fn new(w: &WalletLibrary) -> Result<Self>{
    Ok(
      LegacyKeys {
        child_0_owner: get_account_from_private_key(w, 0)?,
        child_1_operator: get_account_from_private_key(w, 1)?,
        child_2_val_network: get_account_from_private_key(w, 2)?,
        child_3_fullnode_network: get_account_from_private_key(w, 3)?,
        child_4_consensus: get_account_from_private_key(w, 4)?,
        child_5_executor: get_account_from_private_key(w, 5)?,
        
      }
    )

  }

  /// Save the legacy keys to a json file
  pub fn save_keys(&self, dir: &PathBuf) -> Result<()> {
    let json = serde_json::to_string_pretty(self)?;
    let path = dir.join("legacy_keys.json");
    std::fs::write(path, json)?;
    Ok(())
  }

  pub fn display(&self) {
    eprintln!("{}", serde_json::to_string_pretty(&self).unwrap());
  }
}




#[test]
fn test_legacy_keys() {
  let alice_mnem = "talent sunset lizard pill fame nuclear spy noodle basket okay critic grow sleep legend hurry pitch blanket clerk impose rough degree sock insane purse";

  let l = get_keys_from_mnem(alice_mnem.to_string()).unwrap();

  assert!(&l.child_0_owner.account.to_string() == "000000000000000000000000000000004c613c2f4b1e67ca8d98a542ee3f59f5");
}