//! legacy key generation scheme for Libra wallets

// This legacy implementation is necessary for backwards compatibility with the old key generation scheme in 0L.
// Any legacy account, is an account generated prior to V7.
// Any account generated after V7, is derived using a BIP-44 wallet.
// We assume legacy users care about two things: their address, and their mnemonic string. However the mnemonic string when used in BIP-44 wallets, will generate a different private key (and authentication key). So we need to keep the legacy implementation around to generate the same private key as the old implementation. At a minimum users should be able to use the Legacy Diem key generation to rotate their Authentication Key on-chain. The key which will be roated to, should be a BIP-44 derived key. This will allow the user to use the same mnemonic string with different wallets (any wallet implementing the Bip-44 standard).

pub mod helpers;
