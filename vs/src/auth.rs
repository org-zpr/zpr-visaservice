use base64::prelude::*;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;

use zpr::vsapi_types::SelfSignedBlob;

use crate::error::CryptoError;

/// Returns TRUE if signature is valid for the given self-signed blob and CN.
pub fn verify_ss_blob_signature(
    cn: &str,
    ssb: &SelfSignedBlob,
    pubkey: PKey<Public>,
) -> Result<bool, CryptoError> {
    let input_signature = BASE64_STANDARD.decode(&ssb.signature)?;
    let content = [
        &ssb.timestamp.to_be_bytes()[..],
        cn.as_bytes(),
        &ssb.challenge[..],
    ];
    verify_rsa_sha256_signature(pubkey, &input_signature, &content)
}

/// Returns TRUE if signature is valid for the given content and public key.
pub fn verify_rsa_sha256_signature(
    pubkey: PKey<Public>,
    incomming_signature: &[u8],
    content: &[&[u8]],
) -> Result<bool, CryptoError> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey)?;

    for chunk in content {
        verifier.update(chunk)?;
    }

    let sig_ok = verifier.verify(incomming_signature)?;
    Ok(sig_ok)
}
