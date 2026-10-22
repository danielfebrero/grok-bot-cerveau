use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

#[derive(Debug)]
pub(crate) enum CryptoError {
    Point,
    Dh,
    Aead,
    Hkdf,
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// libsodium / RFC 8032 seed to X25519 scalar (SHA-512, clamp).
pub(crate) fn ed25519_seed_to_x25519_secret(seed: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&hash[..32]);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    sk
}

pub(crate) fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

pub(crate) fn ed25519_public_to_x25519(edwards: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let point = CompressedEdwardsY(*edwards)
        .decompress()
        .ok_or(CryptoError::Point)?;
    Ok(point.to_montgomery().to_bytes())
}

pub(crate) fn dh(secret: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let sk = StaticSecret::from(*secret);
    let pk = PublicKey::from(*peer);
    let shared: SharedSecret = sk.diffie_hellman(&pk);
    if !shared.was_contributory() {
        return Err(CryptoError::Dh);
    }
    Ok(*shared.as_bytes())
}

pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::Hkdf)?;
    Ok(okm)
}

pub(crate) fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

pub(crate) fn aead_open(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != 12 {
        return Err(CryptoError::Aead);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

pub(crate) fn zeroize_key(key: &mut [u8; 32]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn rfc8032_test1_and_x25519_conversion_agree() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        assert_eq!(
            hex::encode(public),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = signing.sign(b"");
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        let scalar = ed25519_seed_to_x25519_secret(&seed);
        let from_secret = x25519_public(&scalar);
        let from_edwards = ed25519_public_to_x25519(&public).unwrap();
        assert_eq!(from_secret, from_edwards);
    }
}
