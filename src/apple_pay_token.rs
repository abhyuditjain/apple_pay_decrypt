use base64::{
    engine::{general_purpose, Engine as _},
    DecodeError,
};
use hex::{decode, encode, FromHexError};
use openssl::ec::EcKey;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Public};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::{derive::Deriver, error::ErrorStack};
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeJsonError;
use std::{str, string::FromUtf8Error};
use thiserror::Error;
use x509_certificate::{X509Certificate, X509CertificateError};

const APPLE_MERCHANT_ID_OID: &str = "1.2.840.113635.100.6.32";

#[derive(Debug, Error)]
pub enum ApplePayTokenError {
    #[error("Utf8 error: {0}")]
    Utf8Error(#[from] FromUtf8Error),

    #[error("Base64 decoding error: {0}")]
    Base64Decode(#[from] DecodeError),

    #[error("Hex error: {0}")]
    HexError(#[from] FromHexError),

    #[error("JSON deserialization error: {0}")]
    JsonDeserialize(#[from] SerdeJsonError),

    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] ErrorStack),

    #[error("X509Certificate error: {0}")]
    X509CertificateError(#[from] X509CertificateError),

    #[error("Merchant ID not found: {0}")]
    MerchantIDNotFound(&'static str),

    #[error("Invalid encoded octet string")]
    InvalidEncodedOctetString,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedToken {
    pub application_primary_account_number: String,
    pub application_expiration_date: String,
    pub currency_code: String,
    pub transaction_amount: i32,
    pub device_manufacturer_identifier: String,
    pub payment_data_type: String,
    pub payment_data: PaymentData,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentData {
    pub online_payment_cryptogram: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedToken {
    pub data: String,
    pub header: EncryptedTokenHeader,
    pub signature: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedTokenHeader {
    pub ephemeral_public_key: String,
    pub public_key_hash: String,
    pub transaction_id: String,
}

impl EncryptedToken {
    /// Tries to create a new EncryptedToken instance from a base64 encoded string
    pub fn try_from_base64_str(s: &str) -> Result<Self, ApplePayTokenError> {
        let decoded_token = general_purpose::STANDARD.decode(s)?;
        let encrypted_token = serde_json::from_slice::<Self>(&decoded_token)?;

        Ok(encrypted_token)
    }

    /// Decrypts the payment token
    pub fn decrypt(
        &self,
        cert_pem: &str,
        private_pem: &str,
    ) -> Result<DecryptedToken, ApplePayTokenError> {
        let merchant_id = self.merchant_id(cert_pem)?;
        let shared_secret = self.shared_secret(private_pem)?;
        let symmetric_key = self.symmetric_key(&merchant_id, &shared_secret)?;

        let decrypted = self.decrypt_ciphertext(&symmetric_key, &self.data)?;
        let decrypted_token = serde_json::from_str(&decrypted)?;
        Ok(decrypted_token)
    }

    fn create_ec_key_from_spki(base64_spki: &str) -> Result<EcKey<Public>, ApplePayTokenError> {
        let decoded_spki = general_purpose::STANDARD.decode(base64_spki)?;
        let ephemeral_public_key = EcKey::public_key_from_der(&decoded_spki)?;
        Ok(ephemeral_public_key)
    }

    /// Computes the shared secret using Elliptic Curve Diffie-Hellman
    fn shared_secret(&self, private_pem: &str) -> Result<String, ApplePayTokenError> {
        // Load the merchant's private key
        let merchant_private_key = EcKey::private_key_from_pem(private_pem.as_bytes())?;
        let pkey: PKey<_> = merchant_private_key.try_into()?;

        // Parse the ephemeral public key from base64
        let ephemeral_public_key =
            Self::create_ec_key_from_spki(&self.header.ephemeral_public_key)?;
        let pub_key: PKey<_> = ephemeral_public_key.try_into()?;

        // Create a shared key context
        let mut deriver = Deriver::new(&pkey)?;
        deriver.set_peer(&pub_key)?;

        let shared_secret = deriver.derive_to_vec()?;

        // Hex encode
        let shared_secret = hex::encode(shared_secret);

        Ok(shared_secret)
    }

    /// Extracts the merchant ID from the certificate
    fn merchant_id(&self, cert: &str) -> Result<String, ApplePayTokenError> {
        let cert = X509Certificate::from_pem(cert.as_bytes())?;
        let ext = cert
            .iter_extensions()
            .find(|ext| ext.id.to_string() == APPLE_MERCHANT_ID_OID);

        let Some(ext) = ext else {
            return Err(ApplePayTokenError::MerchantIDNotFound(
                APPLE_MERCHANT_ID_OID,
            ));
        };

        let value = &ext.value;

        let Some(slice) = value.as_slice() else {
            return Err(ApplePayTokenError::InvalidEncodedOctetString);
        };

        let merchant_id = slice
            .iter()
            .copied()
            .skip_while(|c| *c != b'@')
            .skip(1)
            .collect();

        let merchant_id = String::from_utf8(merchant_id)?;

        Ok(merchant_id)
    }

    fn symmetric_key(
        &self,
        merchant_id: &str,
        shared_secret: &str,
    ) -> Result<String, ApplePayTokenError> {
        const KDF_ALGORITHM: &[u8] = b"\x0did-aes256-GCM";
        let kdf_party_v = decode(merchant_id)?;
        const KDF_PARTY_U: &[u8] = b"Apple";
        let mut kdf_info: Vec<u8> = Vec::new();
        kdf_info.extend_from_slice(KDF_ALGORITHM);
        kdf_info.extend_from_slice(KDF_PARTY_U);
        kdf_info.extend_from_slice(&kdf_party_v);

        let mut context = Hasher::new(MessageDigest::sha256())?;

        let hex_string = "000000";
        let bytes = decode(hex_string)?;

        context.update(&bytes)?;

        let hex_string = "01";
        let bytes = decode(hex_string)?;

        context.update(&bytes)?;

        context.update(&decode(shared_secret)?)?;

        context.update(&kdf_info)?;

        let hash = context.finish()?;

        Ok(encode(hash))
    }

    /// Decrypts the cipher text
    fn decrypt_ciphertext(
        &self,
        symmetric_key: &str,
        cipher_text: &str,
    ) -> Result<String, ApplePayTokenError> {
        let data = general_purpose::STANDARD.decode(cipher_text)?;

        let symmetric_key_bytes = hex::decode(symmetric_key)?;

        let iv = vec![0u8; 16]; // Initialization vector of 16 null bytes
        let tag = &data[data.len() - 16..];
        let ciphertext = &data[..data.len() - 16];

        let cipher = Cipher::aes_256_gcm();

        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &symmetric_key_bytes, Some(&iv))?;
        decrypter.set_tag(tag)?;

        let mut decrypted = vec![0u8; ciphertext.len()]; // Allocate space for decrypted text

        // Perform the decryption
        let len = decrypter.update(ciphertext, &mut decrypted)?;
        let final_len = decrypter.finalize(&mut decrypted[len..])?;

        let total_len = len + final_len;

        // Truncate to the actual decrypted length
        decrypted.truncate(total_len);

        let decrypted_str = String::from_utf8(decrypted)?;

        Ok(decrypted_str)
    }
}
