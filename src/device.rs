use std::fmt;
use std::str::FromStr;

use async_trait::async_trait;
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEVICE_ID_PREFIX: &str = "arc-";
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

/// Stable ArcRelay device identity derived from the root Ed25519 public key.
///
/// Device ids are never allocated independently from a key, which prevents an
/// identifier from being rebound to a different cryptographic identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ts_rs::TS)]
#[serde(transparent)]
pub struct DeviceId(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DevicePublicKey(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSignature(Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningContext {
    EndpointBinding,
    SessionAuthentication,
    PairingTranscript,
    FeaturePayload,
}

impl SigningContext {
    pub const fn domain(self) -> &'static [u8] {
        match self {
            Self::EndpointBinding => b"arcrelay.endpoint-binding.v1\0",
            Self::SessionAuthentication => b"arcrelay.session-auth.v1\0",
            Self::PairingTranscript => b"arcrelay.pairing.v1\0",
            Self::FeaturePayload => b"arcrelay.feature-payload.v1\0",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrustState {
    Paired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerRecord {
    pub device_id: DeviceId,
    pub public_key: DevicePublicKey,
    pub display_name: String,
    pub platform: String,
    pub model: String,
    pub trust_state: TrustState,
    /// Whether this device may be dialed automatically when it becomes available.
    /// Manual connection attempts and an existing live session are unaffected.
    #[serde(default = "auto_connect_default")]
    pub auto_connect: bool,
    pub paired_at_ms: i64,
    pub updated_at_ms: i64,
}

const fn auto_connect_default() -> bool {
    true
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeviceIdError {
    #[error("device public key must contain exactly 32 bytes")]
    InvalidPublicKey,
    #[error("device id has an invalid format")]
    InvalidFormat,
    #[error("device id does not match the public key")]
    KeyMismatch,
    #[error("device signature must contain exactly 64 bytes")]
    InvalidSignature,
}

impl DeviceId {
    #[must_use]
    pub fn from_public_key(public_key: &DevicePublicKey) -> Self {
        let digest = Sha256::digest(public_key.as_bytes());
        Self(format!(
            "{DEVICE_ID_PREFIX}{}",
            BASE32_NOPAD.encode(&digest).to_ascii_lowercase()
        ))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, DeviceIdError> {
        let value = value.into().trim().to_ascii_lowercase();
        let encoded = value
            .strip_prefix(DEVICE_ID_PREFIX)
            .ok_or(DeviceIdError::InvalidFormat)?;
        if encoded.len() != 52
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(DeviceIdError::InvalidFormat);
        }
        let decoded = BASE32_NOPAD
            .decode(encoded.to_ascii_uppercase().as_bytes())
            .map_err(|_| DeviceIdError::InvalidFormat)?;
        if decoded.len() != 32 {
            return Err(DeviceIdError::InvalidFormat);
        }
        Ok(Self(value))
    }

    pub fn verify_key(&self, public_key: &DevicePublicKey) -> Result<(), DeviceIdError> {
        if self == &Self::from_public_key(public_key) {
            Ok(())
        } else {
            Err(DeviceIdError::KeyMismatch)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl DevicePublicKey {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, DeviceIdError> {
        let bytes = bytes.into();
        if bytes.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(DeviceIdError::InvalidPublicKey);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl DeviceSignature {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, DeviceIdError> {
        let bytes = bytes.into();
        if bytes.len() != ED25519_SIGNATURE_BYTES {
            return Err(DeviceIdError::InvalidSignature);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[async_trait]
pub trait DeviceKeyProvider: Send + Sync {
    async fn public_key(&self)
        -> Result<DevicePublicKey, Box<dyn std::error::Error + Send + Sync>>;

    async fn sign(
        &self,
        context: SigningContext,
        message: &[u8],
    ) -> Result<DeviceSignature, Box<dyn std::error::Error + Send + Sync>>;

    async fn device_id(&self) -> Result<DeviceId, Box<dyn std::error::Error + Send + Sync>> {
        Ok(DeviceId::from_public_key(&self.public_key().await?))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for DeviceId {
    type Err = DeviceIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_canonical_and_bound_to_key() {
        let key = DevicePublicKey::from_bytes(vec![7; 32]).unwrap();
        let other = DevicePublicKey::from_bytes(vec![8; 32]).unwrap();
        let id = DeviceId::from_public_key(&key);
        assert_eq!(DeviceId::parse(id.to_string()).unwrap(), id);
        assert!(id.verify_key(&key).is_ok());
        assert_eq!(id.verify_key(&other), Err(DeviceIdError::KeyMismatch));
    }
}
