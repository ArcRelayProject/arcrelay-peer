use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProductId(String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ts_rs::TS)]
#[serde(transparent)]
pub struct ServiceInstanceId(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerIdError {
    #[error("identifier cannot be empty")]
    Empty,
    #[error("identifier is too long")]
    TooLong,
    #[error("identifier contains unsupported characters")]
    InvalidCharacters,
}

fn validate(value: String, maximum: usize) -> Result<String, PeerIdError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(PeerIdError::Empty);
    }
    if value.len() > maximum {
        return Err(PeerIdError::TooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(PeerIdError::InvalidCharacters);
    }
    Ok(value)
}

impl ProductId {
    pub fn parse(value: impl Into<String>) -> Result<Self, PeerIdError> {
        validate(value.into(), 64).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ServiceInstanceId {
    pub fn parse(value: impl Into<String>) -> Result<Self, PeerIdError> {
        validate(value.into(), 128).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProductId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for ServiceInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_normalized_and_orderable() {
        let first = ServiceInstanceId::parse(" arc-input-a ").unwrap();
        let second = ServiceInstanceId::parse("arc-input-b").unwrap();
        assert_eq!(first.as_str(), "arc-input-a");
        assert!(first < second);
        assert!(ProductId::parse("arc.input").is_ok());
        assert!(ProductId::parse("arc input").is_err());
    }
}
