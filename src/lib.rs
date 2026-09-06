//! Product-neutral device identity, authorization and connection arbitration.
//!
//! This crate intentionally does not open sockets. Product runtimes own their
//! discovery and QUIC policies while sharing the invariants that a device pair
//! has one dialer and at most one live authenticated connection.

mod capability;
mod connection;
mod device;
mod identity;
mod repository;
mod service;

pub use capability::{CapabilityId, Grant, GrantConstraints, GrantDirection};
pub use connection::{
    should_dial, ConnectionCandidate, ConnectionDecision, ConnectionDirection, ConnectionRegistry,
    DialIntent,
};
pub use device::{
    DeviceId, DeviceIdError, DeviceKeyProvider, DevicePublicKey, DeviceSignature, PeerRecord,
    SigningContext, TrustState,
};
pub use identity::{PeerIdError, ProductId, ServiceInstanceId};
pub use repository::{InMemoryPeerRepository, PeerRepository, RepositoryError};
pub use service::{AuthorizationError, AuthorizationService, PeerService, PeerServiceError};
