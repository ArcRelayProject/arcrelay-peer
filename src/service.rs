use std::sync::Arc;

use crate::{
    CapabilityId, DeviceId, Grant, GrantConstraints, GrantDirection, PeerRecord, PeerRepository,
    RepositoryError, TrustState,
};

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("peer is not paired")]
    Unpaired,
    #[error("capability {0} is not granted")]
    Denied(&'static str),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Debug, thiserror::Error)]
pub enum PeerServiceError {
    #[error("peer identity is invalid: {0}")]
    InvalidIdentity(String),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[derive(Clone)]
pub struct AuthorizationService {
    repository: Arc<dyn PeerRepository>,
}

impl AuthorizationService {
    pub fn new(repository: Arc<dyn PeerRepository>) -> Self {
        Self { repository }
    }

    pub async fn require(
        &self,
        peer_id: &DeviceId,
        capability: CapabilityId,
    ) -> Result<GrantConstraints, AuthorizationError> {
        let peer = self
            .repository
            .peer(peer_id)
            .await?
            .filter(|peer| peer.trust_state == TrustState::Paired)
            .ok_or(AuthorizationError::Unpaired)?;
        debug_assert_eq!(peer.device_id, *peer_id);
        self.repository
            .grants(peer_id)
            .await?
            .into_iter()
            .find(|grant| {
                grant.capability == capability && grant.direction == GrantDirection::Inbound
            })
            .map(|grant| grant.constraints)
            .ok_or(AuthorizationError::Denied(capability.token()))
    }
}

#[derive(Clone)]
pub struct PeerService {
    repository: Arc<dyn PeerRepository>,
}

impl PeerService {
    pub fn new(repository: Arc<dyn PeerRepository>) -> Self {
        Self { repository }
    }

    pub async fn pair(&self, mut peer: PeerRecord) -> Result<(), PeerServiceError> {
        peer.device_id
            .verify_key(&peer.public_key)
            .map_err(|error| PeerServiceError::InvalidIdentity(error.to_string()))?;
        peer.trust_state = TrustState::Paired;
        self.repository.save_peer(peer).await?;
        Ok(())
    }

    pub async fn grant(&self, grant: Grant) -> Result<(), PeerServiceError> {
        let paired = self
            .repository
            .peer(&grant.peer_id)
            .await?
            .is_some_and(|peer| peer.trust_state == TrustState::Paired);
        if !paired {
            return Err(PeerServiceError::InvalidIdentity(
                "cannot grant a capability to an unpaired peer".into(),
            ));
        }
        self.repository.save_grant(grant).await?;
        Ok(())
    }

    pub async fn forget(&self, peer_id: &DeviceId) -> Result<bool, PeerServiceError> {
        Ok(self.repository.forget_peer(peer_id).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DevicePublicKey, InMemoryPeerRepository};

    fn peer() -> PeerRecord {
        let public_key = DevicePublicKey::from_bytes(vec![9; 32]).unwrap();
        PeerRecord {
            device_id: DeviceId::from_public_key(&public_key),
            public_key,
            display_name: "Desk".into(),
            platform: "macos".into(),
            model: "Mac".into(),
            trust_state: TrustState::Paired,
            auto_connect: true,
            paired_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    #[tokio::test]
    async fn pairing_does_not_implicitly_grant_capabilities() {
        let repository: Arc<dyn PeerRepository> = Arc::new(InMemoryPeerRepository::default());
        let peers = PeerService::new(repository.clone());
        let authorization = AuthorizationService::new(repository);
        let peer = peer();
        peers.pair(peer.clone()).await.unwrap();
        assert!(matches!(
            authorization
                .require(&peer.device_id, CapabilityId::CrossScreenInject)
                .await,
            Err(AuthorizationError::Denied(_))
        ));
        peers
            .grant(Grant {
                peer_id: peer.device_id.clone(),
                capability: CapabilityId::CrossScreenInject,
                direction: GrantDirection::Inbound,
                constraints: GrantConstraints::None,
                granted_at_ms: 2,
            })
            .await
            .unwrap();
        assert_eq!(
            authorization
                .require(&peer.device_id, CapabilityId::CrossScreenInject)
                .await
                .unwrap(),
            GrantConstraints::None
        );
    }
}
