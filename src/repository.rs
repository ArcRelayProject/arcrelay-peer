use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;

use crate::{CapabilityId, DeviceId, Grant, GrantDirection, PeerRecord};

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("peer repository failed: {0}")]
    Backend(String),
}

#[async_trait]
pub trait PeerRepository: Send + Sync {
    async fn peer(&self, id: &DeviceId) -> Result<Option<PeerRecord>, RepositoryError>;
    async fn peers(&self) -> Result<Vec<PeerRecord>, RepositoryError>;
    async fn save_peer(&self, peer: PeerRecord) -> Result<(), RepositoryError>;
    /// Persists the paired identity and its complete initial grant set as one
    /// repository transaction.
    async fn save_pairing(
        &self,
        peer: PeerRecord,
        grants: Vec<Grant>,
    ) -> Result<(), RepositoryError>;
    async fn forget_peer(&self, id: &DeviceId) -> Result<bool, RepositoryError>;
    async fn grants(&self, id: &DeviceId) -> Result<Vec<Grant>, RepositoryError>;
    async fn save_grant(&self, grant: Grant) -> Result<(), RepositoryError>;
    async fn revoke_grant(
        &self,
        id: &DeviceId,
        capability: CapabilityId,
        direction: GrantDirection,
    ) -> Result<bool, RepositoryError>;
}

type GrantKey = (DeviceId, CapabilityId, GrantDirection);

#[derive(Debug, Clone, Default)]
pub struct InMemoryPeerRepository {
    peers: Arc<Mutex<BTreeMap<DeviceId, PeerRecord>>>,
    grants: Arc<Mutex<BTreeMap<GrantKey, Grant>>>,
}

#[async_trait]
impl PeerRepository for InMemoryPeerRepository {
    async fn peer(&self, id: &DeviceId) -> Result<Option<PeerRecord>, RepositoryError> {
        Ok(lock(&self.peers).get(id).cloned())
    }

    async fn peers(&self) -> Result<Vec<PeerRecord>, RepositoryError> {
        Ok(lock(&self.peers).values().cloned().collect())
    }

    async fn save_peer(&self, peer: PeerRecord) -> Result<(), RepositoryError> {
        peer.device_id
            .verify_key(&peer.public_key)
            .map_err(|error| RepositoryError::Backend(error.to_string()))?;
        lock(&self.peers).insert(peer.device_id.clone(), peer);
        Ok(())
    }

    async fn save_pairing(
        &self,
        peer: PeerRecord,
        grants: Vec<Grant>,
    ) -> Result<(), RepositoryError> {
        peer.device_id
            .verify_key(&peer.public_key)
            .map_err(|error| RepositoryError::Backend(error.to_string()))?;
        if grants.iter().any(|grant| grant.peer_id != peer.device_id) {
            return Err(RepositoryError::Backend(
                "pairing grant belongs to another peer".into(),
            ));
        }
        let mut peers = lock(&self.peers);
        let mut stored_grants = lock(&self.grants);
        stored_grants.retain(|(peer_id, _, _), _| peer_id != &peer.device_id);
        for grant in grants {
            stored_grants.insert(
                (grant.peer_id.clone(), grant.capability, grant.direction),
                grant,
            );
        }
        peers.insert(peer.device_id.clone(), peer);
        Ok(())
    }

    async fn forget_peer(&self, id: &DeviceId) -> Result<bool, RepositoryError> {
        let removed = lock(&self.peers).remove(id).is_some();
        lock(&self.grants).retain(|(peer, _, _), _| peer != id);
        Ok(removed)
    }

    async fn grants(&self, id: &DeviceId) -> Result<Vec<Grant>, RepositoryError> {
        Ok(lock(&self.grants)
            .iter()
            .filter(|((peer, _, _), _)| peer == id)
            .map(|(_, grant)| grant.clone())
            .collect())
    }

    async fn save_grant(&self, grant: Grant) -> Result<(), RepositoryError> {
        lock(&self.grants).insert(
            (grant.peer_id.clone(), grant.capability, grant.direction),
            grant,
        );
        Ok(())
    }

    async fn revoke_grant(
        &self,
        id: &DeviceId,
        capability: CapabilityId,
        direction: GrantDirection,
    ) -> Result<bool, RepositoryError> {
        Ok(lock(&self.grants)
            .remove(&(id.clone(), capability, direction))
            .is_some())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DevicePublicKey, GrantConstraints, TrustState};

    fn peer(seed: u8, name: &str) -> PeerRecord {
        let public_key = DevicePublicKey::from_bytes(vec![seed; 32]).unwrap();
        PeerRecord {
            device_id: DeviceId::from_public_key(&public_key),
            public_key,
            display_name: name.into(),
            platform: "test".into(),
            model: "virtual".into(),
            trust_state: TrustState::Paired,
            auto_connect: true,
            paired_at_ms: 1,
            updated_at_ms: 2,
        }
    }

    fn grant(peer_id: DeviceId, capability: CapabilityId, direction: GrantDirection) -> Grant {
        Grant {
            peer_id,
            capability,
            direction,
            constraints: GrantConstraints::None,
            granted_at_ms: 3,
        }
    }

    #[tokio::test]
    async fn peer_crud_and_clone_share_the_same_repository_state() {
        let repository = InMemoryPeerRepository::default();
        let clone = repository.clone();
        let first = peer(1, "first");
        let second = peer(2, "second");

        repository.save_peer(second.clone()).await.unwrap();
        repository.save_peer(first.clone()).await.unwrap();
        assert_eq!(
            clone.peer(&first.device_id).await.unwrap(),
            Some(first.clone())
        );
        assert_eq!(
            repository.peers().await.unwrap(),
            vec![first.clone(), second]
        );

        assert!(repository.forget_peer(&first.device_id).await.unwrap());
        assert!(!repository.forget_peer(&first.device_id).await.unwrap());
        assert_eq!(clone.peer(&first.device_id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn saving_a_peer_rejects_an_identity_key_mismatch() {
        let repository = InMemoryPeerRepository::default();
        let mut record = peer(3, "tampered");
        record.public_key = DevicePublicKey::from_bytes(vec![4; 32]).unwrap();

        assert!(repository.save_peer(record).await.is_err());
        assert!(repository.peers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn pairing_replaces_grants_and_rejects_cross_peer_grants_atomically() {
        let repository = InMemoryPeerRepository::default();
        let first = peer(5, "first");
        let other = peer(6, "other");
        repository
            .save_grant(grant(
                first.device_id.clone(),
                CapabilityId::SystemRead,
                GrantDirection::Inbound,
            ))
            .await
            .unwrap();

        let replacement = grant(
            first.device_id.clone(),
            CapabilityId::ClipboardRead,
            GrantDirection::Outbound,
        );
        repository
            .save_pairing(first.clone(), vec![replacement.clone()])
            .await
            .unwrap();
        assert_eq!(
            repository.grants(&first.device_id).await.unwrap(),
            vec![replacement]
        );

        let invalid = grant(
            other.device_id.clone(),
            CapabilityId::MediaRead,
            GrantDirection::Inbound,
        );
        assert!(repository
            .save_pairing(first.clone(), vec![invalid])
            .await
            .is_err());
        assert_eq!(
            repository.peer(&first.device_id).await.unwrap(),
            Some(first)
        );
    }

    #[tokio::test]
    async fn grants_are_upserted_revoked_and_removed_with_the_peer() {
        let repository = InMemoryPeerRepository::default();
        let record = peer(7, "peer");
        repository.save_peer(record.clone()).await.unwrap();
        let mut original = grant(
            record.device_id.clone(),
            CapabilityId::PrintSubmit,
            GrantDirection::Inbound,
        );
        repository.save_grant(original.clone()).await.unwrap();
        original.granted_at_ms = 99;
        repository.save_grant(original.clone()).await.unwrap();
        assert_eq!(
            repository.grants(&record.device_id).await.unwrap(),
            vec![original]
        );

        assert!(repository
            .revoke_grant(
                &record.device_id,
                CapabilityId::PrintSubmit,
                GrantDirection::Inbound,
            )
            .await
            .unwrap());
        assert!(!repository
            .revoke_grant(
                &record.device_id,
                CapabilityId::PrintSubmit,
                GrantDirection::Inbound,
            )
            .await
            .unwrap());

        repository
            .save_grant(grant(
                record.device_id.clone(),
                CapabilityId::MediaControl,
                GrantDirection::Outbound,
            ))
            .await
            .unwrap();
        repository.forget_peer(&record.device_id).await.unwrap();
        assert!(repository
            .grants(&record.device_id)
            .await
            .unwrap()
            .is_empty());
    }
}
