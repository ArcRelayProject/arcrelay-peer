use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::ServiceInstanceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialIntent {
    Automatic,
    UserInitiated,
    Controller,
}

/// Elect the only default dialer. A manual action may bypass the ordering,
/// while controller-only Arc Input links must originate at the controller.
pub fn should_dial(
    local: &ServiceInstanceId,
    remote: &ServiceInstanceId,
    paired: bool,
    intent: DialIntent,
    local_is_controller: bool,
) -> bool {
    if local == remote {
        return false;
    }
    match intent {
        DialIntent::UserInitiated => true,
        DialIntent::Automatic => paired && local < remote,
        DialIntent::Controller => paired && local_is_controller,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCandidate {
    pub connection_id: u64,
    pub local_id: ServiceInstanceId,
    pub remote_id: ServiceInstanceId,
    pub local_nonce: u128,
    pub remote_nonce: u128,
    pub direction: ConnectionDirection,
}

impl ConnectionCandidate {
    fn rank(&self) -> (ServiceInstanceId, u128, ServiceInstanceId, u128, u64) {
        let (initiator_id, initiator_nonce, acceptor_id, acceptor_nonce) = match self.direction {
            ConnectionDirection::Outbound => (
                self.local_id.clone(),
                self.local_nonce,
                self.remote_id.clone(),
                self.remote_nonce,
            ),
            ConnectionDirection::Inbound => (
                self.remote_id.clone(),
                self.remote_nonce,
                self.local_id.clone(),
                self.local_nonce,
            ),
        };
        (
            initiator_id,
            initiator_nonce,
            acceptor_id,
            acceptor_nonce,
            self.connection_id,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDecision {
    Accepted,
    Replaced { connection_id: u64 },
    Rejected { winner_id: u64 },
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionRegistry {
    active: Arc<Mutex<HashMap<ServiceInstanceId, ConnectionCandidate>>>,
}

impl ConnectionRegistry {
    pub fn register(&self, candidate: ConnectionCandidate) -> ConnectionDecision {
        let mut active = lock(&self.active);
        match active.get(&candidate.remote_id) {
            None => {
                active.insert(candidate.remote_id.clone(), candidate);
                ConnectionDecision::Accepted
            }
            Some(current) if candidate.rank() < current.rank() => {
                let replaced = current.connection_id;
                active.insert(candidate.remote_id.clone(), candidate);
                ConnectionDecision::Replaced {
                    connection_id: replaced,
                }
            }
            Some(current) => ConnectionDecision::Rejected {
                winner_id: current.connection_id,
            },
        }
    }

    pub fn remove(&self, remote: &ServiceInstanceId, connection_id: u64) -> bool {
        let mut active = lock(&self.active);
        if active
            .get(remote)
            .is_some_and(|candidate| candidate.connection_id == connection_id)
        {
            active.remove(remote);
            true
        } else {
            false
        }
    }

    pub fn active_connection(&self, remote: &ServiceInstanceId) -> Option<u64> {
        lock(&self.active)
            .get(remote)
            .map(|candidate| candidate.connection_id)
    }

    pub fn len(&self) -> usize {
        lock(&self.active).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    fn id(value: &str) -> ServiceInstanceId {
        ServiceInstanceId::parse(value).unwrap()
    }

    #[test]
    fn elects_one_automatic_dialer() {
        let a = id("a");
        let b = id("b");
        assert!(should_dial(&a, &b, true, DialIntent::Automatic, false));
        assert!(!should_dial(&b, &a, true, DialIntent::Automatic, false));
        assert!(!should_dial(&a, &b, false, DialIntent::Automatic, false));
        assert!(should_dial(&b, &a, false, DialIntent::UserInitiated, false));
    }

    #[test]
    fn simultaneous_candidates_converge_on_the_same_rank() {
        let registry = ConnectionRegistry::default();
        let first = ConnectionCandidate {
            connection_id: 20,
            local_id: id("b"),
            remote_id: id("a"),
            local_nonce: 9,
            remote_nonce: 4,
            direction: ConnectionDirection::Outbound,
        };
        let winner = ConnectionCandidate {
            connection_id: 10,
            local_id: id("b"),
            remote_id: id("a"),
            local_nonce: 4,
            remote_nonce: 7,
            direction: ConnectionDirection::Inbound,
        };
        assert_eq!(registry.register(first), ConnectionDecision::Accepted);
        assert_eq!(
            registry.register(winner),
            ConnectionDecision::Replaced { connection_id: 20 }
        );
        assert_eq!(registry.active_connection(&id("a")), Some(10));
        assert!(!registry.remove(&id("a"), 20));
        assert!(registry.remove(&id("a"), 10));
    }
}
