use serde::{Deserialize, Serialize};

use crate::DeviceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityId {
    SystemRead,
    ProcessRead,
    ProcessManage,
    MediaRead,
    MediaControl,
    ClipboardRead,
    ClipboardWrite,
    ClipboardSync,
    WindowRead,
    WindowControl,
    ActionRead,
    ActionExecute,
    NotificationRead,
    NotificationAcknowledge,
    RemoteInputInject,
    CrossScreenInject,
    RemoteFilesRead,
    RemoteFilesWrite,
    NearbyTransferSend,
    PrintSubmit,
}

impl CapabilityId {
    pub const fn token(self) -> &'static str {
        match self {
            Self::SystemRead => "system.read",
            Self::ProcessRead => "process.read",
            Self::ProcessManage => "process.manage",
            Self::MediaRead => "media.read",
            Self::MediaControl => "media.control",
            Self::ClipboardRead => "clipboard.read",
            Self::ClipboardWrite => "clipboard.write",
            Self::ClipboardSync => "clipboard.sync",
            Self::WindowRead => "window.read",
            Self::WindowControl => "window.control",
            Self::ActionRead => "action.read",
            Self::ActionExecute => "action.execute",
            Self::NotificationRead => "notification.read",
            Self::NotificationAcknowledge => "notification.acknowledge",
            Self::RemoteInputInject => "remote-input.inject",
            Self::CrossScreenInject => "cross-screen.inject",
            Self::RemoteFilesRead => "remote-files.read",
            Self::RemoteFilesWrite => "remote-files.write",
            Self::NearbyTransferSend => "nearby-transfer.send",
            Self::PrintSubmit => "print.submit",
        }
    }

    pub fn parse_token(value: &str) -> Option<Self> {
        Some(match value {
            "system.read" => Self::SystemRead,
            "process.read" => Self::ProcessRead,
            "process.manage" => Self::ProcessManage,
            "media.read" => Self::MediaRead,
            "media.control" => Self::MediaControl,
            "clipboard.read" => Self::ClipboardRead,
            "clipboard.write" => Self::ClipboardWrite,
            "clipboard.sync" => Self::ClipboardSync,
            "window.read" => Self::WindowRead,
            "window.control" => Self::WindowControl,
            "action.read" => Self::ActionRead,
            "action.execute" => Self::ActionExecute,
            "notification.read" => Self::NotificationRead,
            "notification.acknowledge" => Self::NotificationAcknowledge,
            "remote-input.inject" => Self::RemoteInputInject,
            "cross-screen.inject" => Self::CrossScreenInject,
            "remote-files.read" => Self::RemoteFilesRead,
            "remote-files.write" => Self::RemoteFilesWrite,
            "nearby-transfer.send" => Self::NearbyTransferSend,
            "print.submit" => Self::PrintSubmit,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GrantDirection {
    /// The peer may invoke a capability owned by this device.
    Inbound,
    /// This device may invoke a capability owned by the peer.
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum GrantConstraints {
    None,
    RemoteFileShares {
        share_ids: Vec<String>,
        writable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub peer_id: DeviceId,
    pub capability: CapabilityId,
    pub direction: GrantDirection,
    pub constraints: GrantConstraints,
    pub granted_at_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_token_round_trips_and_unknown_tokens_are_rejected() {
        let capabilities = [
            CapabilityId::SystemRead,
            CapabilityId::ProcessRead,
            CapabilityId::ProcessManage,
            CapabilityId::MediaRead,
            CapabilityId::MediaControl,
            CapabilityId::ClipboardRead,
            CapabilityId::ClipboardWrite,
            CapabilityId::ClipboardSync,
            CapabilityId::WindowRead,
            CapabilityId::WindowControl,
            CapabilityId::ActionRead,
            CapabilityId::ActionExecute,
            CapabilityId::NotificationRead,
            CapabilityId::NotificationAcknowledge,
            CapabilityId::RemoteInputInject,
            CapabilityId::CrossScreenInject,
            CapabilityId::RemoteFilesRead,
            CapabilityId::RemoteFilesWrite,
            CapabilityId::NearbyTransferSend,
            CapabilityId::PrintSubmit,
        ];

        for capability in capabilities {
            assert_eq!(
                CapabilityId::parse_token(capability.token()),
                Some(capability)
            );
        }
        assert_eq!(CapabilityId::parse_token(""), None);
        assert_eq!(CapabilityId::parse_token("clipboard.Read"), None);
        assert_eq!(CapabilityId::parse_token("unknown.read"), None);
    }

    #[test]
    fn constraints_use_the_stable_tagged_json_contract() {
        let constraints = GrantConstraints::RemoteFileShares {
            share_ids: vec!["docs".into(), "photos".into()],
            writable: true,
        };
        let value = serde_json::to_value(&constraints).unwrap();
        assert_eq!(value["kind"], "remoteFileShares");
        assert_eq!(
            serde_json::from_value::<GrantConstraints>(value).unwrap(),
            constraints
        );
    }
}
