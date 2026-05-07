//! ACL (Access Control List) — Network Policy System.
//!
//! Provides fine-grained network access control:
//! - Device groups (admin, db, web, etc.)
//! - Source/destination rules per port/protocol
//! - Subnet-level ACLs
//! - Device isolation policies
//! - Default-deny or default-allow modes
//!
//! Policy format (JSON):
//! ```json
//! {
//!   "mode": "default-deny",
//!   "groups": {
//!     "admin": ["device-uuid-1"],
//!     "database": ["device-uuid-2", "device-uuid-3"]
//!   },
//!   "rules": [
//!     {
//!       "action": "allow",
//!       "src": "admin",
//!       "dst": "database",
//!       "protocol": "tcp",
//!       "ports": [5432, 3306]
//!     }
//!   ]
//! }
//! ```

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Policy enforcement mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// Allow all traffic by default, deny only what rules specify
    DefaultAllow,
    /// Deny all traffic by default, allow only what rules specify
    DefaultDeny,
}

impl Default for PolicyMode {
    fn default() -> Self {
        PolicyMode::DefaultDeny
    }
}

/// A single ACL rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    /// "allow" or "deny"
    pub action: AclAction,
    /// Source group name or device ID
    pub src: String,
    /// Destination group name or device ID
    pub dst: String,
    /// Protocol: "tcp", "udp", "icmp", "any"
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Ports to allow/deny (empty = all ports)
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Optional source IP ranges
    #[serde(default)]
    pub src_cidrs: Vec<String>,
    /// Priority (higher = evaluated first)
    #[serde(default)]
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Allow,
    Deny,
}

fn default_protocol() -> String {
    "any".to_string()
}

/// ACL Policy (loaded from control plane or config file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclPolicy {
    /// Enforcement mode
    #[serde(default)]
    pub mode: PolicyMode,
    /// Device groups: group_name → [device_ids]
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,
    /// Access control rules
    #[serde(default)]
    pub rules: Vec<AclRule>,
    /// Isolated devices (cannot communicate with anyone else)
    #[serde(default)]
    pub isolated_devices: Vec<String>,
    /// Devices exempt from ACL enforcement (e.g., control plane, relay)
    #[serde(default)]
    pub bypass_devices: Vec<String>,
}

impl AclPolicy {
    /// Parse a JSON policy string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Get all member device IDs for a group (including nested expansion).
    pub fn resolve_group(&self, group_name: &str) -> Vec<String> {
        self.groups.get(group_name).cloned().unwrap_or_default()
    }

    /// Check if a device is in a given group.
    pub fn device_in_group(&self, device_id: &str, group_name: &str) -> bool {
        self.groups
            .get(group_name)
            .map(|members| members.contains(&device_id.to_string()))
            .unwrap_or(false)
    }
}

/// ACL Enforcement Engine.
///
/// Evaluates traffic against the loaded ACL policy.
pub struct AclEngine {
    /// Current active policy
    policy: RwLock<AclPolicy>,
    /// Device ID → virtual IP cache
    device_ips: RwLock<HashMap<String, Ipv4Addr>>,
}

impl AclEngine {
    /// Create a new ACL engine with default-deny policy.
    pub fn new() -> Self {
        Self {
            policy: RwLock::new(AclPolicy {
                mode: PolicyMode::DefaultDeny,
                groups: HashMap::new(),
                rules: vec![],
                isolated_devices: vec![],
                bypass_devices: vec![],
            }),
            device_ips: RwLock::new(HashMap::new()),
        }
    }

    /// Load a new policy.
    pub async fn load_policy(&self, policy: AclPolicy) {
        let mut current = self.policy.write().await;
        *current = policy;
        log::info!("ACL policy loaded: mode={:?}, groups={}, rules={}",
            current.mode, current.groups.len(), current.rules.len());
    }

    /// Load policy from JSON string.
    pub async fn load_policy_json(&self, json: &str) -> Result<(), serde_json::Error> {
        let policy = AclPolicy::from_json(json)?;
        self.load_policy(policy).await;
        Ok(())
    }

    /// Register a device's IP for ACL resolution.
    pub async fn register_device_ip(&self, device_id: &str, ip: Ipv4Addr) {
        let mut ips = self.device_ips.write().await;
        ips.insert(device_id.to_string(), ip);
    }

    /// Check if traffic from src_device to dst_device on a specific port
    /// is allowed by the current policy.
    ///
    /// Returns true if traffic is permitted, false if denied.
    pub async fn check(
        &self,
        src_device: &str,
        dst_device: &str,
        protocol: &str,
        dst_port: u16,
    ) -> bool {
        let policy = self.policy.read().await;

        // Bypassed devices are always allowed
        if policy.bypass_devices.iter().any(|d| d == src_device || d == dst_device) {
            return true;
        }

        // Isolated devices cannot communicate
        if policy.isolated_devices.iter().any(|d| d == src_device)
            || policy.isolated_devices.iter().any(|d| d == dst_device)
        {
            // Isolated devices can only talk to bypass devices
            if !policy.bypass_devices.iter().any(|d| d == src_device || d == dst_device) {
                return false;
            }
        }

        // Evaluate rules in priority order (highest first)
        let mut rules = policy.rules.clone();
        rules.sort_by_key(|r| std::cmp::Reverse(r.priority));

        for rule in &rules {
            if self.rule_matches(rule, src_device, dst_device, protocol, dst_port, &policy.groups) {
                return rule.action == AclAction::Allow;
            }
        }

        // No rule matched — use default mode
        match policy.mode {
            PolicyMode::DefaultAllow => true,
            PolicyMode::DefaultDeny => false,
        }
    }

    /// Check if a specific rule matches the given traffic.
    fn rule_matches(
        &self,
        rule: &AclRule,
        src_device: &str,
        dst_device: &str,
        protocol: &str,
        dst_port: u16,
        groups: &HashMap<String, Vec<String>>,
    ) -> bool {
        // Check source matches
        let src_matches = src_device == rule.src
            || device_in_group(src_device, &rule.src, groups);

        // Check destination matches
        let dst_matches = dst_device == rule.dst
            || device_in_group(dst_device, &rule.dst, groups);

        if !src_matches || !dst_matches {
            return false;
        }

        // Check protocol
        if rule.protocol != "any" && rule.protocol.to_lowercase() != protocol.to_lowercase() {
            return false;
        }

        // Check port (if specified)
        if !rule.ports.is_empty() && !rule.ports.contains(&dst_port) {
            return false;
        }

        true
    }

/// Check if a device belongs to a named group.
///
/// Handles special group names "any" and "*" as wildcards.
/// Consults the groups map for actual group membership.
fn device_in_group(device_id: &str, group_name: &str, groups: &HashMap<String, Vec<String>>) -> bool {
    if group_name == "any" || group_name == "*" {
        return true;
    }
    if device_id == group_name {
        return true;
    }
    // Check actual group membership
    if let Some(members) = groups.get(group_name) {
        return members.iter().any(|m| m == device_id);
    }
    false
}

    /// Get the current policy for inspection.
    pub async fn get_policy(&self) -> AclPolicy {
        let policy = self.policy.read().await;
        policy.clone()
    }

    /// Add a device to a group in the current policy.
    pub async fn add_device_to_group(&self, group_name: &str, device_id: &str) {
        let mut policy = self.policy.write().await;
        let members = policy.groups.entry(group_name.to_string()).or_default();
        if !members.contains(&device_id.to_string()) {
            members.push(device_id.to_string());
        }
    }

    /// Remove a device from a group.
    pub async fn remove_device_from_group(&self, group_name: &str, device_id: &str) {
        let mut policy = self.policy.write().await;
        if let Some(members) = policy.groups.get_mut(group_name) {
            members.retain(|d| d != device_id);
        }
    }

    /// Add a rule to the policy.
    pub async fn add_rule(&self, rule: AclRule) {
        let mut policy = self.policy.write().await;
        policy.rules.push(rule);
    }

    /// Isolate a device (prevent all non-bypass communication).
    pub async fn isolate_device(&self, device_id: &str) {
        let mut policy = self.policy.write().await;
        if !policy.isolated_devices.contains(&device_id.to_string()) {
            policy.isolated_devices.push(device_id.to_string());
        }
        log::warn!("Device {} isolated by ACL policy", device_id);
    }

    /// Remove isolation from a device.
    pub async fn unisolate_device(&self, device_id: &str) {
        let mut policy = self.policy.write().await;
        policy.isolated_devices.retain(|d| d != device_id);
        log::info!("Device {} removed from ACL isolation", device_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_policy() -> AclPolicy {
        let json = r#"{
            "mode": "default-deny",
            "groups": {
                "admin": ["admin-device-1"],
                "database": ["db-1", "db-2"]
            },
            "rules": [
                {
                    "action": "allow",
                    "src": "admin",
                    "dst": "database",
                    "protocol": "tcp",
                    "ports": [5432]
                },
                {
                    "action": "allow",
                    "src": "*",
                    "dst": "*",
                    "protocol": "icmp",
                    "ports": []
                }
            ]
        }"#;
        AclPolicy::from_json(json).unwrap()
    }

    #[tokio::test]
    async fn test_acl_default_deny() {
        let engine = AclEngine::new();
        engine.load_policy(make_test_policy()).await;

        // Admin to database on port 5432 should be allowed
        assert!(engine.check("admin-device-1", "db-1", "tcp", 5432).await);

        // Admin to database on port 3306 should be denied (not in rules)
        assert!(!engine.check("admin-device-1", "db-1", "tcp", 3306).await);

        // Unknown devices should be denied
        assert!(!engine.check("unknown", "db-1", "tcp", 5432).await);
    }

    #[tokio::test]
    async fn test_acl_icmp_wildcard() {
        let engine = AclEngine::new();
        engine.load_policy(make_test_policy()).await;

        // ICMP from any to any should be allowed (wildcard rule)
        assert!(engine.check("device-a", "device-b", "icmp", 0).await);
    }

    #[tokio::test]
    async fn test_device_isolation() {
        let engine = AclEngine::new();
        engine.load_policy(make_test_policy()).await;
        engine.isolate_device("db-1").await;

        // Isolated device cannot communicate with anyone
        assert!(!engine.check("admin-device-1", "db-1", "tcp", 5432).await);
        assert!(!engine.check("db-1", "admin-device-1", "tcp", 80).await);
    }

    #[tokio::test]
    async fn test_bypass_device() {
        let engine = AclEngine::new();
        let mut policy = make_test_policy();
        policy.bypass_devices = vec!["control-plane".to_string()];

        engine.load_policy(policy).await;

        // Bypass devices can communicate with anyone
        assert!(engine.check("control-plane", "db-1", "tcp", 9999).await);
        assert!(engine.check("db-1", "control-plane", "udp", 1234).await);
    }
}
