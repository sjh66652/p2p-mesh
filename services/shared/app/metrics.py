"""
Prometheus metrics shared across all p2p-mesh microservices.
"""

from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST

# ---- HTTP Metrics ----
http_requests_total = Counter(
    "p2p_mesh_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "service", "status"],
)

http_request_duration_seconds = Histogram(
    "p2p_mesh_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint", "service"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# ---- WebSocket Metrics ----
ws_connections_active = Gauge(
    "p2p_mesh_ws_connections_active",
    "Number of active WebSocket connections",
    ["node_id"],
)

ws_connections_total = Counter(
    "p2p_mesh_ws_connections_total",
    "Total WebSocket connections established",
    ["node_id"],
)

ws_messages_total = Counter(
    "p2p_mesh_ws_messages_total",
    "Total WebSocket messages processed",
    ["type", "node_id"],
)

# ---- Usage Metrics ----
usage_requests_total = Counter(
    "p2p_mesh_usage_requests_total",
    "Total usage events recorded",
    ["metric_type", "plan"],
)

usage_quota_rejections_total = Counter(
    "p2p_mesh_usage_quota_rejections_total",
    "Total quota rejections",
    ["reason"],
)

usage_active_users = Gauge(
    "p2p_mesh_usage_active_users",
    "Number of active users in the current window",
    ["plan"],
)

# ---- Relay Metrics ----
relay_nodes_online = Gauge(
    "p2p_mesh_relay_nodes_online",
    "Number of online relay nodes",
    ["region"],
)

relay_bandwidth_bytes_total = Counter(
    "p2p_mesh_relay_bandwidth_bytes_total",
    "Total bytes relayed",
    ["relay_id", "region"],
)

# ---- Auth Metrics ----
auth_logins_total = Counter(
    "p2p_mesh_auth_logins_total",
    "Total login attempts",
    ["status"],
)

auth_active_sessions = Gauge(
    "p2p_mesh_auth_active_sessions",
    "Estimated active sessions (from refresh tokens)",
)

# ---- Service Info ----
service_info = Info(
    "p2p_mesh_service",
    "Service metadata",
)


def init_metrics(service_name: str, version: str = "1.0.0"):
    """Initialize service info metric."""
    service_info.info({
        "service": service_name,
        "version": version,
    })
