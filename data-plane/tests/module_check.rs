/// Integration test: verify all expected public modules are accessible.
use p2p_mesh_dataplane::relay;
use p2p_mesh_dataplane::stun;
use p2p_mesh_dataplane::puncher;
use p2p_mesh_dataplane::tunnel;
use p2p_mesh_dataplane::quic;
use p2p_mesh_dataplane::multipath;
use p2p_mesh_dataplane::metrics;

#[test]
fn test_modules_exist() {
    // If this compiles, modules are exported correctly
}
