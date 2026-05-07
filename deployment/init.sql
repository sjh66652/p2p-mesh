-- P2P Mesh Network - Database Initialization (v2.0.0)
-- Run once during PostgreSQL container startup
--
-- Phase 1 additions: virtual_ips, route_table, acl_policies

-- Extensions (safe to create even if they already exist)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Virtual IP assignments (IPAM)
-- Maps device_id -> overlay virtual IP in 100.64.0.0/10
CREATE TABLE IF NOT EXISTS virtual_ips (
    device_id UUID PRIMARY KEY,
    virtual_ip INET UNIQUE NOT NULL,
    allocated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    released_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_virtual_ips_ip ON virtual_ips (virtual_ip);
CREATE INDEX IF NOT EXISTS idx_virtual_ips_status ON virtual_ips (status);

-- Overlay route table
-- Stores CIDR routes for the mesh routing layer
CREATE TABLE IF NOT EXISTS route_table (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cidr INET NOT NULL,
    peer_device_id UUID NOT NULL,
    metric INTEGER DEFAULT 10,
    admin_distance INTEGER DEFAULT 1,
    route_type VARCHAR(20) DEFAULT 'mesh',
    active INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(cidr, peer_device_id)
);

CREATE INDEX IF NOT EXISTS idx_route_table_cidr ON route_table (cidr);
CREATE INDEX IF NOT EXISTS idx_route_table_peer ON route_table (peer_device_id);
CREATE INDEX IF NOT EXISTS idx_route_table_active ON route_table (active);

-- ACL policy versions
-- Versioned policy documents for network access control
CREATE TABLE IF NOT EXISTS acl_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    version INTEGER DEFAULT 1,
    policy_json JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    comment TEXT,
    UNIQUE(version)
);

CREATE INDEX IF NOT EXISTS idx_acl_policies_status ON acl_policies (status);

-- Note: Table creation and indexing are also handled by the API service
-- (SQLAlchemy ORM) at application startup. These CREATE IF NOT EXISTS
-- statements ensure tables exist even if the API hasn't started yet.
