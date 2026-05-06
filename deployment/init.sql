-- P2P Mesh Network - Database Initialization
-- Run once during PostgreSQL container startup

-- Extensions (safe to create even if they already exist)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Note: Table creation and indexing are handled by the API service
-- (SQLAlchemy ORM) at application startup. Do NOT add CREATE INDEX
-- statements here — the tables don't exist yet when this script runs.
