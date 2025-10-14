-- PostgreSQL Initial Schema Migration
-- Creates the core users table with comprehensive authentication features

-- Enable UUID extension for better ID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table with comprehensive authentication features
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(36) UNIQUE NOT NULL DEFAULT uuid_generate_v4()::text,
    email VARCHAR(320) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    email_verification_token VARCHAR(255),
    email_verification_expires TIMESTAMPTZ,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMPTZ,
    last_login TIMESTAMPTZ,
    login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_user_id ON users(user_id);
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token) 
    WHERE email_verification_token IS NOT NULL;
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token) 
    WHERE password_reset_token IS NOT NULL;
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_last_login ON users(last_login);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active);
CREATE INDEX idx_users_locked ON users(locked_until) 
    WHERE locked_until IS NOT NULL;

-- GIN index for JSONB metadata queries
CREATE INDEX idx_users_metadata ON users USING GIN(metadata);

-- Constraints and validations
ALTER TABLE users ADD CONSTRAINT chk_users_email 
    CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');

ALTER TABLE users ADD CONSTRAINT chk_users_role 
    CHECK (role IN ('user', 'admin', 'moderator', 'guest'));

ALTER TABLE users ADD CONSTRAINT chk_users_login_attempts 
    CHECK (login_attempts >= 0 AND login_attempts <= 100);

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at on user changes
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();

-- Function to cleanup expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    UPDATE users 
    SET 
        email_verification_token = NULL,
        email_verification_expires = NULL
    WHERE email_verification_expires IS NOT NULL 
    AND email_verification_expires < NOW();
    
    UPDATE users 
    SET 
        password_reset_token = NULL,
        password_reset_expires = NULL
    WHERE password_reset_expires IS NOT NULL 
    AND password_reset_expires < NOW();
    
    UPDATE users 
    SET 
        locked_until = NULL
    WHERE locked_until IS NOT NULL 
    AND locked_until < NOW();
END;
$$ LANGUAGE plpgsql;

-- Create a scheduled job (requires pg_cron extension in production)
-- SELECT cron.schedule('cleanup-expired-tokens', '0 */6 * * *', 'SELECT cleanup_expired_tokens();');

-- Comments for documentation
COMMENT ON TABLE users IS 'Core users table for authentication and user management';
COMMENT ON COLUMN users.user_id IS 'Public UUID identifier for the user';
COMMENT ON COLUMN users.email IS 'User email address, must be unique and valid';
COMMENT ON COLUMN users.password_hash IS 'Bcrypt hashed password';
COMMENT ON COLUMN users.role IS 'User role for authorization (user, admin, moderator, guest)';
COMMENT ON COLUMN users.metadata IS 'Additional user data stored as JSON';
COMMENT ON COLUMN users.login_attempts IS 'Number of consecutive failed login attempts';
COMMENT ON COLUMN users.locked_until IS 'Timestamp until which the account is locked';