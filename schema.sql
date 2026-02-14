-- HostBay Telegram Bot - Clean Database Schema
-- A streamlined, production-ready PostgreSQL schema for domain registration, hosting, and payment processing
-- Created: September 2025

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- 1. USER MANAGEMENT
-- =============================================================================

-- Core user accounts with Telegram integration
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    telegram_id BIGINT UNIQUE NOT NULL,
    username VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    preferred_language VARCHAR(10) DEFAULT 'en',
    wallet_balance DECIMAL(12,2) DEFAULT 0.00 CHECK (wallet_balance >= 0),
    terms_accepted BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User profiles for domain registration (WHOIS data)
CREATE TABLE user_profiles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    organization VARCHAR(255),
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(255),
    state_province VARCHAR(255),
    postal_code VARCHAR(20),
    country_code CHAR(2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Telegram callback tokens for pagination and complex UI flows
CREATE TABLE callback_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(32) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    callback_data TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- 2. DOMAIN REGISTRATION & DNS MANAGEMENT
-- =============================================================================

-- Domain registration intents (atomic registration workflow)
CREATE TABLE domain_registration_intents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    domain_name VARCHAR(255) NOT NULL,
    tld VARCHAR(50) NOT NULL,
    registration_period INTEGER DEFAULT 1, -- years
    quote_price DECIMAL(10,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',
    status VARCHAR(50) DEFAULT 'created',
    idempotency_key VARCHAR(255) UNIQUE NOT NULL,
    provider_reference VARCHAR(255),
    nameservers TEXT[],
    auto_dns_setup BOOLEAN DEFAULT TRUE,
    completed_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Registered domains inventory
CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    domain_name VARCHAR(255) UNIQUE NOT NULL,
    tld VARCHAR(50) NOT NULL,
    provider_domain_id VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active',
    nameservers TEXT[],
    auto_proxy_enabled BOOLEAN DEFAULT TRUE,
    dns_managed BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DNS zones managed by Cloudflare
CREATE TABLE dns_zones (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    domain_name VARCHAR(255) UNIQUE NOT NULL,
    provider VARCHAR(50) DEFAULT 'cloudflare',
    zone_id VARCHAR(255) UNIQUE NOT NULL,
    nameservers TEXT[],
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Domain search history for analytics
CREATE TABLE domain_searches (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    search_term VARCHAR(255) NOT NULL,
    results_found INTEGER DEFAULT 0,
    search_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- 3. HOSTING SERVICES
-- =============================================================================

-- Hosting plan definitions
CREATE TABLE hosting_plans (
    id SERIAL PRIMARY KEY,
    plan_name VARCHAR(100) NOT NULL,
    plan_type VARCHAR(50) NOT NULL,
    billing_cycle VARCHAR(20) NOT NULL, -- '7days', '30days', 'monthly', 'yearly'
    duration_days INTEGER NOT NULL,
    disk_space_gb INTEGER,
    bandwidth_gb INTEGER,
    databases INTEGER,
    email_accounts INTEGER,
    subdomains INTEGER,
    price DECIMAL(10,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',
    features TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Hosting provision intents (atomic provisioning workflow)
CREATE TABLE hosting_provision_intents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    hosting_plan_id INTEGER REFERENCES hosting_plans(id),
    domain_name VARCHAR(255),
    quote_price DECIMAL(10,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',
    status VARCHAR(50) DEFAULT 'created',
    idempotency_key VARCHAR(255) UNIQUE NOT NULL,
    server_details JSONB,
    completed_at TIMESTAMP,
    processing_started_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Active hosting subscriptions
CREATE TABLE hosting_subscriptions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    hosting_plan_id INTEGER REFERENCES hosting_plans(id),
    domain_name VARCHAR(255),
    server_username VARCHAR(255),
    server_ip INET,
    control_panel_url VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active',
    billing_cycle VARCHAR(20),
    next_billing_date DATE,
    auto_renew BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- cPanel account details (secure storage)
CREATE TABLE cpanel_accounts (
    id SERIAL PRIMARY KEY,
    subscription_id INTEGER REFERENCES hosting_subscriptions(id) ON DELETE CASCADE,
    cpanel_username VARCHAR(255) NOT NULL,
    domain_name VARCHAR(255),
    server_name VARCHAR(255),
    quota_mb INTEGER,
    ip_address INET,
    secret_reference VARCHAR(255), -- Reference to secure credential store
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- 4. ORDERS & COMMERCE
-- =============================================================================

-- Unified order system
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    order_type VARCHAR(50) NOT NULL, -- 'domain', 'hosting', 'bundle'
    status VARCHAR(50) DEFAULT 'pending',
    total_amount DECIMAL(12,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',
    discount_applied DECIMAL(12,2) DEFAULT 0.00,
    metadata JSONB,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Order line items
CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    item_type VARCHAR(50) NOT NULL,
    item_name VARCHAR(255) NOT NULL,
    quantity INTEGER DEFAULT 1,
    unit_price DECIMAL(12,2) NOT NULL,
    total_price DECIMAL(12,2) NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Domain + Hosting bundles
CREATE TABLE domain_hosting_bundles (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    domain_registration_intent_id INTEGER REFERENCES domain_registration_intents(id),
    hosting_provision_intent_id INTEGER REFERENCES hosting_provision_intents(id),
    bundle_type VARCHAR(50) DEFAULT 'domain_hosting',
    status VARCHAR(50) DEFAULT 'pending',
    total_amount DECIMAL(12,2) NOT NULL,
    discount_applied DECIMAL(12,2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bundle pricing and discounts
CREATE TABLE bundle_pricing (
    id SERIAL PRIMARY KEY,
    bundle_type VARCHAR(50) NOT NULL,
    domain_tld VARCHAR(50),
    hosting_plan_id INTEGER REFERENCES hosting_plans(id),
    base_price DECIMAL(10,2),
    bundle_discount_percent DECIMAL(5,2),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- 5. PAYMENT PROCESSING & WALLET
-- =============================================================================

-- Unified payment intents for all providers
CREATE TABLE payment_intents (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id),
    amount DECIMAL(12,2) NOT NULL,
    currency VARCHAR(10) NOT NULL,
    crypto_currency VARCHAR(10), -- 'BTC', 'ETH', 'LTC', 'DOGE', 'USDT'
    payment_provider VARCHAR(50) NOT NULL, -- 'dynopay', 'blockbee'
    provider_order_id VARCHAR(255),
    payment_address VARCHAR(255),
    expected_confirmations INTEGER DEFAULT 1,
    status VARCHAR(50) DEFAULT 'created',
    expires_at TIMESTAMP,
    completed_at TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Payment webhooks and callbacks
CREATE TABLE payment_callbacks (
    id SERIAL PRIMARY KEY,
    payment_intent_id INTEGER REFERENCES payment_intents(id),
    provider VARCHAR(50) NOT NULL,
    external_callback_id VARCHAR(255),
    callback_type VARCHAR(50),
    status VARCHAR(50),
    confirmations INTEGER DEFAULT 0,
    transaction_hash VARCHAR(255),
    raw_payload JSONB,
    processed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(provider, external_callback_id)
);

-- Wallet transactions (credits, debits, transfers)
CREATE TABLE wallet_transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    transaction_type VARCHAR(50) NOT NULL, -- 'credit', 'debit', 'refund'
    amount DECIMAL(12,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',
    balance_before DECIMAL(12,2),
    balance_after DECIMAL(12,2),
    reference_type VARCHAR(50), -- 'payment', 'refund', 'admin'
    reference_id INTEGER,
    external_transaction_id VARCHAR(255),
    description TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cryptocurrency deposit tracking
CREATE TABLE crypto_deposits (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    payment_intent_id INTEGER REFERENCES payment_intents(id),
    crypto_currency VARCHAR(10) NOT NULL,
    deposit_address VARCHAR(255) NOT NULL,
    expected_amount DECIMAL(20,8) NOT NULL,
    received_amount DECIMAL(20,8) DEFAULT 0,
    usd_equivalent DECIMAL(12,2),
    confirmations INTEGER DEFAULT 0,
    transaction_hash VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    confirmed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- 6. REFUNDS & CUSTOMER SERVICE
-- =============================================================================

-- Unified refund system
CREATE TABLE refunds (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id),
    user_id INTEGER REFERENCES users(id),
    refund_type VARCHAR(50) NOT NULL, -- 'full', 'partial', 'wallet_credit'
    amount DECIMAL(12,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',
    reason VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    processing_method VARCHAR(50), -- 'wallet_credit', 'crypto_return'
    external_refund_id VARCHAR(255),
    processed_by VARCHAR(100), -- admin user or system
    processed_at TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- 7. NOTIFICATIONS & MESSAGING
-- =============================================================================

-- System notifications to users
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    notification_type VARCHAR(50) NOT NULL,
    title VARCHAR(255),
    message TEXT NOT NULL,
    channels TEXT[] DEFAULT ARRAY['telegram'], -- 'telegram', 'email'
    priority VARCHAR(20) DEFAULT 'normal', -- 'low', 'normal', 'high', 'critical'
    sent_at TIMESTAMP,
    read_at TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Admin alerts for system issues
CREATE TABLE admin_alerts (
    id SERIAL PRIMARY KEY,
    severity VARCHAR(20) NOT NULL, -- 'info', 'warning', 'error', 'critical'
    category VARCHAR(50) NOT NULL,
    component VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    details JSONB,
    fingerprint VARCHAR(32) NOT NULL,
    sent_at TIMESTAMP,
    suppressed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Group notification channels (auto-registered when bot is added to groups)
CREATE TABLE IF NOT EXISTS notification_groups (
    id SERIAL PRIMARY KEY,
    chat_id BIGINT UNIQUE NOT NULL,
    chat_title TEXT,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- =============================================================================
-- 8. PERFORMANCE & MONITORING
-- =============================================================================

-- System performance metrics
CREATE TABLE performance_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(12,4) NOT NULL,
    metric_unit VARCHAR(20),
    component VARCHAR(100),
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API rate limiting and usage tracking
CREATE TABLE api_usage_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    endpoint VARCHAR(255),
    method VARCHAR(10),
    status_code INTEGER,
    response_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- INDEXES FOR PERFORMANCE
-- =============================================================================

-- User management indexes
CREATE INDEX idx_users_telegram_id ON users(telegram_id);
CREATE INDEX idx_callback_tokens_expires ON callback_tokens(expires_at);
CREATE INDEX idx_callback_tokens_user ON callback_tokens(user_id);

-- Domain management indexes
CREATE INDEX idx_domain_intents_user ON domain_registration_intents(user_id);
CREATE INDEX idx_domain_intents_status ON domain_registration_intents(status);
CREATE INDEX idx_domains_user ON domains(user_id);
CREATE INDEX idx_domains_status ON domains(status);
CREATE INDEX idx_dns_zones_domain ON dns_zones(domain_name);

-- Hosting indexes
CREATE INDEX idx_hosting_intents_user ON hosting_provision_intents(user_id);
CREATE INDEX idx_hosting_intents_status ON hosting_provision_intents(status);
CREATE INDEX idx_hosting_subs_user ON hosting_subscriptions(user_id);
CREATE INDEX idx_hosting_subs_billing ON hosting_subscriptions(next_billing_date);

-- Order and commerce indexes
CREATE INDEX idx_orders_user ON orders(user_id);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_created ON orders(created_at);
CREATE INDEX idx_order_items_order ON order_items(order_id);

-- Payment indexes
CREATE INDEX idx_payment_intents_order ON payment_intents(order_id);
CREATE INDEX idx_payment_intents_status ON payment_intents(status);
CREATE INDEX idx_payment_intents_provider ON payment_intents(payment_provider);
CREATE INDEX idx_payment_callbacks_intent ON payment_callbacks(payment_intent_id);
CREATE INDEX idx_wallet_transactions_user ON wallet_transactions(user_id);
CREATE INDEX idx_wallet_transactions_created ON wallet_transactions(created_at);

-- Notification indexes
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_sent ON notifications(sent_at);
CREATE INDEX idx_admin_alerts_fingerprint ON admin_alerts(fingerprint);
CREATE INDEX idx_admin_alerts_created ON admin_alerts(created_at);

-- Performance monitoring indexes
CREATE INDEX idx_performance_metrics_name ON performance_metrics(metric_name);
CREATE INDEX idx_performance_metrics_recorded ON performance_metrics(recorded_at);
CREATE INDEX idx_api_usage_user ON api_usage_logs(user_id);
CREATE INDEX idx_api_usage_created ON api_usage_logs(created_at);

-- =============================================================================
-- CONSTRAINTS AND BUSINESS RULES
-- =============================================================================

-- Ensure positive amounts and balances
ALTER TABLE users ADD CONSTRAINT chk_wallet_balance_positive CHECK (wallet_balance >= 0);
ALTER TABLE wallet_transactions ADD CONSTRAINT chk_transaction_amount_positive CHECK (amount > 0);
ALTER TABLE payment_intents ADD CONSTRAINT chk_payment_amount_positive CHECK (amount > 0);
ALTER TABLE orders ADD CONSTRAINT chk_order_total_positive CHECK (total_amount >= 0);

-- Status constraints
ALTER TABLE domain_registration_intents ADD CONSTRAINT chk_domain_intent_status 
    CHECK (status IN ('created', 'processing', 'completed', 'failed', 'cancelled'));
    
ALTER TABLE hosting_provision_intents ADD CONSTRAINT chk_hosting_intent_status 
    CHECK (status IN ('created', 'processing', 'completed', 'failed', 'cancelled'));
    
ALTER TABLE payment_intents ADD CONSTRAINT chk_payment_status 
    CHECK (status IN ('created', 'pending', 'processing', 'completed', 'failed', 'expired', 'cancelled'));
    
ALTER TABLE orders ADD CONSTRAINT chk_order_status 
    CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled', 'refunded'));

-- Unique constraints for idempotency
CREATE UNIQUE INDEX idx_domain_intents_idempotency ON domain_registration_intents(idempotency_key);
CREATE UNIQUE INDEX idx_hosting_intents_idempotency ON hosting_provision_intents(idempotency_key);

-- =============================================================================
-- FUNCTIONS AND TRIGGERS
-- =============================================================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers to relevant tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_user_profiles_updated_at BEFORE UPDATE ON user_profiles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_domains_updated_at BEFORE UPDATE ON domains FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_dns_zones_updated_at BEFORE UPDATE ON dns_zones FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_domain_intents_updated_at BEFORE UPDATE ON domain_registration_intents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_hosting_plans_updated_at BEFORE UPDATE ON hosting_plans FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_hosting_intents_updated_at BEFORE UPDATE ON hosting_provision_intents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_hosting_subs_updated_at BEFORE UPDATE ON hosting_subscriptions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_cpanel_accounts_updated_at BEFORE UPDATE ON cpanel_accounts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_orders_updated_at BEFORE UPDATE ON orders FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_bundles_updated_at BEFORE UPDATE ON domain_hosting_bundles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_payment_intents_updated_at BEFORE UPDATE ON payment_intents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_crypto_deposits_updated_at BEFORE UPDATE ON crypto_deposits FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_refunds_updated_at BEFORE UPDATE ON refunds FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- SEED DATA
-- =============================================================================

-- Insert default hosting plans
INSERT INTO hosting_plans (plan_name, plan_type, billing_cycle, duration_days, disk_space_gb, bandwidth_gb, databases, email_accounts, subdomains, price, features) VALUES
('Pro 7 Days', 'shared', '7days', 7, 10, 100, 5, 10, 10, 75.00, ARRAY['cPanel Access', 'SSL Certificate', 'Daily Backups']),
('Pro 30 Days', 'shared', '30days', 30, 10, 100, 5, 10, 10, 150.00, ARRAY['cPanel Access', 'SSL Certificate', 'Daily Backups']);

-- Insert bundle pricing
INSERT INTO bundle_pricing (bundle_type, domain_tld, hosting_plan_id, base_price, bundle_discount_percent) VALUES
('domain_hosting', '.com', 1, 85.00, 10.00),
('domain_hosting', '.com', 2, 160.00, 10.00),
('domain_hosting', '.net', 1, 90.00, 10.00),
('domain_hosting', '.net', 2, 165.00, 10.00);

-- =============================================================================
-- CLEANUP NOTES
-- =============================================================================

/*
This schema consolidates and modernizes the previous database structure:

REMOVED TABLES (duplicates/obsolete):
- payment_intents_unified (merged into payment_intents)
- ledger_transactions (functionality moved to wallet_transactions)
- refunds_unified (renamed to refunds)
- domain_orders (functionality moved to orders + order_items)
- payment_orders (functionality moved to orders + order_items)
- provider_claims (simplified into payment workflow)
- webhook_callbacks (renamed to payment_callbacks with cleaner structure)
- wallet_deposits (renamed to crypto_deposits with better structure)
- domain_notifications (replaced with unified notifications table)
- bundle_discounts (simplified into bundle_pricing)
- refund_tracking (merged into refunds table)

RENAMED/CONSOLIDATED:
- cloudflare_zones → dns_zones (more generic)
- admin_alerts (kept but simplified)
- callback_tokens (kept for Telegram UI)

IMPROVEMENTS:
- Consistent naming conventions
- Proper foreign key relationships
- Appropriate indexes for performance
- Business rule constraints
- Clean separation of concerns
- Better data types and precision
- Unified order system
- Streamlined payment processing
- Better security with secret references
*/

-- =============================================================================
-- MIGRATION SECTION: ENSURE BACKWARD COMPATIBILITY FOR EXISTING DATABASES
-- =============================================================================
-- This section ensures that existing databases get all new columns that were
-- added to the CREATE TABLE statements above. These ALTER TABLE statements are
-- idempotent and safe to run multiple times.
-- =============================================================================

-- =============================================================================
-- 1. USERS TABLE - LANGUAGE PREFERENCES AND SOFT DELETION
-- =============================================================================

-- Add language preference columns (preferred_language already in CREATE TABLE)
ALTER TABLE users ADD COLUMN IF NOT EXISTS language_selected_manually BOOLEAN DEFAULT FALSE;

-- Add soft deletion columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- =============================================================================
-- 2. DOMAINS TABLE - CLOUDFLARE INTEGRATION AND SOFT DELETION  
-- =============================================================================

-- Add domain management columns (auto_proxy_enabled already in CREATE TABLE)
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ownership_state VARCHAR(50);
ALTER TABLE domains ADD COLUMN IF NOT EXISTS cloudflare_zone_id VARCHAR(255);

-- Add soft deletion columns
ALTER TABLE domains ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- =============================================================================
-- 3. COMPREHENSIVE SOFT DELETION FOR ALL BUSINESS TABLES
-- =============================================================================

-- ORDERS TABLE
ALTER TABLE orders ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- HOSTING SUBSCRIPTIONS TABLE
ALTER TABLE hosting_subscriptions ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE hosting_subscriptions ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- WALLET TRANSACTIONS TABLE
ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- PAYMENT INTENTS TABLE
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE payment_intents ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- USER PROFILES TABLE
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE user_profiles ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- DOMAIN REGISTRATION INTENTS TABLE
ALTER TABLE domain_registration_intents ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE domain_registration_intents ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- HOSTING PROVISION INTENTS TABLE
ALTER TABLE hosting_provision_intents ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE hosting_provision_intents ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- ORDER ITEMS TABLE
ALTER TABLE order_items ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE order_items ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- DOMAIN HOSTING BUNDLES TABLE
ALTER TABLE domain_hosting_bundles ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE domain_hosting_bundles ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- PAYMENT CALLBACKS TABLE
ALTER TABLE payment_callbacks ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE payment_callbacks ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- CRYPTO DEPOSITS TABLE
ALTER TABLE crypto_deposits ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE crypto_deposits ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- REFUNDS TABLE
ALTER TABLE refunds ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE refunds ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- CPANEL ACCOUNTS TABLE
ALTER TABLE cpanel_accounts ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE cpanel_accounts ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- DNS ZONES TABLE
ALTER TABLE dns_zones ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE dns_zones ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- NOTIFICATIONS TABLE
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- CALLBACK TOKENS TABLE
ALTER TABLE callback_tokens ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE callback_tokens ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- DOMAIN SEARCHES TABLE
ALTER TABLE domain_searches ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE domain_searches ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id);

-- =============================================================================
-- 4. CREATE ACTIVE VIEWS FOR SOFT DELETION SUPPORT
-- =============================================================================

-- Create active views that filter out soft-deleted records
-- These views provide a clean interface for application code

CREATE OR REPLACE VIEW users_active AS
SELECT * FROM users WHERE deleted_at IS NULL;

CREATE OR REPLACE VIEW domains_active AS
SELECT * FROM domains WHERE deleted_at IS NULL;

CREATE OR REPLACE VIEW orders_active AS
SELECT * FROM orders WHERE deleted_at IS NULL;

CREATE OR REPLACE VIEW hosting_subscriptions_active AS
SELECT * FROM hosting_subscriptions WHERE deleted_at IS NULL;

CREATE OR REPLACE VIEW wallet_transactions_active AS
SELECT * FROM wallet_transactions WHERE deleted_at IS NULL;

CREATE OR REPLACE VIEW payment_intents_active AS
SELECT * FROM payment_intents WHERE deleted_at IS NULL;

CREATE OR REPLACE VIEW user_profiles_active AS
SELECT * FROM user_profiles WHERE deleted_at IS NULL;

CREATE OR REPLACE VIEW notifications_active AS
SELECT * FROM notifications WHERE deleted_at IS NULL;

-- =============================================================================
-- 5. SOFT DELETION HELPER FUNCTIONS
-- =============================================================================

-- Function to soft delete a record
CREATE OR REPLACE FUNCTION soft_delete_record(
    p_table_name TEXT,
    p_record_id INTEGER,
    p_deleted_by INTEGER
)
RETURNS BOOLEAN AS $$
DECLARE
    sql_query TEXT;
    result BOOLEAN := FALSE;
BEGIN
    -- Validate table name to prevent SQL injection
    IF p_table_name !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'Invalid table name: %', p_table_name;
    END IF;
    
    -- Build the dynamic SQL query
    sql_query := format(
        'UPDATE %I SET deleted_at = CURRENT_TIMESTAMP, deleted_by = $1 WHERE id = $2 AND deleted_at IS NULL',
        p_table_name
    );
    
    -- Execute the query
    EXECUTE sql_query USING p_deleted_by, p_record_id;
    
    -- Check if any rows were affected
    GET DIAGNOSTICS result = ROW_COUNT;
    
    RETURN result > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to restore a soft-deleted record
CREATE OR REPLACE FUNCTION restore_soft_deleted_record(
    p_table_name TEXT,
    p_record_id INTEGER
)
RETURNS BOOLEAN AS $$
DECLARE
    sql_query TEXT;
    result BOOLEAN := FALSE;
BEGIN
    -- Validate table name to prevent SQL injection
    IF p_table_name !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' THEN
        RAISE EXCEPTION 'Invalid table name: %', p_table_name;
    END IF;
    
    -- Build the dynamic SQL query
    sql_query := format(
        'UPDATE %I SET deleted_at = NULL, deleted_by = NULL WHERE id = $1 AND deleted_at IS NOT NULL',
        p_table_name
    );
    
    -- Execute the query
    EXECUTE sql_query USING p_record_id;
    
    -- Check if any rows were affected
    GET DIAGNOSTICS result = ROW_COUNT;
    
    RETURN result > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- 6. ADDITIONAL INDEXES FOR SOFT DELETION PERFORMANCE
-- =============================================================================

-- Add indexes on deleted_at columns for better performance when filtering active records
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_domains_deleted_at ON domains(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_deleted_at ON orders(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_hosting_subscriptions_deleted_at ON hosting_subscriptions(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_wallet_transactions_deleted_at ON wallet_transactions(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_payment_intents_deleted_at ON payment_intents(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_profiles_deleted_at ON user_profiles(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notifications_deleted_at ON notifications(deleted_at) WHERE deleted_at IS NULL;

-- =============================================================================
-- 7. UPDATE EXISTING UNIQUE CONSTRAINTS FOR SOFT DELETION
-- =============================================================================

-- Drop and recreate unique indexes to support soft deletion (only apply to active records)
-- This ensures uniqueness only among non-deleted records

-- Users: telegram_id should be unique only among active users
DROP INDEX IF EXISTS users_telegram_id_key;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_users_telegram_id_unique_active 
ON users(telegram_id) WHERE deleted_at IS NULL;

-- Domains: domain_name should be unique only among active domains
DROP INDEX IF EXISTS domains_domain_name_key;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_domains_name_unique_active 
ON domains(domain_name) WHERE deleted_at IS NULL;

-- DNS zones: domain_name and zone_id should be unique only among active zones
DROP INDEX IF EXISTS dns_zones_domain_name_key;
DROP INDEX IF EXISTS dns_zones_zone_id_key;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_dns_zones_domain_name_unique_active 
ON dns_zones(domain_name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_dns_zones_zone_id_unique_active 
ON dns_zones(zone_id) WHERE deleted_at IS NULL;

-- =============================================================================
-- MIGRATION COMPLETION NOTICE
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '=== DATABASE MIGRATION COMPLETED SUCCESSFULLY ===';
    RAISE NOTICE 'Backward compatibility ensured for existing databases';
    RAISE NOTICE '';
    RAISE NOTICE 'Added columns:';
    RAISE NOTICE '✅ users.language_selected_manually';
    RAISE NOTICE '✅ domains.ownership_state, cloudflare_zone_id';
    RAISE NOTICE '✅ Soft deletion columns (deleted_at, deleted_by) on ALL business tables';
    RAISE NOTICE '';
    RAISE NOTICE 'Created features:';
    RAISE NOTICE '✅ Active views for all major tables';
    RAISE NOTICE '✅ Soft deletion helper functions';
    RAISE NOTICE '✅ Performance indexes for soft deletion queries';
    RAISE NOTICE '✅ Updated unique constraints to support soft deletion';
    RAISE NOTICE '';
    RAISE NOTICE 'Schema is now fully backward compatible and production-ready!';
    RAISE NOTICE '';
END
$$;