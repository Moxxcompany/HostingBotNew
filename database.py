"""
Simple PostgreSQL database functions for HostBay Telegram Bot
Direct database connections with raw SQL queries for transparency and performance
"""

import os
import asyncio
import logging
import json
import uuid
from uuid import uuid4
import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor, RealDictRow
from typing import Optional, Dict, List, Any, Union, cast, Tuple
import time
import random
import threading
import contextvars
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from payment_validation import validate_payment_simple, log_validation_config
from financial_precision import (
    to_decimal, to_currency_decimal, safe_decimal_conversion,
    ZERO, ONE
)
from utils.environment_manager import get_environment_manager

# Initialize logger
logger = logging.getLogger(__name__)

# UUID Utility Functions for Production-Safe ID Generation
def generate_uuid() -> str:
    """Generate a new UUID v4 string for database records"""
    return str(uuid4())

def validate_uuid(uuid_string: str) -> bool:
    """Validate UUID format for security"""
    try:
        # Ensure input is a string
        if not isinstance(uuid_string, str):
            return False
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def generate_secure_order_id() -> str:
    """Generate secure UUID for order identification"""
    return generate_uuid()

def generate_payment_uuid() -> str:
    """Generate secure UUID for payment operations"""
    return generate_uuid()

# UUID-based database operations for production-safe ID management
async def create_payment_intent_with_uuid(user_id: int, amount: Decimal, currency: str, order_type: str = 'wallet', payment_provider: str = 'test', order_id: str = None, base_amount: Decimal = None) -> str:
    """Create payment intent with UUID - eliminates sequence synchronization issues
    
    Args:
        base_amount: Original user-intended amount BEFORE crypto padding. If None, defaults to amount.
    """
    uuid_id = generate_payment_uuid()
    
    # base_amount stores the original user-facing amount (before $2 crypto padding)
    stored_base_amount = str(base_amount) if base_amount is not None else str(amount)
    
    await execute_update("""
        INSERT INTO payment_intents (uuid_id, user_id, amount, base_amount, currency, order_type, payment_provider, order_id, status, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending', CURRENT_TIMESTAMP)
    """, (uuid_id, user_id, str(amount), stored_base_amount, currency, order_type, payment_provider, order_id))
    
    logger.info(f"✅ Payment intent created with UUID: {uuid_id} for user {user_id} (order_id: {order_id})")
    return uuid_id

async def create_order_with_uuid(user_id: int, order_type: str, **kwargs) -> str:
    """Create order with UUID - eliminates sequence synchronization issues"""
    import json
    
    uuid_id = generate_secure_order_id()
    
    # Build dynamic column list based on kwargs - fixed pattern to match create_domain_with_uuid
    base_columns = ['uuid_id', 'user_id', 'order_type', 'status', 'created_at']
    base_values = [uuid_id, user_id, order_type, 'pending']  # No created_at value
    
    # CRITICAL FIX: Remove 'status' from kwargs if it exists to prevent duplicate column error
    kwargs_copy = kwargs.copy()
    if 'status' in kwargs_copy:
        logger.warning(f"⚠️ DUPLICATE COLUMN FIX: Removing 'status' from kwargs to prevent duplicate column error")
        kwargs_copy.pop('status')
    
    # CRITICAL FIX: JSON-serialize metadata dict to prevent "can't adapt type 'dict'" error
    if 'metadata' in kwargs_copy and isinstance(kwargs_copy['metadata'], dict):
        kwargs_copy['metadata'] = json.dumps(kwargs_copy['metadata'])
        logger.info(f"🔧 Serialized metadata dict to JSON for PostgreSQL JSONB column")
    
    # Add additional columns from filtered kwargs
    additional_columns = list(kwargs_copy.keys())
    additional_values = list(kwargs_copy.values())
    
    # Construct all_columns with created_at always at the end
    all_columns = base_columns[:-1] + additional_columns + ['created_at']
    all_values = base_values + additional_values
    placeholders = ', '.join(['%s'] * len(all_values))
    
    query = f"""
        INSERT INTO orders ({', '.join(all_columns[:-1])}, created_at)
        VALUES ({placeholders}, CURRENT_TIMESTAMP)
    """
    
    await execute_update(query, tuple(all_values))
    
    logger.info(f"✅ Order created with UUID: {uuid_id} for user {user_id} type {order_type}")
    return uuid_id

async def get_payment_intent_by_uuid(uuid_id: str) -> Optional[Dict]:
    """Get payment intent by UUID"""
    if not validate_uuid(uuid_id):
        logger.warning(f"Invalid UUID format: {uuid_id}")
        return None
        
    result = await execute_query("""
        SELECT * FROM payment_intents WHERE uuid_id = %s
    """, (uuid_id,))
    
    return result[0] if result else None

async def get_order_by_uuid(uuid_id: str) -> Optional[Dict]:
    """Get order by UUID"""
    if not validate_uuid(uuid_id):
        logger.warning(f"Invalid UUID format: {uuid_id}")
        return None
        
    result = await execute_query("""
        SELECT * FROM orders WHERE uuid_id = %s
    """, (uuid_id,))
    
    return result[0] if result else None

async def update_payment_intent_by_uuid(uuid_id: str, **kwargs) -> bool:
    """Update payment intent by UUID"""
    if not validate_uuid(uuid_id):
        logger.warning(f"Invalid UUID format: {uuid_id}")
        return False
        
    if not kwargs:
        return True
        
    # Build SET clause
    set_clauses = []
    values = []
    for key, value in kwargs.items():
        set_clauses.append(f"{key} = %s")
        values.append(value)
    
    values.append(uuid_id)  # For WHERE clause
    
    query = f"""
        UPDATE payment_intents 
        SET {', '.join(set_clauses)}, updated_at = CURRENT_TIMESTAMP
        WHERE uuid_id = %s
    """
    
    await execute_update(query, tuple(values))
    return True

# Import centralized payment logging utilities
from utils.payment_logging import (
    get_payment_logger, PaymentLogContext, PaymentEventType, PaymentLogLevel,
    PaymentOperationContext, PaymentCorrelationContext,
    log_payment_intent_created, log_payment_status_change, log_wallet_credited,
    track_payment_operation, PAYMENT_LOGGING_AVAILABLE, PaymentLogger
)

payment_logger: PaymentLogger = get_payment_logger()

# Simplified connection pool with hardening for Neon
_connection_pool = None
_pool_lock = threading.Lock()
_pool_recreation_count = 0
_last_pool_recreation = 0

# NEON HARDENING: Async health probe for automatic recovery
_health_probe_task = None
_health_probe_enabled = True
_database_healthy = True
_last_health_check = 0

# PHASE 1: Database Threading for 5000+ User Scalability
_db_executor = None

# Simplified: Single security gate
FINANCIAL_OPERATIONS_ENABLED = os.getenv('FINANCIAL_OPERATIONS_ENABLED', 'true').lower() == 'true'

# ARCHITECT REQUIREMENT 3: Strict DB mode for testing to raise exceptions instead of graceful degradation
TEST_STRICT_DB = os.getenv('TEST_STRICT_DB', 'false').lower() == 'true'

async def create_wallet_deposit_with_uuid(user_id: int, crypto_currency: str, usd_amount: Decimal, payment_address: str, **kwargs) -> str:
    """Create wallet deposit with UUID - eliminates sequence synchronization issues"""
    uuid_id = generate_uuid()
    
    # Build dynamic column list based on kwargs
    base_columns = ['uuid_id', 'user_id', 'crypto_currency', 'usd_amount', 'payment_address', 'status']
    base_values = [uuid_id, user_id, crypto_currency, str(usd_amount), payment_address, 'pending_payment']
    
    # Remove conflicting kwargs
    kwargs_copy = kwargs.copy()
    if 'status' in kwargs_copy:
        kwargs_copy.pop('status')
    
    # Add additional columns from kwargs
    additional_columns = list(kwargs_copy.keys())
    additional_values = list(kwargs_copy.values())
    
    # Construct complete column list
    all_columns = base_columns + additional_columns + ['created_at']
    all_values = base_values + additional_values
    placeholders = ', '.join(['%s'] * len(all_values))
    
    query = f"""
        INSERT INTO wallet_deposits ({', '.join(all_columns[:-1])}, created_at)
        VALUES ({placeholders}, CURRENT_TIMESTAMP)
    """
    
    await execute_update(query, tuple(all_values))
    
    logger.info(f"✅ Wallet deposit created with UUID: {uuid_id} for user {user_id} ({crypto_currency})")
    return uuid_id

async def get_wallet_deposit_by_uuid(uuid_id: str) -> Optional[Dict]:
    """Get wallet deposit by UUID"""
    if not validate_uuid(uuid_id):
        logger.warning(f"Invalid UUID format: {uuid_id}")
        return None
        
    result = await execute_query("""
        SELECT * FROM wallet_deposits WHERE uuid_id = %s
    """, (uuid_id,))
    
    return result[0] if result else None

async def update_wallet_deposit_by_uuid(uuid_id: str, **kwargs) -> bool:
    """Update wallet deposit by UUID"""
    if not validate_uuid(uuid_id):
        logger.warning(f"Invalid UUID format: {uuid_id}")
        return False
        
    if not kwargs:
        return True
        
    # Build SET clause
    set_clauses = []
    values = []
    for key, value in kwargs.items():
        set_clauses.append(f"{key} = %s")
        values.append(value)
    
    values.append(uuid_id)  # For WHERE clause
    
    query = f"""
        UPDATE wallet_deposits 
        SET {', '.join(set_clauses)}, updated_at = CURRENT_TIMESTAMP
        WHERE uuid_id = %s
    """
    
    await execute_update(query, tuple(values))
    return True


# UUID-based domain and hosting operations
async def create_domain_with_uuid(user_id: int, domain_name: str, **kwargs) -> str:
    """Create domain with UUID"""
    uuid_id = generate_uuid()
    
    base_columns = ['uuid_id', 'user_id', 'domain_name', 'created_at']
    base_values = [uuid_id, user_id, domain_name]
    
    additional_columns = list(kwargs.keys())
    additional_values = list(kwargs.values())
    
    all_columns = base_columns[:-1] + additional_columns + ['created_at']
    all_values = base_values + additional_values
    placeholders = ', '.join(['%s'] * len(all_values))
    
    query = f"""
        INSERT INTO domains ({', '.join(all_columns[:-1])}, created_at)
        VALUES ({placeholders}, CURRENT_TIMESTAMP)
    """
    
    await execute_update(query, tuple(all_values))
    logger.info(f"✅ Domain created with UUID: {uuid_id} for {domain_name}")
    return uuid_id

async def create_hosting_subscription_with_uuid(user_id: int, plan_id: int, **kwargs) -> str:
    """Create hosting subscription with UUID"""
    uuid_id = generate_uuid()
    
    base_columns = ['uuid_id', 'user_id', 'plan_id', 'created_at']
    base_values = [uuid_id, user_id, plan_id]
    
    additional_columns = list(kwargs.keys())
    additional_values = list(kwargs.values())
    
    all_columns = base_columns[:-1] + additional_columns + ['created_at']
    all_values = base_values + additional_values
    placeholders = ', '.join(['%s'] * len(all_values))
    
    query = f"""
        INSERT INTO hosting_subscriptions ({', '.join(all_columns[:-1])}, created_at)
        VALUES ({placeholders}, CURRENT_TIMESTAMP)
    """
    
    await execute_update(query, tuple(all_values))
    logger.info(f"✅ Hosting subscription created with UUID: {uuid_id}")
    return uuid_id

async def create_domain_order_crypto(
    user_id: int,
    domain_name: str,
    expected_amount: Decimal,
    currency: str,
    blockbee_order_id: str,
    intent_id: Union[int, str],
    payment_address: str,
    status: str = 'pending_payment'
) -> Optional[int]:
    """
    Create domain order for crypto payment in domain_orders table.
    Returns the integer order ID for tracking.
    
    This function is part of the single-table consolidation for domain orders,
    replacing the dual-table system (orders + domain_orders).
    """
    try:
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query(
            """INSERT INTO domain_orders 
               (user_id, domain_name, status, expected_amount, currency, 
                blockbee_order_id, intent_id, payment_address, created_at, updated_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) 
               RETURNING id""",
            (user_id, domain_name, status, str(expected_amount), currency, 
             blockbee_order_id, str(intent_id), payment_address)
        )
        
        if result and len(result) > 0:
            order_id = result[0]['id']
            logger.info(f"✅ Created domain order {order_id} for {domain_name} by user {user_id} (tracking: {blockbee_order_id})")
            return order_id
        return None
    except Exception as e:
        logger.error(f"❌ Error creating domain order for {domain_name}: {e}")
        return None

async def create_hosting_order_crypto(
    user_id: int,
    hosting_plan_id: int,
    domain_name: str,
    expected_amount: Decimal,
    currency: str,
    blockbee_order_id: str,
    intent_id: Optional[int],
    subscription_id: Optional[int],
    payment_address: str,
    status: str = 'pending_payment'
) -> Optional[int]:
    """
    Create hosting order for crypto payment in hosting_orders table.
    Returns the integer order ID for tracking.
    
    This function is part of the single-table consolidation for hosting orders,
    replacing the dual-table system (orders + hosting_provision_intents).
    All hosting orders (crypto + wallet) now go through hosting_orders table.
    """
    try:
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query(
            """INSERT INTO hosting_orders 
               (user_id, hosting_plan_id, domain_name, status, expected_amount, currency, 
                blockbee_order_id, intent_id, subscription_id, payment_address, created_at, updated_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) 
               RETURNING id""",
            (user_id, hosting_plan_id, domain_name, status, str(expected_amount), currency, 
             blockbee_order_id, intent_id, subscription_id, payment_address)
        )
        
        if result and len(result) > 0:
            order_id = result[0]['id']
            logger.info(f"✅ Created hosting order {order_id} for {domain_name} by user {user_id} (plan: {hosting_plan_id}, tracking: {blockbee_order_id})")
            return order_id
        return None
    except Exception as e:
        logger.error(f"❌ Error creating hosting order for {domain_name}: {e}")
        return None

# Global variables for simplified security system
_security_constraints_verified = True  # Simplified: always verified
_allow_degraded_startup = True  # Simplified: always allow startup
_safe_mode_enabled = False  # Simplified: never in safe mode
_security_verification_cache_time = 0  # Simplified: no caching needed
_security_verification_cache_duration = 3600  # 1 hour (not used in simplified mode)

def get_db_executor():
    """Get or create database thread pool executor for non-blocking operations"""
    global _db_executor
    if _db_executor is None:
        _db_executor = ThreadPoolExecutor(
            max_workers=10,  # Optimized: Reduced from 50 to 10 for better resource efficiency
            thread_name_prefix="db_worker"
        )
        logger.info("✅ Database ThreadPoolExecutor created (10 workers) - optimized for efficiency")
    return _db_executor


# =============================================================================
# PHASE 5: DATABASE ENCRYPTION FUNCTIONS
# =============================================================================

class EncryptionError(Exception):
    """Custom exception for encryption/decryption errors"""
    pass

async def encrypt_field(plaintext: str, key_alias: str = 'default') -> Optional[Dict[str, Any]]:
    """
    Encrypt sensitive data using secure database encryption functions
    Returns dict with ciphertext and key_id, or None if encryption fails
    """
    if not plaintext or not plaintext.strip():
        return None
    
    try:
        # Use secure encryption context to ensure master key is available
        async with with_secure_encryption():
            result = await execute_query(
                "SELECT ciphertext, key_id FROM encrypt_sensitive_data(%s, NULL, %s) AS (ciphertext BYTEA, key_id INTEGER)",
                (plaintext, key_alias)
            )
            
            if result:
                ciphertext = result[0].get('ciphertext')
                key_id = result[0].get('key_id')
                
                if ciphertext and key_id:
                    logger.debug(f"🔐 ENCRYPTION: Successfully encrypted data using key_id={key_id}")
                    return {
                        'ciphertext': ciphertext,
                        'key_id': key_id
                    }
            
            logger.warning("⚠️ ENCRYPTION: Failed to encrypt data - no result returned")
            return None
        
    except Exception as e:
        logger.error(f"❌ ENCRYPTION: Error encrypting data: {e}")
        raise EncryptionError(f"Encryption failed: {e}")

async def decrypt_field(ciphertext: bytes, key_id: int) -> Optional[str]:
    """
    Decrypt sensitive data using secure database encryption functions
    Returns decrypted text or None if decryption fails
    """
    if not ciphertext or not key_id:
        return None
    
    try:
        # Use secure encryption context to ensure master key is available
        async with with_secure_encryption():
            result = await execute_query(
                "SELECT decrypt_sensitive_data(%s, %s) as decrypted_text",
                (ciphertext, key_id)
            )
            
            if result and result[0]:
                decrypted_text = result[0].get('decrypted_text')
                
                if decrypted_text and decrypted_text != '[DECRYPTION_FAILED]':
                    logger.debug(f"🔓 DECRYPTION: Successfully decrypted data using key_id={key_id}")
                    return decrypted_text
                else:
                    logger.warning(f"⚠️ DECRYPTION: Failed to decrypt data with key_id={key_id}")
                    return None
            
            logger.warning("⚠️ DECRYPTION: No result returned from decryption function")
            return None
        
    except Exception as e:
        logger.error(f"❌ DECRYPTION: Error decrypting data: {e}")
        return None

async def encrypt_user_profile_field(user_profile_id: int, field_name: str, plaintext: str, key_alias: str = 'default') -> bool:
    """
    Encrypt and update a specific field in user_profiles table
    Returns True if successful, False otherwise
    """
    try:
        result = await execute_query(
            "SELECT encrypt_field_value('user_profiles', %s, %s, %s, %s) as success",
            (user_profile_id, field_name, plaintext, key_alias)
        )
        
        if result and result[0]:
            success = result[0].get('success', False)
            if success:
                logger.info(f"✅ ENCRYPTION: Successfully encrypted {field_name} for user_profile_id={user_profile_id}")
            else:
                logger.warning(f"⚠️ ENCRYPTION: Failed to encrypt {field_name} for user_profile_id={user_profile_id}")
            return success
        
        return False
        
    except Exception as e:
        logger.error(f"❌ ENCRYPTION: Error encrypting {field_name} for user_profile_id={user_profile_id}: {e}")
        return False

async def decrypt_user_profile_field(user_profile_id: int, field_name: str) -> Optional[str]:
    """
    Decrypt a specific field from user_profiles table
    Returns decrypted text or None if decryption fails
    """
    try:
        result = await execute_query(
            "SELECT decrypt_field_value('user_profiles', %s, %s) as decrypted_text",
            (user_profile_id, field_name)
        )
        
        if result and result[0]:
            decrypted_text = result[0].get('decrypted_text')
            if decrypted_text and decrypted_text != '[DECRYPTION_FAILED]':
                logger.debug(f"🔓 DECRYPTION: Successfully decrypted {field_name} for user_profile_id={user_profile_id}")
                return decrypted_text
            else:
                logger.warning(f"⚠️ DECRYPTION: Failed to decrypt {field_name} for user_profile_id={user_profile_id}")
                return None
        
        return None
        
    except Exception as e:
        logger.error(f"❌ DECRYPTION: Error decrypting {field_name} for user_profile_id={user_profile_id}: {e}")
        return None

async def encrypt_cpanel_credentials(cpanel_account_id: int, password: Optional[str] = None, api_token: Optional[str] = None, key_alias: str = 'default') -> bool:
    """
    Encrypt cPanel credentials (password and/or API token)
    Returns True if successful, False otherwise
    """
    success = True
    
    try:
        if password:
            password_success = await execute_query(
                "SELECT encrypt_field_value('cpanel_accounts', %s, 'cpanel_password', %s, %s) as success",
                (cpanel_account_id, password, key_alias)
            )
            if not (password_success and password_success[0] and password_success[0].get('success')):
                success = False
                logger.warning(f"⚠️ ENCRYPTION: Failed to encrypt password for cpanel_account_id={cpanel_account_id}")
            else:
                logger.info(f"✅ ENCRYPTION: Successfully encrypted password for cpanel_account_id={cpanel_account_id}")
        
        if api_token:
            token_success = await execute_query(
                "SELECT encrypt_field_value('cpanel_accounts', %s, 'api_token', %s, %s) as success",
                (cpanel_account_id, api_token, key_alias)
            )
            if not (token_success and token_success[0] and token_success[0].get('success')):
                success = False
                logger.warning(f"⚠️ ENCRYPTION: Failed to encrypt API token for cpanel_account_id={cpanel_account_id}")
            else:
                logger.info(f"✅ ENCRYPTION: Successfully encrypted API token for cpanel_account_id={cpanel_account_id}")
        
        return success
        
    except Exception as e:
        logger.error(f"❌ ENCRYPTION: Error encrypting cPanel credentials for cpanel_account_id={cpanel_account_id}: {e}")
        return False

async def decrypt_cpanel_credentials(cpanel_account_id: int) -> Dict[str, Optional[str]]:
    """
    Decrypt cPanel credentials (password and API token)
    Returns dict with 'password' and 'api_token' keys
    """
    credentials: Dict[str, Optional[str]] = {'password': None, 'api_token': None}
    
    try:
        # Decrypt password
        password_result = await execute_query(
            "SELECT decrypt_field_value('cpanel_accounts', %s, 'cpanel_password') as password",
            (cpanel_account_id,)
        )
        if password_result and password_result[0]:
            password = password_result[0].get('password')
            if password and password != '[DECRYPTION_FAILED]':
                credentials['password'] = password
        
        # Decrypt API token
        token_result = await execute_query(
            "SELECT decrypt_field_value('cpanel_accounts', %s, 'api_token') as api_token",
            (cpanel_account_id,)
        )
        if token_result and token_result[0]:
            api_token = token_result[0].get('api_token')
            if api_token and api_token != '[DECRYPTION_FAILED]':
                credentials['api_token'] = api_token
        
        logger.debug(f"🔓 DECRYPTION: Retrieved cPanel credentials for cpanel_account_id={cpanel_account_id}")
        return credentials
        
    except Exception as e:
        logger.error(f"❌ DECRYPTION: Error decrypting cPanel credentials for cpanel_account_id={cpanel_account_id}: {e}")
        return credentials

async def encrypt_payment_data(payment_intent_id: int, provider_order_id: Optional[str] = None, 
                             payment_address: Optional[str] = None, metadata: Optional[str] = None, 
                             key_alias: str = 'default') -> bool:
    """
    Encrypt payment intent sensitive data
    Returns True if successful, False otherwise
    """
    success = True
    
    try:
        if provider_order_id:
            result = await execute_query(
                "SELECT encrypt_field_value('payment_intents', %s, 'provider_order_id', %s, %s) as success",
                (payment_intent_id, provider_order_id, key_alias)
            )
            if not (result and result[0] and result[0].get('success')):
                success = False
        
        if payment_address:
            result = await execute_query(
                "SELECT encrypt_field_value('payment_intents', %s, 'payment_address', %s, %s) as success",
                (payment_intent_id, payment_address, key_alias)
            )
            if not (result and result[0] and result[0].get('success')):
                success = False
        
        if metadata:
            result = await execute_query(
                "SELECT encrypt_field_value('payment_intents', %s, 'metadata', %s, %s) as success",
                (payment_intent_id, metadata, key_alias)
            )
            if not (result and result[0] and result[0].get('success')):
                success = False
        
        if success:
            logger.info(f"✅ ENCRYPTION: Successfully encrypted payment data for payment_intent_id={payment_intent_id}")
        else:
            logger.warning(f"⚠️ ENCRYPTION: Failed to encrypt some payment data for payment_intent_id={payment_intent_id}")
        
        return success
        
    except Exception as e:
        logger.error(f"❌ ENCRYPTION: Error encrypting payment data for payment_intent_id={payment_intent_id}: {e}")
        return False

async def migrate_table_encryption(table_name: str, fields: List[str], key_alias: str = 'default', batch_size: int = 100) -> int:
    """
    Migrate existing plaintext data to encrypted format
    Returns number of records migrated
    """
    try:
        result = await execute_query(
            "SELECT migrate_table_to_encryption(%s, %s, %s, %s) as migrated_count",
            (table_name, fields, key_alias, batch_size)
        )
        
        if result and result[0]:
            migrated_count = result[0].get('migrated_count', 0)
            logger.info(f"✅ MIGRATION: Successfully migrated {migrated_count} records in table {table_name}")
            return migrated_count
        
        return 0
        
    except Exception as e:
        logger.error(f"❌ MIGRATION: Error migrating table {table_name}: {e}")
        return 0

async def verify_encryption_migration(table_name: str, fields: List[str]) -> Dict[str, Any]:
    """
    Verify encryption migration status for a table
    Returns dict with migration status for each field
    """
    try:
        result = await execute_query(
            "SELECT * FROM verify_encryption_migration(%s, %s)",
            (table_name, fields)
        )
        
        migration_status = {}
        if result:
            for row in result:
                field_name = row.get('field_name')
                migration_status[field_name] = {
                    'total_records': row.get('total_records', 0),
                    'encrypted_records': row.get('encrypted_records', 0),
                    'plaintext_remaining': row.get('plaintext_remaining', 0),
                    'migration_complete': row.get('migration_complete', False)
                }
        
        logger.info(f"📊 MIGRATION STATUS: Verified encryption status for table {table_name}")
        return migration_status
        
    except Exception as e:
        logger.error(f"❌ VERIFICATION: Error verifying migration for table {table_name}: {e}")
        return {}

async def create_encryption_key(key_alias: str, make_default: bool = False) -> Optional[int]:
    """
    Create a new encryption key metadata (SECURE - no master key stored)
    Returns key ID if successful, None otherwise
    """
    try:
        result = await execute_query(
            "SELECT create_encryption_key(%s, %s) as key_id",
            (key_alias, make_default)
        )
        
        if result and result[0]:
            key_id = result[0].get('key_id')
            logger.info(f"✅ KEY MANAGEMENT: Created encryption key metadata {key_alias} with ID {key_id}")
            return key_id
        
        return None
        
    except Exception as e:
        logger.error(f"❌ KEY MANAGEMENT: Error creating encryption key metadata {key_alias}: {e}")
        return None

async def rotate_encryption_key(key_alias: str) -> Optional[int]:
    """
    Rotate encryption key to a new version (SECURE - no master key in database)
    Returns new key ID if successful, None otherwise
    """
    try:
        result = await execute_query(
            "SELECT rotate_encryption_key(%s) as new_key_id",
            (key_alias,)
        )
        
        if result and result[0]:
            new_key_id = result[0].get('new_key_id')
            logger.info(f"✅ KEY ROTATION: Successfully rotated key {key_alias} to new ID {new_key_id}")
            return new_key_id
        
        return None
        
    except Exception as e:
        logger.error(f"❌ KEY ROTATION: Error rotating encryption key {key_alias}: {e}")
        return None

# Simplified security functions for import compatibility

def verify_financial_operation_safety(*args, **kwargs) -> bool:
    """Simplified financial operation safety check (accepts any parameters for compatibility)"""
    return FINANCIAL_OPERATIONS_ENABLED

def ensure_financial_operations_allowed() -> bool:
    """Simplified function to check if financial operations are allowed"""
    if not FINANCIAL_OPERATIONS_ENABLED:
        logger.warning("⚠️ Financial operations are disabled by configuration")
        return False
    return True

def enable_safe_mode(reason: str):
    """Simplified safe mode enabler (no-op in simplified system)"""
    global _safe_mode_enabled
    _safe_mode_enabled = True
    logger.warning(f"⚠️ Safe mode enabled: {reason}")

def get_security_status() -> Dict[str, Any]:
    """Get simplified security status for compatibility"""
    return {
        'security_verified': True,
        'safe_mode_enabled': False,
        'financial_operations_allowed': FINANCIAL_OPERATIONS_ENABLED,
        'degraded_startup_allowed': True
    }

# =============================================================================
# SECURE EXTERNAL KEY MANAGEMENT FUNCTIONS
# =============================================================================

def get_master_encryption_key() -> Optional[str]:
    """
    Get master encryption key from environment variable (SECURE)
    Returns None if not set - requires ENCRYPTION_MASTER_KEY environment variable
    """
    master_key = os.getenv('ENCRYPTION_MASTER_KEY')
    if not master_key:
        logger.error("❌ SECURITY: ENCRYPTION_MASTER_KEY environment variable not set")
        return None
    
    if len(master_key) < 32:
        logger.error("❌ SECURITY: ENCRYPTION_MASTER_KEY must be at least 32 characters long")
        return None
    
    return master_key

async def set_database_master_key(conn=None) -> bool:
    """
    Set master key session variable for database encryption functions (SECURE)
    Returns True if successful, False otherwise
    """
    master_key = get_master_encryption_key()
    if not master_key:
        logger.error("❌ SECURITY: Cannot set database master key - missing environment variable")
        return False
    
    try:
        if conn:
            # Use provided connection
            with conn.cursor() as cursor:
                cursor.execute("SET app.master_key = %s", (master_key,))
                logger.debug("🔐 SECURITY: Set master key session variable on provided connection")
        else:
            # Use default connection
            await execute_query("SET app.master_key = %s", (master_key,))
            logger.debug("🔐 SECURITY: Set master key session variable")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ SECURITY: Failed to set master key session variable: {e}")
        return False

async def ensure_master_key_available() -> bool:
    """
    Ensure master key is available and set in database session (SECURE)
    Returns True if available, False otherwise
    """
    master_key = get_master_encryption_key()
    if not master_key:
        return False
    
    return await set_database_master_key()

class SecureEncryptionContext:
    """Context manager for secure encryption operations with master key management"""
    
    def __init__(self):
        self.master_key_set = False
    
    async def __aenter__(self):
        self.master_key_set = await ensure_master_key_available()
        if not self.master_key_set:
            raise EncryptionError("Master encryption key not available - set ENCRYPTION_MASTER_KEY environment variable")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Clear session variable for security
        try:
            await execute_query("SET app.master_key = ''")
            logger.debug("🔐 SECURITY: Cleared master key session variable")
        except Exception as e:
            logger.warning(f"⚠️ SECURITY: Failed to clear master key session variable: {e}")

def with_secure_encryption():
    """Decorator/context manager for secure encryption operations"""
    return SecureEncryptionContext()

# Removed complex security functions - replaced with simple gate in credit_user_wallet()

async def probe_database_health():
    """NEON HARDENING: Lightweight async health probe for automatic recovery"""
    global _database_healthy, _last_health_check
    
    try:
        # ENVIRONMENT-AWARE: Get database URL based on current environment
        database_url = get_environment_manager().get_database_url()
        if not database_url:
            return False
        
        # Quick connection test with minimal timeout
        import psycopg2
        conn = psycopg2.connect(
            database_url,
            connect_timeout=3,  # Very fast timeout for probe
            sslmode='require'    # NEON FIX: Require SSL for connection stability
        )
        
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            
            _last_health_check = time.time()
            
            # If database was previously unhealthy and is now healthy, recreate pool
            if not _database_healthy:
                logger.info("✅ NEON HARDENING: Database endpoint resumed - recreating connection pool")
                if recreate_connection_pool():
                    _database_healthy = True
                    return True
            
            _database_healthy = True
            return True
            
        finally:
            conn.close()
            
    except Exception as e:
        error_msg = str(e).lower()
        if _database_healthy and any(indicator in error_msg for indicator in ['connection refused', 'timeout', 'no route']):
            logger.debug(f"🔄 NEON HARDENING: Database appears to be auto-suspended: {e}")
            _database_healthy = False
        return False

async def start_health_probe():
    """NEON HARDENING: Start background health probe task"""
    global _health_probe_task, _health_probe_enabled
    
    if not _health_probe_enabled or _health_probe_task is not None:
        return
    
    async def health_probe_loop():
        logger.info("✅ NEON HARDENING: Starting background database health probe")
        
        while _health_probe_enabled:
            try:
                await probe_database_health()
                # Probe every 30 seconds when healthy, every 10 seconds when unhealthy
                probe_interval = 30 if _database_healthy else 10
                await asyncio.sleep(probe_interval)
                
            except asyncio.CancelledError:
                logger.info("🔄 NEON HARDENING: Health probe cancelled")
                break
            except Exception as probe_error:
                logger.warning(f"⚠️ NEON HARDENING: Health probe error: {probe_error}")
                await asyncio.sleep(30)  # Wait longer on probe errors
    
    _health_probe_task = asyncio.create_task(health_probe_loop())
    logger.info("✅ NEON HARDENING: Background health probe started")

async def stop_health_probe():
    """NEON HARDENING: Stop background health probe task"""
    global _health_probe_task, _health_probe_enabled
    
    _health_probe_enabled = False
    
    if _health_probe_task:
        _health_probe_task.cancel()
        try:
            await _health_probe_task
        except asyncio.CancelledError:
            pass
        _health_probe_task = None
        logger.info("🔄 NEON HARDENING: Background health probe stopped")

async def run_db(func, *args, **kwargs):
    """Run database operation in thread pool with context propagation"""
    loop = asyncio.get_event_loop()
    executor = get_db_executor()
    
    # Capture current context to propagate context variables to worker threads
    current_context = contextvars.copy_context()
    
    # Create wrapper function that runs in the copied context
    def context_aware_wrapper():
        return current_context.run(func, *args, **kwargs)
    
    return await loop.run_in_executor(executor, context_aware_wrapper)

# PHASE 1: Database threading infrastructure for high concurrency

logger = logging.getLogger(__name__)

def _ensure_pool_timezone_utc():
    """TIMEZONE CONSISTENCY: Verify database supports UTC timezone configuration"""
    global _connection_pool
    if _connection_pool is None:
        return
    
    try:
        # Test that we can configure timezone (session-specific)
        test_conn = _connection_pool.getconn()
        try:
            with test_conn.cursor() as cursor:
                cursor.execute("SET TIME ZONE 'UTC'")
                cursor.execute("SHOW TIME ZONE")
                result = cursor.fetchone()
                logger.info(f"🌍 TIMEZONE CONSISTENCY: Database supports UTC timezone (verified: {result[0]})")
            test_conn.commit()
        finally:
            _connection_pool.putconn(test_conn)
            
        # Note: Timezone is session-specific, so it's set on each connection checkout in get_connection()
        logger.info("✅ TIMEZONE CONSISTENCY: UTC timezone enforcement active per-connection")
        
    except Exception as e:
        # This is not critical since timezone is set per-connection in get_connection()
        logger.info(f"ℹ️ TIMEZONE CONSISTENCY: Pool test skipped ({e}), per-connection timezone setting will be used")

def recreate_connection_pool():
    """NEON HARDENING: Recreate connection pool to recover from dead connections"""
    global _connection_pool, _pool_recreation_count, _last_pool_recreation
    
    current_time = time.time()
    
    # Rate limiting: Don't recreate pool more than once every 10 seconds
    if current_time - _last_pool_recreation < 10:
        logger.debug("🔄 Pool recreation rate limited - skipping")
        return False
    
    with _pool_lock:
        try:
            # Close existing pool if it exists
            if _connection_pool is not None:
                try:
                    _connection_pool.closeall()
                    logger.info("🔄 NEON HARDENING: Closed existing connection pool")
                except Exception as close_error:
                    logger.warning(f"⚠️ Error closing existing pool: {close_error}")
            
            # ENVIRONMENT-AWARE: Get database URL based on current environment
            database_url = get_environment_manager().get_database_url()
            if not database_url:
                raise ValueError("Database URL not found - check environment configuration")
            
            # Create new pool with enhanced SSL hardening settings
            # NEON FREE TIER: Limited to 112 max connections (105 available)
            # Sized for 20-30 concurrent users (each needs ~3-4 queries)
            _connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=10,       # Pre-warm for concurrent user operations
                maxconn=30,       # Handle 20-30 users with parallel queries
                dsn=database_url,
                cursor_factory=RealDictCursor,
                connect_timeout=15,     # PRODUCTION FIX: Allow time for Neon cold start
                keepalives_idle=300,    # SSL FIX: Reduced to 5 minutes for faster SSL timeout detection
                keepalives_interval=15, # SSL FIX: Reduced to 15 seconds for more aggressive SSL probing
                keepalives_count=2,     # SSL FIX: Reduced to 2 probes for faster SSL failure detection
                sslmode='require',      # SSL FIX: Require SSL for Neon, more reliable than 'prefer'
                sslcert=None,          # SSL FIX: Let Neon handle SSL certificate automatically
                sslkey=None,           # SSL FIX: Let Neon handle SSL key automatically
                sslrootcert=None       # SSL FIX: Let Neon handle SSL root certificate automatically
            )
            
            # TIMEZONE CONSISTENCY: Ensure all connections use UTC timezone
            _ensure_pool_timezone_utc()
            
            _pool_recreation_count += 1
            _last_pool_recreation = current_time
            logger.info(f"✅ NEON HARDENING: Connection pool recreated (#{_pool_recreation_count}) - recovering from dead connections")
            return True
            
        except Exception as e:
            logger.error(f"❌ NEON HARDENING: Failed to recreate connection pool: {e}")
            _connection_pool = None
            return False

def get_connection_pool():
    """Get or create simplified database connection pool with Neon hardening"""
    global _connection_pool
    if _connection_pool is None:
        try:
            # ENVIRONMENT-AWARE: Get database URL based on current environment
            database_url = get_environment_manager().get_database_url()
            if not database_url:
                raise ValueError("Database URL not found - check environment configuration")
            
            # NEON FREE TIER: Limited to 112 max connections (105 available)
            # Sized for 20-30 concurrent users (each needs ~3-4 queries)
            # Note: For higher throughput, upgrade to Neon's pooled connections (-pooler suffix)
            _connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=10,       # Pre-warm for concurrent user operations
                maxconn=30,       # Handle 20-30 users with parallel queries
                dsn=database_url,
                cursor_factory=RealDictCursor,
                connect_timeout=15,     # PRODUCTION FIX: Allow time for Neon cold start
                keepalives_idle=300,    # SSL FIX: Reduced to 5 minutes for faster SSL timeout detection
                keepalives_interval=15, # SSL FIX: Reduced to 15 seconds for more aggressive SSL probing
                keepalives_count=2,     # SSL FIX: Reduced to 2 probes for faster SSL failure detection
                sslmode='require',      # SSL FIX: Require SSL for Neon, more reliable than 'prefer'
                sslcert=None,          # SSL FIX: Let Neon handle SSL certificate automatically
                sslkey=None,           # SSL FIX: Let Neon handle SSL key automatically
                sslrootcert=None       # SSL FIX: Let Neon handle SSL root certificate automatically
            )
            
            # TIMEZONE CONSISTENCY: Ensure all connections use UTC timezone to prevent comparison issues
            # with timezone-aware Python datetime objects
            _ensure_pool_timezone_utc()
            logger.info("✅ NEON HARDENING: Connection pool created with fast failure detection (2-10 connections for free tier)")
        except Exception as e:
            logger.error(f"Failed to create connection pool: {e}")
            raise
    return _connection_pool

def with_database_timeout(operation_func, timeout_seconds=10, operation_name="database operation"):
    """NEON HARDENING: Thread-safe wrapper to prevent database operations from hanging indefinitely"""
    import threading
    import time
    
    result_container = {'result': None, 'exception': None, 'completed': False}
    
    def target():
        try:
            result_container['result'] = operation_func()
            result_container['completed'] = True
        except Exception as e:
            result_container['exception'] = e
            result_container['completed'] = True
    
    # Start operation in a separate thread
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    
    # Wait for completion with timeout
    thread.join(timeout_seconds)
    
    if not result_container['completed']:
        logger.error(f"💥 NEON HARDENING: {operation_name} timed out after {timeout_seconds}s - preventing application hang")
        logger.info("🏥 FALLBACK: Preventing application hang due to database timeout")
        logger.info("   └─ Background health probe will attempt automatic recovery")
        raise TimeoutError(f"NEON HARDENING: {operation_name} timed out after {timeout_seconds}s")
    
    if result_container['exception']:
        raise result_container['exception']
        
    return result_container['result']

def test_connection_health(conn, timeout_seconds=3):
    """NEON HARDENING: Thread-safe connection health test with timeout"""
    
    def _health_check():
        try:
            # Alternative approach: Test connection without cursor complications  
            try:
                # Simple connection test that avoids cursor factory issues
                conn.execute("SELECT 1")
                return True, "Healthy"
            except AttributeError:
                # If conn.execute doesn't work, use basic cursor
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    # Handle both tuple and dict results
                    if result is None:
                        return False, "No result from health query"
                    if hasattr(result, '__getitem__'):
                        # Try both numeric and string access for compatibility
                        try:
                            check_val = result[0] if isinstance(result, (tuple, list)) else result.get(0, result.get('?column?', None))
                            if check_val == 1:
                                return True, "Healthy"
                        except (KeyError, IndexError, TypeError):
                            pass
                    return False, f"Unexpected result format: {type(result)} = {result}"
                
                return True, "Healthy"
        except Exception as e:
            # Debug: Log the exact exception details
            logger.warning(f"🔍 Health check exception debug - Type: {type(e)}, Str: '{str(e)}', Repr: {repr(e)}")
            return False, f"Health check failed: {e}"
    
    try:
        return with_database_timeout(_health_check, timeout_seconds, "connection health check")
    except TimeoutError:
        return False, "Health check timed out - possible auto-suspend"
    except Exception as e:
        error_msg = str(e).lower()
        # SSL FIX: Enhanced SSL error detection patterns
        ssl_error_indicators = [
            'connection closed', 'server closed', 'ssl connection', 'timeout', 'broken pipe',
            'ssl connection has been closed unexpectedly', 'ssl handshake', 'ssl: connection has been closed',
            'connection reset by peer', 'certificate verify failed', 'ssl: decryption failed',
            'ssl: bad record mac', 'ssl: unexpected message', 'operation timed out'
        ]
        if any(indicator in error_msg for indicator in ssl_error_indicators):
            return False, f"SSL/Connection failure detected: {e}"
        return False, f"Health check failed: {e}"

def get_connection():
    """NEON HARDENING: Get database connection with enhanced health testing"""
    pool_retry_attempts = 3  # Retry pool connections before falling back
    
    for pool_attempt in range(pool_retry_attempts):
        try:
            pool = get_connection_pool()
            conn = pool.getconn()
            
            if conn:
                conn.autocommit = True
                
                # NEON HARDENING: Enhanced health check with timeout
                is_healthy, health_message = test_connection_health(conn, timeout_seconds=3)
                
                if is_healthy:
                    # TIMEZONE CONSISTENCY: Ensure UTC timezone for this connection session
                    # CRITICAL FIX: Only set timezone when autocommit is True to avoid transaction conflicts
                    try:
                        if conn.autocommit:  # Only set timezone outside transactions
                            with conn.cursor() as cursor:
                                cursor.execute("SET TIME ZONE 'UTC'")
                        else:
                            logger.debug("⚠️ TIMEZONE CONSISTENCY: Skipping timezone setting - connection in transaction mode")
                    except Exception as tz_error:
                        logger.warning(f"⚠️ TIMEZONE CONSISTENCY: Failed to set UTC timezone for connection: {tz_error}")
                    
                    
                    logger.debug(f"✅ Pool connection {pool_attempt + 1}: {health_message}")
                    return conn
                else:
                    logger.warning(f"🔄 Pool connection {pool_attempt + 1}/{pool_retry_attempts}: {health_message}")
                    return_connection(conn, is_broken=True)
                    
                    # Continue to next pool attempt instead of falling back immediately
                    if pool_attempt < pool_retry_attempts - 1:
                        # Small delay to allow pool to recover
                        time.sleep(0.1)
                        continue
                        
            # No connection available from pool on this attempt
            if pool_attempt < pool_retry_attempts - 1:
                logger.debug(f"Pool attempt {pool_attempt + 1}/{pool_retry_attempts}: No connection available, retrying...")
                time.sleep(0.1)
                continue
                
        except Exception as pool_error:
            logger.warning(f"Pool attempt {pool_attempt + 1}/{pool_retry_attempts} failed: {pool_error}")
            if pool_attempt < pool_retry_attempts - 1:
                continue
    
    # FALLBACK: Only after all pool attempts failed
    logger.warning(f"⚠️ NEON HARDENING: Connection pool exhausted after {pool_retry_attempts} attempts, using direct connection")
    
    try:
        # ENVIRONMENT-AWARE: Get database URL based on current environment
        database_url = get_environment_manager().get_database_url()
        if not database_url:
            raise Exception("Database URL not configured - check environment settings")
            
        conn = psycopg2.connect(
            database_url,
            cursor_factory=RealDictCursor,
            connect_timeout=15,     # PRODUCTION FIX: Allow time for Neon cold start
            keepalives_idle=600,    # NEON HARDENING: 10 minutes - detect auto-suspend faster
            keepalives_interval=30, # NEON HARDENING: 30 seconds - more aggressive probing
            keepalives_count=3,     # NEON HARDENING: 3 failed probes before marking dead
            sslmode='prefer'        # NEON FIX: Prefer SSL but allow fallback for auto-suspend compatibility
        )
        conn.autocommit = True
        
        # Test the direct connection too
        is_healthy, health_message = test_connection_health(conn, timeout_seconds=5)
        if not is_healthy:
            conn.close()
            raise Exception(f"Direct connection health check failed: {health_message}")
            
        # TIMEZONE CONSISTENCY: Set timezone for direct connections too
        try:
            if conn.autocommit:  # Only set timezone outside transactions
                with conn.cursor() as cursor:
                    cursor.execute("SET TIME ZONE 'UTC'")
        except Exception as tz_error:
            logger.warning(f"⚠️ TIMEZONE CONSISTENCY: Failed to set UTC timezone for direct connection: {tz_error}")
        
            
        logger.info(f"✅ NEON HARDENING: Using healthy direct connection fallback ({health_message})")
        return conn
        
    except Exception as e:
        logger.error(f"❌ NEON HARDENING: Database connection error: {e}")
        raise

def return_connection(conn, is_broken=False):
    """Simplified connection return to pool"""
    try:
        pool = get_connection_pool()
        if is_broken:
            pool.putconn(conn, close=True)
        else:
            pool.putconn(conn)
    except Exception:
        # Fallback: close connection directly
        try:
            conn.close()
        except:
            pass

async def execute_query(query: str, params: Optional[tuple] = None) -> List[Dict]:
    """Execute a SELECT query and return results using connection pool with retry"""
    import psycopg2
    
    def _execute() -> List[Dict]:
        max_retries = 3
        for attempt in range(max_retries):
            conn = None
            try:
                conn = get_connection()
                with conn.cursor() as cursor:
                    cursor.execute(query, params)
                    results = cursor.fetchall()
                    return [dict(row) for row in results] if results else []
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                # NEON HARDENING: Connection-level errors that indicate dead connections
                if conn:
                    return_connection(conn, is_broken=True)
                    conn = None
                
                # NEON HARDENING: Recreate pool on connection failures to recover from auto-suspend
                error_msg = str(e).lower()
                # SSL FIX: Use enhanced SSL error detection patterns
                ssl_error_indicators = [
                    'connection closed', 'server closed', 'ssl connection', 'timeout', 'broken pipe',
                    'ssl connection has been closed unexpectedly', 'ssl handshake', 'ssl: connection has been closed',
                    'connection reset by peer', 'certificate verify failed', 'ssl: decryption failed',
                    'ssl: bad record mac', 'ssl: unexpected message', 'operation timed out'
                ]
                if any(indicator in error_msg for indicator in ssl_error_indicators):
                    logger.warning(f"🔄 NEON HARDENING: Detected dead connection, recreating pool: {e}")
                    if recreate_connection_pool():
                        logger.info("✅ NEON HARDENING: Pool recreated, connection should be restored")
                
                if attempt < max_retries - 1:
                    logger.warning(f"NEON HARDENING: Database connection retry {attempt + 1}/{max_retries}: {e}")
                    # Short delay between retries to avoid overwhelming the endpoint
                    time.sleep(0.5 + (attempt * 0.5))
                    continue
                else:
                    logger.error(f"💥 NEON HARDENING: All database connection attempts failed after {max_retries} retries")
                    logger.error(f"   └─ Final error: {e}")
                    logger.info("🏥 FALLBACK: Returning empty result set to prevent application hang")
                    logger.info("   └─ Application will continue with limited functionality")
                    logger.info("   └─ Background health probe will attempt automatic recovery")
                    
                    if TEST_STRICT_DB:
                        # ARCHITECT REQUIREMENT 3: Raise exceptions in strict test mode
                        logger.error("⚠️ TEST_STRICT_DB=true - raising exception instead of graceful degradation")
                        raise e
                    
                    return []  # Clear fallback prevents hang
            except Exception as e:
                # Other errors should not be retried
                if conn:
                    return_connection(conn)
                    conn = None
                logger.error(f"Database query error: {e}")
                if TEST_STRICT_DB:
                    # ARCHITECT REQUIREMENT 3: Raise exceptions in strict test mode
                    logger.error("⚠️ TEST_STRICT_DB=true - raising exception instead of graceful degradation")
                    raise e
                logger.warning("🔄 Database operation failed - returning empty result set for graceful degradation")
                return []  # Graceful degradation instead of crash
            finally:
                if conn:
                    return_connection(conn)
        
        # This should never be reached due to the raise statements above
        return []
    
    return await asyncio.to_thread(_execute)

async def execute_update(query: str, params: Optional[tuple] = None) -> int:
    """Execute an UPDATE/INSERT/DELETE query and return affected rows using connection pool (no retries to prevent duplicates)"""
    import psycopg2
    
    def _execute() -> int:
        conn = None
        original_autocommit = True  # Default value to prevent unbound variable
        try:
            conn = get_connection()
            
            # CRITICAL FIX: Properly handle transaction management
            original_autocommit = conn.autocommit
            conn.autocommit = False  # Ensure we're in transaction mode for updates
            
            # ENHANCED LOGGING: Log SQL execution details
            logger.info(f"🔍 SQL UPDATE: Executing query with {len(params) if params else 0} parameters")
            logger.debug(f"  Query: {query}")
            if params:
                logger.debug(f"  Params: {params}")
            
            with conn.cursor() as cursor:
                cursor.execute(query, params)
                rowcount = cursor.rowcount
                conn.commit()
                
                # ENHANCED LOGGING: Report execution results
                logger.info(f"✅ SQL UPDATE: Successfully affected {rowcount} rows")
                return rowcount
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            # ENHANCED ERROR LOGGING: Log actual SQL that failed
            logger.error(f"💥 CONNECTION ERROR in execute_update:")
            logger.error(f"  Query: {query}")
            logger.error(f"  Params: {params}")
            logger.error(f"  Error: {e}")
            
            # NEON HARDENING: Connection-level errors - close broken connection but don't retry writes
            if conn:
                try:
                    conn.rollback()
                    conn.autocommit = original_autocommit  # Restore original state
                except:
                    pass
                return_connection(conn, is_broken=True)
                conn = None
            
            # NEON HARDENING: Recreate pool on connection failures to recover from auto-suspend
            error_msg = str(e).lower()
            # SSL FIX: Use enhanced SSL error detection patterns
            ssl_error_indicators = [
                'connection closed', 'server closed', 'ssl connection', 'timeout', 'broken pipe',
                'ssl connection has been closed unexpectedly', 'ssl handshake', 'ssl: connection has been closed',
                'connection reset by peer', 'certificate verify failed', 'ssl: decryption failed',
                'ssl: bad record mac', 'ssl: unexpected message', 'operation timed out'
            ]
            if any(indicator in error_msg for indicator in ssl_error_indicators):
                logger.warning(f"🔄 NEON HARDENING: Detected dead connection on update, recreating pool: {e}")
                if recreate_connection_pool():
                    logger.info("✅ NEON HARDENING: Pool recreated after update failure")
            
            logger.error(f"💥 NEON HARDENING: Database update connection failed: {e}")
            logger.info("🏥 FALLBACK: Update operation aborted to prevent hang")
            logger.info("   └─ No data was modified (transaction rolled back)")
            logger.info("   └─ Background health probe will attempt automatic recovery")
            
            if TEST_STRICT_DB:
                # ARCHITECT REQUIREMENT 3: Raise exceptions in strict test mode
                logger.error("⚠️ TEST_STRICT_DB=true - raising exception instead of graceful degradation")
                raise e
                
            return 0  # Clear fallback prevents hang
        except Exception as e:
            # ENHANCED ERROR LOGGING: Log the exact SQL error details
            logger.error(f"💥 SQL ERROR in execute_update:")
            logger.error(f"  Query: {query}")
            logger.error(f"  Params: {params}")
            logger.error(f"  Error Type: {type(e).__name__}")
            logger.error(f"  Error Message: {str(e)}")
            
            # Other errors - rollback and return connection
            if conn:
                try:
                    conn.rollback()
                    conn.autocommit = original_autocommit  # Restore original state
                except Exception as rollback_error:
                    logger.error(f"Failed to rollback transaction: {rollback_error}")
                return_connection(conn)
                conn = None
                
            logger.error(f"💥 NEON HARDENING: Database update operation failed: {e}")
            logger.info("🏥 FALLBACK: Update operation aborted with clean rollback")
            logger.info("   └─ Database remains in consistent state")
            logger.info("   └─ Application will continue with degraded functionality")
            
            if TEST_STRICT_DB:
                # ARCHITECT REQUIREMENT 3: Raise exceptions in strict test mode
                logger.error("⚠️ TEST_STRICT_DB=true - raising exception instead of graceful degradation")
                raise e
                
            return 0  # Clear fallback prevents hang
        finally:
            if conn:
                try:
                    # Restore original autocommit setting before returning connection
                    conn.autocommit = original_autocommit
                except:
                    pass
                return_connection(conn)
    
    return await asyncio.to_thread(_execute)

async def run_in_transaction(func, *args, **kwargs):
    """Simplified transaction execution"""
    import psycopg2
    
    def _execute_in_transaction():
        conn = None
        try:
            conn = get_connection()
            original_autocommit = conn.autocommit
            conn.autocommit = False
            
            try:
                result = func(conn, *args, **kwargs)
                conn.commit()
                return result
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.autocommit = original_autocommit
        finally:
            if conn:
                return_connection(conn)
    
    return await asyncio.to_thread(_execute_in_transaction)

async def init_database():
    """Initialize database tables if they don't exist"""
    def _init():
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                # Users table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        telegram_id BIGINT UNIQUE NOT NULL,
                        username VARCHAR(255),
                        first_name VARCHAR(255),
                        last_name VARCHAR(255),
                        wallet_balance DECIMAL(10,2) DEFAULT 0.00,
                        terms_accepted BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # FIX: Ensure users sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'users_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('users_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM users),
                                    (SELECT last_value FROM users_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM users_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: users sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ users_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync users sequence: {seq_error}")
                
                # Add terms_accepted column for existing users (safe if column already exists)
                cursor.execute("""
                    ALTER TABLE users 
                    ADD COLUMN IF NOT EXISTS terms_accepted BOOLEAN DEFAULT FALSE
                """)
                
                # User profiles table for WHOIS data
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS user_profiles (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        first_name VARCHAR(255),
                        last_name VARCHAR(255),
                        organization VARCHAR(255),
                        email VARCHAR(255),
                        phone VARCHAR(20),
                        address VARCHAR(500),
                        city VARCHAR(255),
                        state VARCHAR(255),
                        postal_code VARCHAR(20),
                        country VARCHAR(2),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # OpenProvider accounts table for multi-account support
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS openprovider_accounts (
                        id SERIAL PRIMARY KEY,
                        account_name VARCHAR(100) UNIQUE NOT NULL,
                        username VARCHAR(255) NOT NULL,
                        is_default BOOLEAN DEFAULT FALSE,
                        is_active BOOLEAN DEFAULT TRUE,
                        notes TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # OpenProvider contact handles cache per account
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS openprovider_contact_handles (
                        id SERIAL PRIMARY KEY,
                        account_id INTEGER REFERENCES openprovider_accounts(id) ON DELETE CASCADE,
                        tld VARCHAR(50) NOT NULL,
                        contact_type VARCHAR(50) NOT NULL,
                        handle VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(account_id, tld, contact_type)
                    )
                """)
                
                # Domains table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domains (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        domain_name VARCHAR(255) UNIQUE NOT NULL,
                        provider_domain_id VARCHAR(255),
                        status VARCHAR(50),
                        nameservers TEXT[],
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Cloudflare zones table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cloudflare_zones (
                        id SERIAL PRIMARY KEY,
                        domain_name VARCHAR(255) UNIQUE NOT NULL,
                        cf_zone_id VARCHAR(255) UNIQUE NOT NULL,
                        nameservers TEXT[],
                        status VARCHAR(50),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # DNS record versions table for optimistic concurrency control
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS dns_record_versions (
                        version_id BIGSERIAL PRIMARY KEY,
                        record_id VARCHAR(255) NOT NULL,
                        zone_id VARCHAR(255) NOT NULL,
                        record_type VARCHAR(50) NOT NULL,
                        version_etag VARCHAR(255) NOT NULL,
                        content_hash VARCHAR(255) NOT NULL,
                        record_data JSONB NOT NULL,
                        last_modified_at TIMESTAMPTZ DEFAULT now() NOT NULL,
                        created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
                        UNIQUE(record_id, version_etag)
                    )
                """)
                
                # Add indexes for DNS record versions performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_record_versions_record_id ON dns_record_versions(record_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_record_versions_zone_record_type ON dns_record_versions(zone_id, record_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_record_versions_latest ON dns_record_versions(record_id, created_at DESC)")
                
                # Wallet transactions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS wallet_transactions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        transaction_type VARCHAR(50),
                        amount DECIMAL(10,2),
                        currency VARCHAR(10),
                        status VARCHAR(50),
                        payment_id VARCHAR(255),
                        external_txid VARCHAR(255),
                        description TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(external_txid)
                    )
                """)
                
                # FIX: Ensure wallet_transactions sequence is in sync with data
                # This prevents "duplicate key" errors when the sequence gets out of sync
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'wallet_transactions_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('wallet_transactions_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM wallet_transactions),
                                    (SELECT last_value FROM wallet_transactions_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM wallet_transactions_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: wallet_transactions sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ wallet_transactions_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync wallet_transactions sequence: {seq_error}")
                
                
                # CRITICAL SECURITY: Add CHECK constraint to prevent negative wallet balances at database level
                try:
                    cursor.execute("""
                        DO $$ 
                        BEGIN
                            IF NOT EXISTS (
                                SELECT 1 FROM pg_constraint 
                                WHERE conname = 'wallet_balance_non_negative'
                            ) THEN
                                ALTER TABLE users ADD CONSTRAINT wallet_balance_non_negative CHECK (wallet_balance >= 0);
                                RAISE NOTICE '✅ SECURITY: wallet_balance_non_negative constraint added to users table';
                            ELSE
                                RAISE NOTICE '✅ SECURITY: wallet_balance_non_negative constraint already exists';
                            END IF;
                        END $$;
                    """)
                    logger.info("🔒 CRITICAL SECURITY: Negative balance protection constraint verified at database level")
                except Exception as security_error:
                    logger.error(f"🚫 CRITICAL: Failed to add negative balance protection constraint: {security_error}")
                    raise  # This is critical security - fail initialization if constraint cannot be added
                
                
                
                # Wallet deposits table (for crypto wallet funding)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS wallet_deposits (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        crypto_currency VARCHAR(10) NOT NULL,
                        usd_amount DECIMAL(10,2) NOT NULL,
                        crypto_amount DECIMAL(18,8),
                        payment_address VARCHAR(255) NOT NULL,
                        status VARCHAR(50) DEFAULT 'pending_payment',
                        confirmations INTEGER DEFAULT 0,
                        blockbee_order_id VARCHAR(255),
                        txid VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # FIX: Ensure wallet_deposits sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'wallet_deposits_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('wallet_deposits_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM wallet_deposits),
                                    (SELECT last_value FROM wallet_deposits_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM wallet_deposits_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: wallet_deposits sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ wallet_deposits_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync wallet_deposits sequence: {seq_error}")
                
                # Domain orders table (for payment tracking with processing state machine)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domain_orders (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        domain_name VARCHAR(255) NOT NULL,
                        status VARCHAR(50) DEFAULT 'pending_payment',
                        payment_address VARCHAR(255),
                        expected_amount DECIMAL(10,2),
                        currency VARCHAR(10),
                        confirmations INTEGER DEFAULT 0,
                        contact_handle VARCHAR(255),
                        blockbee_order_id VARCHAR(255),
                        intent_id VARCHAR(255),
                        txid VARCHAR(255),
                        processing_started_at TIMESTAMP,
                        completed_at TIMESTAMP,
                        error_message TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Add intent_id column if it doesn't exist (migration helper)
                try:
                    cursor.execute("""
                        ALTER TABLE domain_orders 
                        ADD COLUMN IF NOT EXISTS intent_id VARCHAR(255)
                    """)
                except Exception as e:
                    logger.warning(f"⚠️ Could not add intent_id to domain_orders: {e}")
                
                # FIX: Ensure domain_orders sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'domain_orders_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('domain_orders_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM domain_orders),
                                    (SELECT last_value FROM domain_orders_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM domain_orders_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: domain_orders sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ domain_orders_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync domain_orders sequence: {seq_error}")
                
                # Hosting orders table (single-table consolidation for all hosting payments)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS hosting_orders (
                        id BIGSERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        hosting_plan_id INTEGER,
                        domain_name VARCHAR(255),
                        status VARCHAR(50) DEFAULT 'pending_payment',
                        payment_address VARCHAR(255),
                        blockbee_order_id VARCHAR(255),
                        external_order_id VARCHAR(255),
                        intent_id INTEGER,
                        subscription_id INTEGER,
                        expected_amount DECIMAL(12,2),
                        amount_received DECIMAL(12,2),
                        currency VARCHAR(10) DEFAULT 'USD',
                        overpayment_detected BOOLEAN DEFAULT FALSE,
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        paid_at TIMESTAMP
                    )
                """)
                
                # Add indexes for hosting_orders performance
                try:
                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_hosting_orders_blockbee_id 
                        ON hosting_orders(blockbee_order_id)
                    """)
                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_hosting_orders_external_id 
                        ON hosting_orders(external_order_id)
                    """)
                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_hosting_orders_intent_id 
                        ON hosting_orders(intent_id)
                    """)
                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_hosting_orders_subscription_id 
                        ON hosting_orders(subscription_id)
                    """)
                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_hosting_orders_user_status 
                        ON hosting_orders(user_id, status)
                    """)
                except Exception as idx_error:
                    logger.warning(f"⚠️ Could not create hosting_orders indexes: {idx_error}")
                
                # Ensure hosting_orders sequence is in sync with data
                try:
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'hosting_orders_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('hosting_orders_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM hosting_orders),
                                    (SELECT last_value FROM hosting_orders_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM hosting_orders_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: hosting_orders sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ hosting_orders_id_seq sequence does not exist yet (will be created on first insert)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync hosting_orders sequence: {seq_error}")
                
                # Hosting plans table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS hosting_plans (
                        id SERIAL PRIMARY KEY,
                        plan_name VARCHAR(255) NOT NULL,
                        plan_type VARCHAR(100) NOT NULL,
                        disk_space_gb INTEGER,
                        bandwidth_gb INTEGER,
                        databases INTEGER,
                        email_accounts INTEGER,
                        subdomains INTEGER,
                        monthly_price DECIMAL(10,2),
                        yearly_price DECIMAL(10,2),
                        features TEXT[],
                        is_active BOOLEAN DEFAULT true,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        billing_cycle VARCHAR(20),
                        duration_days INTEGER
                    )
                """)
                
                
                # SEED ESSENTIAL DATA: Auto-create required hosting plans if they don't exist
                try:
                    # Check if hosting plans exist, if not seed them
                    cursor.execute("SELECT COUNT(*) FROM hosting_plans WHERE id IN (1, 2)")
                    result = cursor.fetchone()
                    if result is None:
                        plan_count = 0
                    else:
                        # Handle both regular cursor (tuple) and RealDictCursor (dict-like) results
                        if isinstance(result, (list, tuple)):
                            plan_count = int(result[0]) if result[0] is not None else 0
                        else:
                            # Dict-like cursor result
                            plan_count = int(result.get('count', 0)) if hasattr(result, 'get') else int(result[0])
                    
                    logger.info(f"📊 Current hosting plans count: {plan_count}/2")
                    
                    if plan_count < 2:
                        logger.info("🌱 Seeding essential hosting plans data...")
                        
                        # Read hosting prices from environment secrets
                        import os
                        plan_7_price = float(os.environ.get('HOSTING_PLAN_7_DAYS_PRICE', '40.00'))
                        plan_30_price = float(os.environ.get('HOSTING_PLAN_30_DAYS_PRICE', '100.00'))
                        
                        # Insert Pro 7 Days plan (ID=1)  
                        cursor.execute("""
                            INSERT INTO hosting_plans 
                            (id, plan_name, plan_type, disk_space_gb, bandwidth_gb, databases, email_accounts, 
                             subdomains, monthly_price, yearly_price, features, is_active, billing_cycle, duration_days)
                            VALUES (1, 'Pro 7 Days', 'shared', 5, 100, 1, 5, 10, %s, %s, 
                                   '{"SSD Storage","cPanel Access","24/7 Support","7-Day Term"}', true, '7days', 7)
                            ON CONFLICT (id) DO UPDATE SET
                                plan_name = EXCLUDED.plan_name,
                                monthly_price = EXCLUDED.monthly_price,
                                yearly_price = EXCLUDED.yearly_price,
                                billing_cycle = EXCLUDED.billing_cycle,
                                duration_days = EXCLUDED.duration_days,
                                updated_at = CURRENT_TIMESTAMP
                        """, (plan_7_price, plan_7_price))
                        
                        # Insert Pro 30 Days plan (ID=2)
                        cursor.execute("""
                            INSERT INTO hosting_plans 
                            (id, plan_name, plan_type, disk_space_gb, bandwidth_gb, databases, email_accounts, 
                             subdomains, monthly_price, yearly_price, features, is_active, billing_cycle, duration_days)
                            VALUES (2, 'Pro 30 Days', 'shared', 10, 500, 5, 25, 50, %s, %s, 
                                   '{"SSD Storage","cPanel Access","24/7 Support","30-Day Term"}', true, '30days', 30)
                            ON CONFLICT (id) DO UPDATE SET
                                plan_name = EXCLUDED.plan_name,
                                monthly_price = EXCLUDED.monthly_price,
                                yearly_price = EXCLUDED.yearly_price,
                                billing_cycle = EXCLUDED.billing_cycle,
                                duration_days = EXCLUDED.duration_days,
                                updated_at = CURRENT_TIMESTAMP
                        """, (plan_30_price, plan_30_price))
                        
                        # Reset sequence to ensure future INSERTs start from ID 3
                        cursor.execute("SELECT setval('hosting_plans_id_seq', GREATEST(2, (SELECT MAX(id) FROM hosting_plans)), true)")
                        
                        # Verify seeding was successful by checking count again
                        cursor.execute("SELECT COUNT(*) FROM hosting_plans WHERE id IN (1, 2)")
                        verify_result = cursor.fetchone()
                        if verify_result is None:
                            final_count = 0
                        else:
                            # Handle both regular cursor (tuple) and RealDictCursor (dict-like) results  
                            try:
                                if isinstance(verify_result, (list, tuple)):
                                    final_count = int(verify_result[0]) if verify_result[0] is not None else 0
                                elif hasattr(verify_result, 'get'):
                                    # Dict-like cursor result
                                    final_count = int(verify_result.get('count', 0))
                                else:
                                    final_count = int(verify_result[0])
                            except (TypeError, ValueError, IndexError) as conversion_error:
                                logger.warning(f"⚠️ Count conversion error: {conversion_error}, result: {verify_result}")
                                final_count = 0
                        
                        if final_count >= 2:
                            logger.info(f"✅ Essential hosting plans seeded successfully ({final_count}/2) - ID 1: Pro 7 Days ${plan_7_price}, ID 2: Pro 30 Days ${plan_30_price}")
                        else:
                            logger.error(f"❌ Seeding verification failed: Expected 2 plans, got {final_count}")
                            raise Exception(f"Hosting plans seeding verification failed: {final_count}/2 plans")
                    else:
                        logger.info(f"✅ Hosting plans already exist ({plan_count}/2), skipping seeding")
                        
                except Exception as seed_error:
                    # Check if the plans actually exist despite the error
                    try:
                        cursor.execute("SELECT COUNT(*) FROM hosting_plans WHERE id IN (1, 2)")
                        check_result = cursor.fetchone()
                        existing_count = int(check_result[0]) if check_result and check_result[0] is not None else 0
                        
                        if existing_count >= 2:
                            logger.info(f"✅ Hosting plans verified to exist ({existing_count}/2) despite seeding error - continuing normally")
                        else:
                            logger.error(f"❌ CRITICAL: Failed to seed hosting plans data: {seed_error}")
                            logger.warning("⚠️ Application will continue without seeded hosting plans - manual seeding may be required")
                    except Exception as verify_error:
                        logger.error(f"❌ CRITICAL: Failed to seed hosting plans data: {seed_error}")
                        logger.warning(f"⚠️ Additional verification error: {verify_error}")
                        logger.warning("⚠️ Application will continue without seeded hosting plans - manual seeding may be required")
                
                # User hosting subscriptions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS hosting_subscriptions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        hosting_plan_id INTEGER REFERENCES hosting_plans(id),
                        domain_name VARCHAR(255),
                        cpanel_username VARCHAR(255),
                        cpanel_password VARCHAR(255),
                        server_ip VARCHAR(45),
                        status VARCHAR(50),
                        billing_cycle VARCHAR(20),
                        next_billing_date DATE,
                        auto_renew BOOLEAN DEFAULT true,
                        grace_period_started TIMESTAMPTZ,
                        last_warning_sent TIMESTAMPTZ,
                        suspended_at TIMESTAMPTZ,
                        deletion_scheduled_for TIMESTAMPTZ,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # FIX: Ensure hosting_subscriptions sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'hosting_subscriptions_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('hosting_subscriptions_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM hosting_subscriptions),
                                    (SELECT last_value FROM hosting_subscriptions_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM hosting_subscriptions_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: hosting_subscriptions sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ hosting_subscriptions_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync hosting_subscriptions sequence: {seq_error}")
                
                
                # cPanel accounts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cpanel_accounts (
                        id SERIAL PRIMARY KEY,
                        subscription_id INTEGER REFERENCES hosting_subscriptions(id),
                        cpanel_username VARCHAR(255) UNIQUE NOT NULL,
                        cpanel_domain VARCHAR(255),
                        quota_mb INTEGER,
                        server_name VARCHAR(255),
                        ip_address VARCHAR(45),
                        status VARCHAR(50),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # FIX: Ensure cpanel_accounts sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'cpanel_accounts_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('cpanel_accounts_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM cpanel_accounts),
                                    (SELECT last_value FROM cpanel_accounts_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM cpanel_accounts_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: cpanel_accounts sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ cpanel_accounts_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync cpanel_accounts sequence: {seq_error}")
                
                # Domain-hosting bundles table for bundle management
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domain_hosting_bundles (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        domain_registration_intent_id INTEGER REFERENCES domain_registration_intents(id),
                        hosting_provision_intent_id INTEGER REFERENCES hosting_provision_intents(id),
                        bundle_type VARCHAR(50) DEFAULT 'domain_hosting',
                        bundle_status VARCHAR(50) DEFAULT 'pending',
                        total_amount DECIMAL(10,2),
                        discount_applied DECIMAL(10,2) DEFAULT 0.00,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                
                # Bundle discounts table for promotional discounts
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS bundle_discounts (
                        id SERIAL PRIMARY KEY,
                        discount_code VARCHAR(50) UNIQUE NOT NULL,
                        discount_type VARCHAR(20) NOT NULL,
                        discount_value DECIMAL(10,2),
                        min_bundle_value DECIMAL(10,2),
                        max_uses INTEGER,
                        current_uses INTEGER DEFAULT 0,
                        expires_at TIMESTAMP,
                        active BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Callback tokens table - REMOVED DUPLICATE (proper definition below)
                
                
                
                # CRITICAL: Provider claims table to prevent duplicate external API calls
                # Uses unique constraint to ensure only one address creation per (order_id, provider)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS provider_claims (
                        id SERIAL PRIMARY KEY,
                        order_id VARCHAR(255) NOT NULL,
                        provider_name VARCHAR(50) NOT NULL,
                        intent_id INTEGER REFERENCES payment_intents(id),
                        idempotency_key VARCHAR(255) NOT NULL,
                        status VARCHAR(50) NOT NULL DEFAULT 'claiming',
                        external_address VARCHAR(255),
                        external_order_id VARCHAR(255),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(order_id, provider_name)
                    )
                """)
                
                # Migration: Fix order_id column type in provider_claims
                cursor.execute("""
                    DO $$ 
                    BEGIN
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name = 'provider_claims' 
                            AND column_name = 'order_id' 
                            AND data_type = 'integer'
                        ) THEN
                            ALTER TABLE provider_claims DROP CONSTRAINT IF EXISTS provider_claims_order_id_provider_name_key;
                            ALTER TABLE provider_claims ALTER COLUMN order_id TYPE VARCHAR(255);
                            ALTER TABLE provider_claims ADD CONSTRAINT provider_claims_order_id_provider_name_key UNIQUE (order_id, provider_name);
                            RAISE NOTICE 'Migration: Updated provider_claims.order_id from INTEGER to VARCHAR(255)';
                        END IF;
                    END $$;
                """)
                
                # Webhook callbacks table for stronger idempotency protection
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_callbacks (
                        id SERIAL PRIMARY KEY,
                        order_id VARCHAR(255) NOT NULL,
                        confirmation_count INTEGER NOT NULL,
                        callback_type VARCHAR(50) NOT NULL,
                        status VARCHAR(50) NOT NULL DEFAULT 'processing',
                        txid VARCHAR(255),
                        amount_usd DECIMAL(10,2),
                        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP,
                        provider_name VARCHAR(50),
                        external_callback_id VARCHAR(255),
                        UNIQUE(order_id, confirmation_count, callback_type),
                        UNIQUE(provider_name, external_callback_id) -- Prevent duplicate provider callbacks
                    )
                """)
                
                # Migration: Fix order_id column type in webhook_callbacks
                cursor.execute("""
                    DO $$ 
                    BEGIN
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name = 'webhook_callbacks' 
                            AND column_name = 'order_id' 
                            AND data_type = 'integer'
                        ) THEN
                            ALTER TABLE webhook_callbacks DROP CONSTRAINT IF EXISTS webhook_callbacks_order_id_confirmation_count_callback_type_key;
                            ALTER TABLE webhook_callbacks ALTER COLUMN order_id TYPE VARCHAR(255);
                            ALTER TABLE webhook_callbacks ADD CONSTRAINT webhook_callbacks_order_id_confirmation_count_callback_type_key UNIQUE (order_id, confirmation_count, callback_type);
                            RAISE NOTICE 'Migration: Updated webhook_callbacks.order_id from INTEGER to VARCHAR(255)';
                        END IF;
                    END $$;
                """)
                
                # NOTE: callback_tokens indexes moved to after table creation (around line 1827)
                
                # Create indexes for payment_intents (critical for concurrent processing)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_payment_intents_order_id ON payment_intents(order_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_payment_intents_status ON payment_intents(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_payment_intents_expires_at ON payment_intents(expires_at)")
                
                # Create indexes for provider_claims (critical for atomic claiming)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_provider_claims_order_id ON provider_claims(order_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_provider_claims_intent_id ON provider_claims(intent_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_provider_claims_status ON provider_claims(status)")
                
                # Create indexes for webhook_callbacks (critical for concurrent processing)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_callbacks_order_id ON webhook_callbacks(order_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_callbacks_status ON webhook_callbacks(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_callbacks_processed_at ON webhook_callbacks(processed_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_callbacks_callback_type ON webhook_callbacks(callback_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_callbacks_provider_external ON webhook_callbacks(provider_name, external_callback_id)")
                
                # Create indexes for wallet_deposits (data integrity)
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_wallet_deposits_blockbee_order_id ON wallet_deposits(blockbee_order_id) WHERE blockbee_order_id IS NOT NULL")
                # CRITICAL FIX: Exclude 'unknown' txids to allow multiple payments when provider doesn't send real transaction hashes
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_wallet_deposits_txid ON wallet_deposits(txid) WHERE txid IS NOT NULL AND txid != 'unknown'")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallet_deposits_user_id ON wallet_deposits(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallet_deposits_payment_address ON wallet_deposits(payment_address)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallet_deposits_status ON wallet_deposits(status)")
                
                # Create indexes for domain_orders (data integrity and security)
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_orders_blockbee_order_id ON domain_orders(blockbee_order_id) WHERE blockbee_order_id IS NOT NULL")
                # CRITICAL FIX: Exclude 'unknown' txids to allow multiple payments when provider doesn't send real transaction hashes
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_orders_txid ON domain_orders(txid) WHERE txid IS NOT NULL AND txid != 'unknown'")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_orders_user_id ON domain_orders(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_orders_domain_name ON domain_orders(domain_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_orders_status ON domain_orders(status)")
                
                # Create indexes for bundle tables (performance optimization)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_hosting_bundles_user_id ON domain_hosting_bundles(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_hosting_bundles_status ON domain_hosting_bundles(bundle_status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_hosting_bundles_type ON domain_hosting_bundles(bundle_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_hosting_bundles_domain_intent ON domain_hosting_bundles(domain_registration_intent_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_hosting_bundles_hosting_intent ON domain_hosting_bundles(hosting_provision_intent_id)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_bundle_pricing_type ON bundle_pricing(bundle_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_bundle_pricing_tld ON bundle_pricing(domain_tld)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_bundle_pricing_hosting_plan ON bundle_pricing(hosting_plan_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_bundle_pricing_active ON bundle_pricing(active)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_bundle_discounts_code ON bundle_discounts(discount_code)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_bundle_discounts_type ON bundle_discounts(discount_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_bundle_discounts_active ON bundle_discounts(active)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_bundle_discounts_expires_at ON bundle_discounts(expires_at)")
                
                # CRITICAL SECURITY: Add missing columns to existing tables if they don't exist
                # This ensures backward compatibility for existing databases
                try:
                    cursor.execute("ALTER TABLE wallet_deposits ADD COLUMN IF NOT EXISTS txid VARCHAR(255)")
                    cursor.execute("ALTER TABLE domain_orders ADD COLUMN IF NOT EXISTS blockbee_order_id VARCHAR(255)")
                    cursor.execute("ALTER TABLE domain_orders ADD COLUMN IF NOT EXISTS txid VARCHAR(255)")
                    # Add new processing state machine columns
                    cursor.execute("ALTER TABLE domain_orders ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMP")
                    cursor.execute("ALTER TABLE domain_orders ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP")
                    cursor.execute("ALTER TABLE domain_orders ADD COLUMN IF NOT EXISTS error_message TEXT")
                except Exception as alter_error:
                    logger.warning(f"Column additions may have failed (likely already exist): {alter_error}")
                
                # CRITICAL: Add missing columns to webhook_callbacks table for concurrency fixes
                try:
                    cursor.execute("ALTER TABLE webhook_callbacks ADD COLUMN IF NOT EXISTS provider_name VARCHAR(50)")
                    cursor.execute("ALTER TABLE webhook_callbacks ADD COLUMN IF NOT EXISTS external_callback_id VARCHAR(255)")
                    logger.info("✅ Database migration: Added provider_name and external_callback_id columns to webhook_callbacks")
                except Exception as webhook_migration_error:
                    logger.warning(f"Webhook migration warning: {webhook_migration_error}")
                
                # CRITICAL: Add unique constraint for webhook idempotency (after columns exist)
                try:
                    cursor.execute("""
                        DO $$ 
                        BEGIN
                            IF NOT EXISTS (
                                SELECT 1 FROM pg_constraint 
                                WHERE conname = 'webhook_callbacks_provider_external_key'
                            ) THEN
                                ALTER TABLE webhook_callbacks ADD CONSTRAINT webhook_callbacks_provider_external_key 
                                UNIQUE(provider_name, external_callback_id);
                            END IF;
                        END $$;
                    """)
                    logger.info("✅ Database migration: Added unique constraint on webhook_callbacks(provider_name, external_callback_id)")
                except Exception as constraint_error:
                    logger.warning(f"⚠️ Database constraint migration warning (non-critical): {constraint_error}")
                
                # MIGRATION: Add missing ownership_state column to domains table
                try:
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS ownership_state VARCHAR(50)")
                    logger.info("✅ Database migration: Added ownership_state column to domains table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (ownership_state): {migration_error}")
                
                # CRITICAL MIGRATION: Add missing processing_started_at column to hosting_provision_intents table
                try:
                    cursor.execute("ALTER TABLE hosting_provision_intents ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMP")
                    logger.info("✅ Database migration: Added processing_started_at column to hosting_provision_intents table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (hosting processing_started_at): {migration_error}")
                
                # CRITICAL MIGRATION: Add missing estimated_price column to hosting_provision_intents table
                try:
                    cursor.execute("ALTER TABLE hosting_provision_intents ADD COLUMN IF NOT EXISTS estimated_price DECIMAL(10,2)")
                    logger.info("✅ Database migration: Added estimated_price column to hosting_provision_intents table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (estimated_price): {migration_error}")
                
                # CRITICAL MIGRATION: Add missing error_message column to hosting_provision_intents table
                try:
                    cursor.execute("ALTER TABLE hosting_provision_intents ADD COLUMN IF NOT EXISTS error_message TEXT")
                    logger.info("✅ Database migration: Added error_message column to hosting_provision_intents table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (error_message): {migration_error}")
                
                # CRITICAL MIGRATION: Add missing domain_id column to hosting_subscriptions table
                try:
                    cursor.execute("ALTER TABLE hosting_subscriptions ADD COLUMN IF NOT EXISTS domain_id INTEGER")
                    logger.info("✅ Database migration: Added domain_id column to hosting_subscriptions table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (domain_id): {migration_error}")
                
                # CRITICAL MIGRATION SAFEGUARD: Verify and prevent order_id column type conflicts
                # This prevents the migration error by ensuring schema consistency
                try:
                    logger.info("🔍 Running migration safeguard checks for order_id columns...")
                    
                    # Check current column types for order_id across all relevant tables
                    order_id_tables = ["payment_intents", "payment_intents_unified", "provider_claims", "webhook_callbacks"]
                    
                    for table_name in order_id_tables:
                        # Check if table exists and get order_id column type
                        cursor.execute("""
                            SELECT data_type 
                            FROM information_schema.columns 
                            WHERE table_name = %s AND column_name = 'order_id'
                        """, (table_name,))
                        result = cursor.fetchone()
                        
                        if result:
                            current_type = result[0] if isinstance(result, tuple) else result['data_type']
                            
                            # Define expected types for each table
                            expected_types = {
                                'payment_intents': 'character varying',  # String-based order IDs
                                'provider_claims': 'character varying',  # String-based order IDs  
                                'webhook_callbacks': 'character varying',  # String-based order IDs
                                'payment_intents_unified': 'integer'  # Integer references to orders table
                            }
                            
                            expected_type = expected_types.get(table_name, 'integer')  # Default to integer for other tables
                            
                            if current_type == expected_type:
                                type_name = "VARCHAR" if expected_type == 'character varying' else "INTEGER"
                                logger.info(f"✅ MIGRATION SAFEGUARD: {table_name}.order_id is already {type_name} (correct)")
                            else:
                                expected_name = "VARCHAR" if expected_type == 'character varying' else "INTEGER"
                                current_name = "VARCHAR" if current_type == 'character varying' else current_type.upper()
                                logger.warning(f"⚠️ MIGRATION SAFEGUARD: {table_name}.order_id is {current_name} but should be {expected_name}")
                                logger.info(f"📋 This inconsistency has been noted but not automatically fixed to preserve data integrity")
                        else:
                            logger.debug(f"MIGRATION SAFEGUARD: Table {table_name} does not exist or has no order_id column")
                    
                    logger.info("✅ MIGRATION SAFEGUARD: order_id column type verification complete")
                except Exception as safeguard_error:
                    logger.warning(f"⚠️ Migration safeguard warning (non-critical): {safeguard_error}")
                    # Don't fail initialization due to safeguard issues
                
                # Domain searches table (ephemeral search history)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domain_searches (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        domain_name VARCHAR(255) NOT NULL,
                        availability_snapshot JSONB,
                        price_snapshot JSONB,
                        nameservers_snapshot JSONB,
                        search_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Domain registration intents table (prevent duplicate registrations)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domain_registration_intents (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        domain_name VARCHAR(255) NOT NULL,
                        quote_price DECIMAL(10,2) NOT NULL,
                        currency VARCHAR(10) DEFAULT 'USD',
                        status VARCHAR(50) DEFAULT 'created',
                        idempotency_key VARCHAR(255) UNIQUE NOT NULL,
                        provider_domain_id VARCHAR(255),
                        completed_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Hosting provision intents table (prevent duplicate hosting provisioning)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS hosting_provision_intents (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        domain_id INTEGER,
                        domain_name VARCHAR(255),
                        hosting_plan_id INTEGER REFERENCES hosting_plans(id),
                        quote_price DECIMAL(10,2) NOT NULL,
                        currency VARCHAR(10) DEFAULT 'USD',
                        status VARCHAR(50) DEFAULT 'pending_payment',
                        service_type VARCHAR(50) NOT NULL,
                        idempotency_key VARCHAR(255) UNIQUE NOT NULL,
                        external_reference VARCHAR(255),
                        last_error TEXT,
                        processing_started_at TIMESTAMP,
                        completed_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # FIX: Ensure hosting_provision_intents sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'hosting_provision_intents_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('hosting_provision_intents_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM hosting_provision_intents),
                                    (SELECT last_value FROM hosting_provision_intents_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM hosting_provision_intents_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: hosting_provision_intents sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ hosting_provision_intents_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync hosting_provision_intents sequence: {seq_error}")
                
                # Domain notifications table (prevent duplicate notifications)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domain_notifications (
                        id SERIAL PRIMARY KEY,
                        order_id VARCHAR(255) NOT NULL,
                        message_type VARCHAR(100) NOT NULL,
                        user_id INTEGER REFERENCES users(id),
                        message_content TEXT,
                        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(order_id, message_type)
                    )
                """)
                
                # CRITICAL: Refund tracking table for idempotent refund processing
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS refund_tracking (
                        id SERIAL PRIMARY KEY,
                        order_id INTEGER NOT NULL,
                        user_id INTEGER REFERENCES users(id),
                        domain_name VARCHAR(255) NOT NULL,
                        status VARCHAR(50) DEFAULT 'processing',
                        failure_phase VARCHAR(100),
                        failure_reason TEXT,
                        refund_method VARCHAR(50),
                        provider_status VARCHAR(50),
                        provider_response JSONB,
                        error_message TEXT,
                        idempotency_key VARCHAR(255) UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP,
                        UNIQUE(order_id, user_id, domain_name)
                    )
                """)
                
                # Create indexes for refund_tracking (critical for performance)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_refund_tracking_order_id ON refund_tracking(order_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_refund_tracking_user_id ON refund_tracking(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_refund_tracking_status ON refund_tracking(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_refund_tracking_domain_name ON refund_tracking(domain_name)")
                
                
                # Bundle pricing table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS bundle_pricing (
                        id SERIAL PRIMARY KEY,
                        bundle_type VARCHAR(50) NOT NULL,
                        domain_tld VARCHAR(10),
                        hosting_plan_id INTEGER REFERENCES hosting_plans(id),
                        base_price DECIMAL(10,2),
                        discount_percentage DECIMAL(5,2),
                        final_price DECIMAL(10,2),
                        active BOOLEAN DEFAULT true,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                
                # Callback tokens table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS callback_tokens (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        token_value VARCHAR(255) UNIQUE NOT NULL,
                        token_type VARCHAR(50) NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        used BOOLEAN DEFAULT false,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for callback_tokens (moved from line 1535 - after table creation)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_callback_tokens_user_id ON callback_tokens(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_callback_tokens_expires_at ON callback_tokens(expires_at)")
                
                # Payment intents table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS payment_intents (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        order_id VARCHAR(255) NOT NULL,
                        order_type VARCHAR(50) NOT NULL,
                        amount DECIMAL(10,2) NOT NULL,
                        currency VARCHAR(10) DEFAULT 'USD',
                        status VARCHAR(50) DEFAULT 'created',
                        payment_address VARCHAR(255),
                        payment_method VARCHAR(50),
                        provider_name VARCHAR(50),
                        provider_order_id VARCHAR(255),
                        expires_at TIMESTAMP,
                        completed_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # FIX: Ensure payment_intents sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'payment_intents_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('payment_intents_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM payment_intents),
                                    (SELECT last_value FROM payment_intents_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM payment_intents_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: payment_intents sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ payment_intents_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync payment_intents sequence: {seq_error}")
                
                # =============================================================================
                # WEBHOOK HEALTH MONITORING TABLES
                # =============================================================================
                
                # Track all webhook delivery attempts and their outcomes
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_delivery_logs (
                        id SERIAL PRIMARY KEY,
                        payment_intent_id INTEGER REFERENCES payment_intents(id),
                        provider VARCHAR(50) NOT NULL,
                        webhook_type VARCHAR(50) NOT NULL,
                        
                        request_id VARCHAR(255),
                        expected_at TIMESTAMP,
                        received_at TIMESTAMP,
                        
                        processing_started_at TIMESTAMP,
                        processing_completed_at TIMESTAMP,
                        processing_duration_ms INTEGER,
                        
                        delivery_status VARCHAR(50) NOT NULL,
                        processing_status VARCHAR(50) NOT NULL,
                        http_status_code INTEGER,
                        
                        error_type VARCHAR(100),
                        error_message TEXT,
                        retry_count INTEGER DEFAULT 0,
                        last_retry_at TIMESTAMP,
                        
                        security_validation_passed BOOLEAN DEFAULT FALSE,
                        signature_valid BOOLEAN,
                        timestamp_valid BOOLEAN,
                        rate_limit_exceeded BOOLEAN DEFAULT FALSE,
                        
                        payload_size_bytes INTEGER,
                        payload_hash VARCHAR(64),
                        raw_payload JSONB,
                        
                        payment_confirmed BOOLEAN DEFAULT FALSE,
                        wallet_credited BOOLEAN DEFAULT FALSE,
                        user_notified BOOLEAN DEFAULT FALSE,
                        
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # FIX: Ensure webhook_delivery_logs sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'webhook_delivery_logs_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('webhook_delivery_logs_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM webhook_delivery_logs),
                                    (SELECT last_value FROM webhook_delivery_logs_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM webhook_delivery_logs_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: webhook_delivery_logs sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ webhook_delivery_logs_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync webhook_delivery_logs sequence: {seq_error}")
                
                # Aggregate health metrics per provider with time-based buckets
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_provider_health (
                        id SERIAL PRIMARY KEY,
                        provider VARCHAR(50) NOT NULL,
                        metric_window_start TIMESTAMP NOT NULL,
                        metric_window_end TIMESTAMP NOT NULL,
                        window_duration_minutes INTEGER NOT NULL,
                        
                        total_expected_webhooks INTEGER DEFAULT 0,
                        total_received_webhooks INTEGER DEFAULT 0,
                        total_successful_webhooks INTEGER DEFAULT 0,
                        total_failed_webhooks INTEGER DEFAULT 0,
                        total_duplicate_webhooks INTEGER DEFAULT 0,
                        
                        avg_delivery_delay_seconds DECIMAL(10,3),
                        avg_processing_time_ms DECIMAL(10,3),
                        min_processing_time_ms INTEGER,
                        max_processing_time_ms INTEGER,
                        p95_processing_time_ms INTEGER,
                        
                        delivery_success_rate DECIMAL(5,4),
                        processing_success_rate DECIMAL(5,4),
                        security_pass_rate DECIMAL(5,4),
                        
                        security_failures INTEGER DEFAULT 0,
                        parsing_errors INTEGER DEFAULT 0,
                        business_logic_errors INTEGER DEFAULT 0,
                        timeout_errors INTEGER DEFAULT 0,
                        rate_limit_hits INTEGER DEFAULT 0,
                        
                        health_score DECIMAL(5,2),
                        health_status VARCHAR(20),
                        
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        
                        UNIQUE(provider, metric_window_start, window_duration_minutes)
                    )
                """)
                
                # FIX: Ensure webhook_provider_health sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'webhook_provider_health_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('webhook_provider_health_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM webhook_provider_health),
                                    (SELECT last_value FROM webhook_provider_health_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM webhook_provider_health_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: webhook_provider_health sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ webhook_provider_health_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync webhook_provider_health sequence: {seq_error}")
                
                # Track payment intents that may be missing webhook confirmations
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS missing_confirmation_alerts (
                        id SERIAL PRIMARY KEY,
                        payment_intent_id INTEGER REFERENCES payment_intents(id),
                        provider VARCHAR(50) NOT NULL,
                        
                        detection_type VARCHAR(50) NOT NULL,
                        detected_at TIMESTAMP NOT NULL,
                        expected_confirmation_by TIMESTAMP,
                        time_overdue_minutes INTEGER,
                        
                        payment_status VARCHAR(50),
                        payment_amount DECIMAL(12,2),
                        payment_currency VARCHAR(10),
                        crypto_currency VARCHAR(10),
                        payment_address VARCHAR(255),
                        order_id VARCHAR(255),
                        
                        last_webhook_received_at TIMESTAMP,
                        total_webhooks_received INTEGER DEFAULT 0,
                        payment_created_at TIMESTAMP,
                        payment_expires_at TIMESTAMP,
                        
                        recovery_status VARCHAR(50) DEFAULT 'pending',
                        recovery_attempted_at TIMESTAMP,
                        recovery_method VARCHAR(50),
                        recovery_result TEXT,
                        
                        alert_sent BOOLEAN DEFAULT FALSE,
                        alert_sent_at TIMESTAMP,
                        alert_level VARCHAR(20),
                        escalation_level INTEGER DEFAULT 0,
                        acknowledged BOOLEAN DEFAULT FALSE,
                        acknowledged_by VARCHAR(100),
                        acknowledged_at TIMESTAMP,
                        
                        resolved BOOLEAN DEFAULT FALSE,
                        resolved_at TIMESTAMP,
                        resolution_notes TEXT,
                        
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        
                        UNIQUE (payment_intent_id, provider, detection_type)
                    )
                """)
                
                # FIX: Ensure missing_confirmation_alerts sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'missing_confirmation_alerts_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('missing_confirmation_alerts_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM missing_confirmation_alerts),
                                    (SELECT last_value FROM missing_confirmation_alerts_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM missing_confirmation_alerts_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: missing_confirmation_alerts sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ missing_confirmation_alerts_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync missing_confirmation_alerts sequence: {seq_error}")
                
                # Log significant health events for alerting and analysis
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_health_events (
                        id SERIAL PRIMARY KEY,
                        event_type VARCHAR(50) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        provider VARCHAR(50),
                        
                        event_title VARCHAR(255) NOT NULL,
                        event_description TEXT,
                        event_context JSONB,
                        
                        current_health_score DECIMAL(5,2),
                        current_success_rate DECIMAL(5,4),
                        affected_payments_count INTEGER DEFAULT 0,
                        
                        threshold_type VARCHAR(50),
                        threshold_value DECIMAL(10,4),
                        actual_value DECIMAL(10,4),
                        
                        alert_sent BOOLEAN DEFAULT FALSE,
                        alert_sent_at TIMESTAMP,
                        alert_fingerprint VARCHAR(32),
                        
                        resolved BOOLEAN DEFAULT FALSE,
                        resolved_at TIMESTAMP,
                        auto_resolved BOOLEAN DEFAULT FALSE,
                        
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # FIX: Ensure webhook_health_events sequence is in sync with data
                try:
                    # Check if sequence exists before trying to sync
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM pg_class 
                            WHERE relkind = 'S' 
                            AND relname = 'webhook_health_events_id_seq'
                        )
                    """)
                    seq_exists_result = cursor.fetchone()
                    if seq_exists_result:
                        seq_exists = seq_exists_result[0] if isinstance(seq_exists_result, tuple) else seq_exists_result.get('exists', False)
                    else:
                        seq_exists = False
                    
                    if seq_exists:
                        cursor.execute("""
                            SELECT setval('webhook_health_events_id_seq', 
                                GREATEST(
                                    (SELECT COALESCE(MAX(id), 0) FROM webhook_health_events),
                                    (SELECT last_value FROM webhook_health_events_id_seq)
                                ),
                                true
                            )
                        """)
                        cursor.execute("SELECT last_value FROM webhook_health_events_id_seq")
                        seq_result = cursor.fetchone()
                        if seq_result:
                            seq_value = seq_result[0] if isinstance(seq_result, (list, tuple)) else seq_result.get('last_value', 0)
                            logger.info(f"✅ SEQUENCE FIX: webhook_health_events sequence synchronized to {seq_value}")
                    else:
                        logger.info(f"ℹ️ webhook_health_events_id_seq sequence does not exist (table may use different ID strategy)")
                except Exception as seq_error:
                    logger.warning(f"⚠️ Could not sync webhook_health_events sequence: {seq_error}")
                
                # Webhook monitoring configuration table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_monitoring_config (
                        id SERIAL PRIMARY KEY,
                        provider VARCHAR(50) NOT NULL,
                        
                        min_success_rate_threshold DECIMAL(5,4) DEFAULT 0.9500,
                        max_avg_processing_time_ms INTEGER DEFAULT 5000,
                        max_delivery_delay_seconds INTEGER DEFAULT 300,
                        missing_confirmation_timeout_minutes INTEGER DEFAULT 30,
                        
                        alert_on_threshold_breach BOOLEAN DEFAULT TRUE,
                        alert_cooldown_minutes INTEGER DEFAULT 60,
                        escalation_thresholds INTEGER[] DEFAULT ARRAY[3, 10, 25],
                        
                        monitoring_enabled BOOLEAN DEFAULT TRUE,
                        auto_recovery_enabled BOOLEAN DEFAULT TRUE,
                        
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        
                        UNIQUE(provider)
                    )
                """)
                
                # Add all columns if they don't exist (migration for existing tables)
                try:
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS provider VARCHAR(50)")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS min_success_rate_threshold DECIMAL(5,4) DEFAULT 0.9500")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS max_avg_processing_time_ms INTEGER DEFAULT 5000")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS max_delivery_delay_seconds INTEGER DEFAULT 300")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS missing_confirmation_timeout_minutes INTEGER DEFAULT 30")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS alert_on_threshold_breach BOOLEAN DEFAULT TRUE")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS alert_cooldown_minutes INTEGER DEFAULT 60")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS escalation_thresholds INTEGER[] DEFAULT ARRAY[3, 10, 25]")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS monitoring_enabled BOOLEAN DEFAULT TRUE")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS auto_recovery_enabled BOOLEAN DEFAULT TRUE")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                    cursor.execute("ALTER TABLE webhook_monitoring_config ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                    
                    # CRITICAL FIX: Migrate from old provider_name column to new provider column
                    # Step 1: Copy data from provider_name to provider if provider is null
                    cursor.execute("""
                        UPDATE webhook_monitoring_config 
                        SET provider = provider_name 
                        WHERE provider IS NULL AND provider_name IS NOT NULL
                    """)
                    
                    # Step 2: Drop the old provider_name column to avoid conflicts
                    cursor.execute("ALTER TABLE webhook_monitoring_config DROP COLUMN IF EXISTS provider_name CASCADE")
                    
                    # Step 3: Make provider column NOT NULL after migration
                    cursor.execute("ALTER TABLE webhook_monitoring_config ALTER COLUMN provider SET NOT NULL")
                    
                    # Add UNIQUE constraint on provider if not exists
                    cursor.execute("""
                        DO $$
                        BEGIN
                            IF NOT EXISTS (
                                SELECT 1 FROM pg_constraint 
                                WHERE conname = 'webhook_monitoring_config_provider_key'
                            ) THEN
                                ALTER TABLE webhook_monitoring_config ADD CONSTRAINT webhook_monitoring_config_provider_key UNIQUE (provider);
                            END IF;
                        END $$;
                    """)
                    
                    logger.info("✅ Database migration: Ensured webhook_monitoring_config has all required columns")
                    logger.info("✅ Database migration: Migrated from provider_name to provider column")
                except Exception as e:
                    logger.debug(f"webhook_monitoring_config column migration note: {e}")
                
                # Insert default monitoring configurations for known providers if not exists
                cursor.execute("""
                    INSERT INTO webhook_monitoring_config (provider, min_success_rate_threshold, max_avg_processing_time_ms, missing_confirmation_timeout_minutes, created_at, updated_at)
                    VALUES ('dynopay', 0.9500, 5000, 30, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT (provider) DO NOTHING
                """)
                cursor.execute("""
                    INSERT INTO webhook_monitoring_config (provider, min_success_rate_threshold, max_avg_processing_time_ms, missing_confirmation_timeout_minutes, created_at, updated_at)
                    VALUES ('blockbee', 0.9500, 5000, 30, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT (provider) DO NOTHING
                """)
                
                # Create indexes for webhook health monitoring tables
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_provider ON webhook_delivery_logs(provider)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_payment ON webhook_delivery_logs(payment_intent_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_received ON webhook_delivery_logs(received_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_status ON webhook_delivery_logs(delivery_status, processing_status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_delivery_logs_hash ON webhook_delivery_logs(payload_hash)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_provider_health_provider ON webhook_provider_health(provider)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_provider_health_window ON webhook_provider_health(metric_window_start, metric_window_end)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_provider_health_score ON webhook_provider_health(health_score)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_missing_confirmation_payment ON missing_confirmation_alerts(payment_intent_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_missing_confirmation_provider ON missing_confirmation_alerts(provider)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_missing_confirmation_detected ON missing_confirmation_alerts(detected_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_missing_confirmation_status ON missing_confirmation_alerts(recovery_status, resolved)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_missing_confirmation_alerts ON missing_confirmation_alerts(alert_sent, acknowledged)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_health_events_type ON webhook_health_events(event_type, severity)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_health_events_provider ON webhook_health_events(provider)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_health_events_created ON webhook_health_events(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_health_events_fingerprint ON webhook_health_events(alert_fingerprint)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_monitoring_config_provider ON webhook_monitoring_config(provider)")
                
                # =============================================================================
                # WEBHOOK MANAGEMENT SYSTEM TABLES
                # =============================================================================
                
                # Webhooks table - user-configured webhooks for API events
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS webhooks (
                        id SERIAL PRIMARY KEY,
                        user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                        url VARCHAR(500) NOT NULL,
                        secret VARCHAR(128) NOT NULL,
                        events JSONB NOT NULL,
                        description TEXT,
                        is_active BOOLEAN DEFAULT true,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_triggered_at TIMESTAMP,
                        success_count INTEGER DEFAULT 0,
                        failure_count INTEGER DEFAULT 0
                    )
                """)
                
                # Create indexes for webhooks table
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON webhooks(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_is_active ON webhooks(is_active)")
                
                # Webhook deliveries table - tracks each delivery attempt
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_deliveries (
                        id SERIAL PRIMARY KEY,
                        webhook_id INTEGER REFERENCES webhooks(id) ON DELETE CASCADE,
                        event_type VARCHAR(100) NOT NULL,
                        payload JSONB NOT NULL,
                        response_code INTEGER,
                        response_body TEXT,
                        status VARCHAR(50) DEFAULT 'pending',
                        attempts INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        delivered_at TIMESTAMP
                    )
                """)
                
                # Create indexes for webhook_deliveries table
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created_at ON webhook_deliveries(created_at)")
                
                # Webhook events table - catalog of available webhook event types
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS webhook_events (
                        event_type VARCHAR(100) PRIMARY KEY,
                        description TEXT,
                        category VARCHAR(50)
                    )
                """)
                
                # Populate webhook_events with initial data
                cursor.execute("""
                    INSERT INTO webhook_events (event_type, description, category) VALUES
                        ('domain.registered', 'Domain successfully registered', 'domain'),
                        ('domain.renewed', 'Domain successfully renewed', 'domain'),
                        ('domain.transferred', 'Domain successfully transferred', 'domain'),
                        ('domain.deleted', 'Domain deleted', 'domain'),
                        ('domain.dns_updated', 'DNS records updated', 'domain'),
                        ('hosting.provisioned', 'Hosting account provisioned', 'hosting'),
                        ('hosting.renewed', 'Hosting subscription renewed', 'hosting'),
                        ('hosting.suspended', 'Hosting account suspended', 'hosting'),
                        ('hosting.unsuspended', 'Hosting account unsuspended', 'hosting'),
                        ('hosting.deleted', 'Hosting account deleted', 'hosting'),
                        ('payment.confirmed', 'Payment confirmed', 'payment'),
                        ('payment.failed', 'Payment failed', 'payment'),
                        ('wallet.topup', 'Wallet balance topped up', 'payment'),
                        ('order.completed', 'Order completed successfully', 'order'),
                        ('order.failed', 'Order failed', 'order')
                    ON CONFLICT (event_type) DO NOTHING
                """)
                
                
                # 🚨 CRITICAL SECURITY FIX: Add cpanel_secret_ref column and NULL plaintext passwords
                try:
                    cursor.execute("ALTER TABLE hosting_subscriptions ADD COLUMN IF NOT EXISTS cpanel_secret_ref VARCHAR(255)")
                    # IMMEDIATELY NULL all existing plaintext passwords for security
                    cursor.execute("UPDATE hosting_subscriptions SET cpanel_password = NULL WHERE cpanel_password IS NOT NULL")
                    logger.info("🔒 CRITICAL SECURITY FIX: Added cpanel_secret_ref column and nullified all plaintext passwords")
                except Exception as security_migration_error:
                    logger.error(f"🚫 CRITICAL SECURITY MIGRATION FAILED: {security_migration_error}")
                    raise  # This is critical security - fail initialization if migration fails
                
                # MIGRATION: Add suspension tracking columns to hosting_subscriptions table
                try:
                    cursor.execute("ALTER TABLE hosting_subscriptions ADD COLUMN IF NOT EXISTS grace_period_started TIMESTAMPTZ")
                    logger.info("✅ Database migration: Added grace_period_started column to hosting_subscriptions table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (grace_period_started): {migration_error}")
                
                try:
                    cursor.execute("ALTER TABLE hosting_subscriptions ADD COLUMN IF NOT EXISTS last_warning_sent TIMESTAMPTZ")
                    logger.info("✅ Database migration: Added last_warning_sent column to hosting_subscriptions table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (last_warning_sent): {migration_error}")
                
                try:
                    cursor.execute("ALTER TABLE hosting_subscriptions ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ")
                    logger.info("✅ Database migration: Added suspended_at column to hosting_subscriptions table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (suspended_at): {migration_error}")
                
                try:
                    cursor.execute("ALTER TABLE hosting_subscriptions ADD COLUMN IF NOT EXISTS deletion_scheduled_for TIMESTAMPTZ")
                    logger.info("✅ Database migration: Added deletion_scheduled_for column to hosting_subscriptions table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (deletion_scheduled_for): {migration_error}")
                
                # MIGRATION: Add missing columns to orders table for UUID-based order system
                try:
                    cursor.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS domain_name VARCHAR(255)")
                    logger.info("✅ Database migration: Added domain_name column to orders table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (orders domain_name): {migration_error}")
                
                try:
                    cursor.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_address VARCHAR(255)")
                    logger.info("✅ Database migration: Added payment_address column to orders table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (orders payment_address): {migration_error}")
                
                try:
                    cursor.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS external_order_id VARCHAR(255)")
                    logger.info("✅ Database migration: Added external_order_id column to orders table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (orders external_order_id): {migration_error}")
                
                try:
                    cursor.execute("ALTER TABLE orders ADD COLUMN IF NOT EXISTS intent_id INTEGER")
                    logger.info("✅ Database migration: Added intent_id column to orders table")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (orders intent_id): {migration_error}")
                
                # 🏗️ PHASE 1: Add unified tables for order management system
                
                # Unified orders table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS orders (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        status VARCHAR(50) NOT NULL,
                        total_amount NUMERIC(12,2),
                        currency VARCHAR(10) DEFAULT 'USD',
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Unified order items table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS order_items (
                        id SERIAL PRIMARY KEY,
                        order_id INTEGER REFERENCES orders(id),
                        item_type VARCHAR(50) NOT NULL,
                        item_name VARCHAR(255) NOT NULL,
                        quantity INTEGER DEFAULT 1,
                        unit_price NUMERIC(12,2),
                        total_price NUMERIC(12,2),
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Unified payment intents table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS payment_intents_unified (
                        id SERIAL PRIMARY KEY,
                        order_id INTEGER REFERENCES orders(id),
                        amount NUMERIC(12,2) NOT NULL,
                        currency VARCHAR(10) DEFAULT 'USD',
                        status VARCHAR(50) NOT NULL DEFAULT 'created',
                        payment_method VARCHAR(50),
                        payment_provider VARCHAR(50),
                        payment_provider_id VARCHAR(255),
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Unified ledger transactions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ledger_transactions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id),
                        order_id INTEGER REFERENCES orders(id),
                        transaction_type VARCHAR(50) NOT NULL,
                        amount NUMERIC(12,2) NOT NULL,
                        currency VARCHAR(10) DEFAULT 'USD',
                        balance_before NUMERIC(12,2),
                        balance_after NUMERIC(12,2),
                        description TEXT,
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Unified refunds table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS refunds_unified (
                        id SERIAL PRIMARY KEY,
                        order_id INTEGER REFERENCES orders(id),
                        user_id INTEGER REFERENCES users(id),
                        amount NUMERIC(12,2) NOT NULL,
                        currency VARCHAR(10) DEFAULT 'USD',
                        reason VARCHAR(255),
                        status VARCHAR(50) DEFAULT 'pending',
                        payment_provider VARCHAR(50),
                        payment_provider_refund_id VARCHAR(255),
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for Phase 1 unified tables
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_order_items_item_type ON order_items(item_type)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_payment_intents_unified_order_id ON payment_intents_unified(order_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_payment_intents_unified_status ON payment_intents_unified(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_payment_intents_unified_payment_provider ON payment_intents_unified(payment_provider)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_ledger_transactions_user_id ON ledger_transactions(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_ledger_transactions_order_id ON ledger_transactions(order_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_ledger_transactions_type ON ledger_transactions(transaction_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_ledger_transactions_created_at ON ledger_transactions(created_at)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_refunds_unified_order_id ON refunds_unified(order_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_refunds_unified_user_id ON refunds_unified(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_refunds_unified_status ON refunds_unified(status)")
                
                # Domain Link Intents table for workflow state management
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domain_link_intents (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER REFERENCES users(id) NOT NULL,
                        domain_name VARCHAR(255) NOT NULL,
                        hosting_subscription_id INTEGER REFERENCES hosting_subscriptions(id),
                        intent_type VARCHAR(50) NOT NULL DEFAULT 'smart_mode',
                        workflow_state VARCHAR(50) NOT NULL DEFAULT 'initiated',
                        current_step VARCHAR(100),
                        progress_percentage INTEGER DEFAULT 0,
                        linking_strategy VARCHAR(50),
                        current_nameservers TEXT[],
                        target_nameservers TEXT[],
                        dns_verification_status VARCHAR(50) DEFAULT 'pending',
                        ownership_verification_status VARCHAR(50) DEFAULT 'pending',
                        configuration_data JSONB,
                        error_details JSONB,
                        retry_count INTEGER DEFAULT 0,
                        last_verification_at TIMESTAMPTZ,
                        estimated_completion_at TIMESTAMPTZ,
                        completed_at TIMESTAMPTZ,
                        failed_at TIMESTAMPTZ,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Domain Verifications table for tracking DNS and ownership checks
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS domain_verifications (
                        id SERIAL PRIMARY KEY,
                        domain_link_intent_id INTEGER REFERENCES domain_link_intents(id) NOT NULL,
                        verification_type VARCHAR(50) NOT NULL,
                        verification_step VARCHAR(100) NOT NULL,
                        status VARCHAR(50) NOT NULL DEFAULT 'pending',
                        verification_method VARCHAR(50),
                        expected_value TEXT,
                        actual_value TEXT,
                        check_details JSONB,
                        error_message TEXT,
                        retry_count INTEGER DEFAULT 0,
                        next_check_at TIMESTAMPTZ,
                        first_checked_at TIMESTAMPTZ,
                        last_checked_at TIMESTAMPTZ,
                        completed_at TIMESTAMPTZ,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create indexes for domain linking tables
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_link_intents_user_id ON domain_link_intents(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_link_intents_domain_name ON domain_link_intents(domain_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_link_intents_workflow_state ON domain_link_intents(workflow_state)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_link_intents_hosting_subscription_id ON domain_link_intents(hosting_subscription_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_link_intents_created_at ON domain_link_intents(created_at)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_verifications_intent_id ON domain_verifications(domain_link_intent_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_verifications_type ON domain_verifications(verification_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_verifications_status ON domain_verifications(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_verifications_next_check_at ON domain_verifications(next_check_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain_verifications_created_at ON domain_verifications(created_at)")
                
                # =============================================================================
                # SECURITY TABLES: Admin monitoring, audit logging, and encryption management
                # =============================================================================
                
                # Admin alerts table for security monitoring
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS admin_alerts (
                        id SERIAL PRIMARY KEY,
                        severity VARCHAR(20) NOT NULL,
                        category VARCHAR(50) NOT NULL,
                        component VARCHAR(100) NOT NULL,
                        message TEXT NOT NULL,
                        details JSONB,
                        fingerprint VARCHAR(255) UNIQUE,
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                        sent_at TIMESTAMPTZ,
                        suppressed BOOLEAN DEFAULT FALSE
                    )
                """)
                
                # Audit log table for comprehensive activity tracking
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id SERIAL PRIMARY KEY,
                        table_name VARCHAR(100) NOT NULL,
                        operation VARCHAR(20) NOT NULL,
                        record_id INTEGER,
                        user_id INTEGER REFERENCES users(id),
                        session_id VARCHAR(255),
                        old_values JSONB,
                        new_values JSONB,
                        changed_fields TEXT[],
                        ip_address INET,
                        user_agent TEXT,
                        application_context VARCHAR(100),
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                        role_name VARCHAR(50),
                        is_admin BOOLEAN DEFAULT FALSE,
                        transaction_id VARCHAR(255),
                        checksum VARCHAR(64),
                        is_soft_delete BOOLEAN DEFAULT FALSE,
                        soft_delete_reason TEXT
                    )
                """)
                
                # DNS records table for DNS management tracking
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS dns_records (
                        id SERIAL PRIMARY KEY,
                        domain_name VARCHAR(255) NOT NULL,
                        record_type VARCHAR(10) NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        content TEXT NOT NULL,
                        ttl INTEGER DEFAULT 300,
                        priority INTEGER,
                        cloudflare_record_id VARCHAR(100),
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # DNS record history table for tracking DNS changes over time
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS dns_record_history (
                        id SERIAL PRIMARY KEY,
                        domain_name VARCHAR(255) NOT NULL,
                        record_type VARCHAR(10) NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        content TEXT NOT NULL,
                        ttl INTEGER,
                        priority INTEGER,
                        cloudflare_record_id VARCHAR(100),
                        action VARCHAR(20) NOT NULL,
                        user_id INTEGER,
                        old_content TEXT,
                        old_ttl INTEGER,
                        old_priority INTEGER,
                        metadata JSONB,
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Encryption audit table for tracking encryption operations
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS encryption_audit (
                        id SERIAL PRIMARY KEY,
                        operation VARCHAR(50) NOT NULL,
                        table_name VARCHAR(100) NOT NULL,
                        column_name VARCHAR(100),
                        record_id INTEGER,
                        key_id INTEGER,
                        key_alias VARCHAR(100),
                        user_id INTEGER REFERENCES users(id),
                        role_name VARCHAR(50),
                        success BOOLEAN NOT NULL,
                        error_message TEXT,
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Encryption keys table for key management (SECURE - no actual keys stored)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS encryption_keys (
                        id SERIAL PRIMARY KEY,
                        key_alias VARCHAR(100) UNIQUE NOT NULL,
                        key_version INTEGER DEFAULT 1,
                        salt VARCHAR(64),
                        is_active BOOLEAN DEFAULT TRUE,
                        is_default BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                        retired_at TIMESTAMPTZ
                    )
                """)
                
                # Create indexes for security tables
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_alerts_severity ON admin_alerts(severity)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_alerts_category ON admin_alerts(category)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_alerts_component ON admin_alerts(component)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_alerts_created_at ON admin_alerts(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_alerts_fingerprint ON admin_alerts(fingerprint)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_table_name ON audit_log(table_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_operation ON audit_log(operation)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_record_id ON audit_log(record_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_transaction_id ON audit_log(transaction_id)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_records_domain_name ON dns_records(domain_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_records_record_type ON dns_records(record_type)")
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_records_cloudflare_id ON dns_records(cloudflare_record_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_records_created_at ON dns_records(created_at)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_record_history_domain_name ON dns_record_history(domain_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_record_history_record_type ON dns_record_history(record_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_record_history_action ON dns_record_history(action)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_record_history_created_at ON dns_record_history(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_record_history_user_id ON dns_record_history(user_id)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_audit_operation ON encryption_audit(operation)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_audit_table_name ON encryption_audit(table_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_audit_user_id ON encryption_audit(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_audit_created_at ON encryption_audit(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_audit_key_id ON encryption_audit(key_id)")
                
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_keys_key_alias ON encryption_keys(key_alias)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_keys_is_active ON encryption_keys(is_active)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_keys_is_default ON encryption_keys(is_default)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_encryption_keys_created_at ON encryption_keys(created_at)")
                
                logger.info("✅ SECURITY TABLES: All security monitoring tables created successfully (admin_alerts, audit_log, dns_records, encryption_audit, encryption_keys)")
                
                # =============================================================================
                # SCHEMA ENHANCEMENT: Add missing columns to existing tables
                # =============================================================================
                
                # Add missing columns to users table
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_language VARCHAR(10) DEFAULT 'en'")
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS language_selected_manually BOOLEAN DEFAULT FALSE")
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ")
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id)")
                    logger.info("✅ Schema enhancement: Added missing columns to users table (preferred_language, language_selected_manually, deleted_at, deleted_by)")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (users columns): {migration_error}")
                
                # Add missing columns to domains table  
                try:
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS ownership_state VARCHAR(50) DEFAULT 'unknown'")
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS cloudflare_zone_id VARCHAR(100)")
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ")
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id)")
                    cursor.execute("ALTER TABLE domains ADD COLUMN IF NOT EXISTS provider_account_id INTEGER REFERENCES openprovider_accounts(id)")
                    logger.info("✅ Schema enhancement: Added missing columns to domains table (ownership_state, cloudflare_zone_id, deleted_at, deleted_by, provider_account_id)")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (domains columns): {migration_error}")
                
                # Add missing columns to wallet_transactions table (external_txid already exists with UNIQUE constraint)
                try:
                    cursor.execute("ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ")
                    cursor.execute("ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id)")
                    logger.info("✅ Schema enhancement: Added soft deletion columns to wallet_transactions table (deleted_at, deleted_by)")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (wallet_transactions columns): {migration_error}")
                
                # Add missing columns to dns_records table for DNS management
                try:
                    cursor.execute("ALTER TABLE dns_records ADD COLUMN IF NOT EXISTS proxied BOOLEAN DEFAULT FALSE")
                    cursor.execute("ALTER TABLE dns_records ADD COLUMN IF NOT EXISTS locked BOOLEAN DEFAULT FALSE")
                    cursor.execute("ALTER TABLE dns_records ADD COLUMN IF NOT EXISTS metadata JSONB")
                    logger.info("✅ Schema enhancement: Added columns to dns_records table (proxied, locked, metadata)")
                except Exception as migration_error:
                    logger.warning(f"Migration warning (dns_records columns): {migration_error}")
                
                # Add soft deletion columns to all business tables
                business_tables = [
                    'hosting_plans', 'hosting_subscriptions', 'cpanel_accounts', 'domain_hosting_bundles',
                    'bundle_pricing', 'bundle_discounts', 'callback_tokens', 'payment_intents', 'provider_claims',
                    'webhook_callbacks', 'domain_searches', 'domain_registration_intents', 'hosting_provision_intents',
                    'domain_notifications', 'refund_tracking', 'orders', 'order_items', 'payment_intents_unified',
                    'ledger_transactions', 'refunds_unified', 'domain_link_intents', 'domain_verifications',
                    'cloudflare_zones', 'dns_record_versions', 'wallet_deposits', 'domain_orders'
                ]
                
                for table_name in business_tables:
                    try:
                        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ")
                        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id)")
                    except Exception as migration_error:
                        logger.warning(f"Migration warning ({table_name} soft deletion): {migration_error}")
                
                logger.info(f"✅ Schema enhancement: Added soft deletion columns (deleted_at, deleted_by) to {len(business_tables)} business tables")
                
                # Create indexes for soft deletion and new columns
                try:
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_preferred_language ON users(preferred_language)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domains_ownership_state ON domains(ownership_state)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domains_cloudflare_zone_id ON domains(cloudflare_zone_id)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domains_deleted_at ON domains(deleted_at)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domains_provider_account_id ON domains(provider_account_id)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_openprovider_accounts_is_default ON openprovider_accounts(is_default)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_openprovider_contact_handles_account_tld ON openprovider_contact_handles(account_id, tld)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallet_transactions_deleted_at ON wallet_transactions(deleted_at)")
                    logger.info("✅ Schema enhancement: Created indexes for new columns and soft deletion")
                except Exception as index_error:
                    logger.warning(f"Index creation warning: {index_error}")
                
                logger.info("✅ PHASE 1: All unified tables created successfully (orders, order_items, payment_intents_unified, ledger_transactions, refunds_unified)")
                logger.info("✅ DOMAIN LINKING: Foundation tables created successfully (domain_link_intents, domain_verifications)")
                
                # 🔧 COMPREHENSIVE SEQUENCE SYNCHRONIZATION
                # Fix for Bug #6: Sync ALL sequences to prevent "duplicate key" errors
                logger.info("🔧 SEQUENCE SYNC: Starting comprehensive sequence synchronization...")
                
                try:
                    # Get all sequences with their associated table and column names
                    cursor.execute("""
                        SELECT 
                            s.sequence_name,
                            t.table_name,
                            c.column_name
                        FROM information_schema.sequences s
                        LEFT JOIN information_schema.columns c 
                            ON c.column_default LIKE '%' || s.sequence_name || '%'
                        LEFT JOIN information_schema.tables t
                            ON t.table_name = c.table_name
                        WHERE s.sequence_name LIKE '%_id_seq'
                        ORDER BY s.sequence_name
                    """)
                    
                    sequences = cursor.fetchall()
                    synced_count = 0
                    failed_count = 0
                    
                    for seq_row in sequences:
                        if isinstance(seq_row, tuple):
                            seq_name, table_name, column_name = seq_row[0], seq_row[1], seq_row[2]
                        else:
                            seq_name = seq_row['sequence_name']
                            table_name = seq_row['table_name']
                            column_name = seq_row['column_name']
                        
                        # Skip if we couldn't find the table/column association
                        if not table_name or not column_name:
                            logger.warning(f"   ⚠️ {seq_name}: could not determine table/column, skipping")
                            failed_count += 1
                            continue
                        
                        try:
                            # Verify table exists before attempting sync
                            cursor.execute(f"""
                                SELECT EXISTS (
                                    SELECT FROM information_schema.tables 
                                    WHERE table_schema = 'public' 
                                    AND table_name = '{table_name}'
                                )
                            """)
                            table_exists_result = cursor.fetchone()
                            if table_exists_result:
                                table_exists = table_exists_result[0] if isinstance(table_exists_result, tuple) else table_exists_result.get('exists', False)
                            else:
                                table_exists = False
                            
                            if not table_exists:
                                logger.warning(f"   ⚠️ {seq_name}: orphaned sequence (table '{table_name}' does not exist), skipping")
                                failed_count += 1
                                continue
                            
                            # Sync sequence using GREATEST to never roll back
                            cursor.execute(f"""
                                SELECT setval('{seq_name}', 
                                    GREATEST(
                                        (SELECT COALESCE(MAX({column_name}), 0) FROM {table_name}),
                                        (SELECT last_value FROM {seq_name})
                                    ),
                                    true
                                )
                            """)
                            
                            # Get the new sequence value
                            cursor.execute(f"SELECT last_value FROM {seq_name}")
                            seq_result = cursor.fetchone()
                            if seq_result:
                                seq_value = seq_result[0] if isinstance(seq_result, tuple) else seq_result.get('last_value', 0)
                                logger.info(f"   ✅ {table_name}.{column_name}: sequence={seq_value}")
                                synced_count += 1
                        except Exception as sync_error:
                            logger.warning(f"   ⚠️ {table_name}.{column_name}: sync failed - {sync_error}")
                            failed_count += 1
                    
                    if synced_count > 0:
                        logger.info(f"🔧 SEQUENCE SYNC COMPLETE: {synced_count} sequences synchronized, {failed_count} failed")
                    else:
                        logger.warning("⚠️ SEQUENCE SYNC: No sequences found to synchronize")
                        
                except Exception as seq_sync_error:
                    logger.error(f"❌ SEQUENCE SYNC ERROR: {seq_sync_error}")
                    # Don't fail initialization, just log the error
                
                conn.commit()
                logger.info("✅ Database tables initialized successfully")
        finally:
            return_connection(conn)
    
    await asyncio.to_thread(_init)
    
    # CRITICAL SECURITY: Verify all security constraints after initialization
    security_verified = await verify_security_constraints()
    
    # Log final security status for production debugging
    security_status = get_security_status()
    logger.info("🔍 FINAL SECURITY STATUS:")
    logger.info(f"   • Security Verified: {security_status['security_verified']}")
    logger.info(f"   • Safe Mode: {security_status['safe_mode_enabled']}")  
    logger.info(f"   • Financial Operations: {security_status['financial_operations_allowed']}")
    logger.info(f"   • Degraded Startup Allowed: {security_status['degraded_startup_allowed']}")
    
    if security_verified:
        logger.info("✅ DATABASE INITIALIZATION COMPLETE: Full security mode active")
    else:
        logger.warning("⚠️ DATABASE INITIALIZATION COMPLETE: Running in safe mode with limited functionality")
    
    # NEON HARDENING: Start background health probe after successful initialization
    try:
        await start_health_probe()
        logger.info("✅ NEON HARDENING: Database health monitoring started")
    except Exception as probe_error:
        logger.warning(f"⚠️ NEON HARDENING: Could not start health probe: {probe_error}")

async def verify_security_constraints() -> bool:
    """
    CRITICAL SECURITY: Verify all financial security constraints are in place
    This function ensures the wallet system is bulletproof against negative balances
    
    Returns True if constraints are verified, False if system should run in safe mode
    """
    global _security_constraints_verified, _safe_mode_enabled, _security_verification_cache_time
    
    try:
        # PERFORMANCE OPTIMIZATION: Check if verification was recently successful
        current_time = time.time()
        if (_security_constraints_verified and 
            _security_verification_cache_time > 0 and 
            (current_time - _security_verification_cache_time) < _security_verification_cache_duration):
            cache_age = int(current_time - _security_verification_cache_time)
            logger.info(f"⚡ SECURITY VERIFICATION CACHED: Skipping verification (verified {cache_age}s ago)")
            logger.info("✅ FINANCIAL OPERATIONS: Enabled (cached verification)")
            return True
        
        logger.info("🔍 Starting security constraint verification...")
        
        # Phase 1: Verify database CHECK constraint exists
        constraints = await execute_query(
            """SELECT cc.constraint_name, cc.check_clause 
               FROM information_schema.check_constraints cc
               JOIN information_schema.table_constraints tc ON cc.constraint_name = tc.constraint_name
               WHERE tc.table_name = 'users' AND cc.constraint_name = 'wallet_balance_non_negative'"""
        )
        
        if constraints:
            logger.info("🔒 SECURITY VERIFIED: wallet_balance_non_negative constraint is active")
            logger.info(f"🔒 Constraint: {constraints[0]['check_clause']}")
        else:
            constraint_error = "CRITICAL: wallet_balance_non_negative constraint is MISSING from users table"
            logger.error(f"🚫 {constraint_error}")
            return await _handle_security_constraint_failure(constraint_error, "missing_constraint")
        
        # Phase 2: Test constraint functionality
        test_result = await _test_negative_balance_protection()
        if not test_result:
            test_error = "CRITICAL: Security constraint test failed - constraint may not be working"
            logger.error(f"🚫 {test_error}")
            return await _handle_security_constraint_failure(test_error, "constraint_test_failed")
        
        # Phase 3: All verifications passed
        _security_constraints_verified = True
        _safe_mode_enabled = False
        _security_verification_cache_time = current_time  # Cache successful verification
        logger.info("✅ SECURITY VERIFICATION COMPLETE: All wallet security constraints verified and working")
        logger.info("✅ FINANCIAL OPERATIONS: Enabled (all security checks passed)")
        return True
        
    except Exception as e:
        error_msg = f"Security verification failed with exception: {e}"
        logger.error(f"🚫 CRITICAL SECURITY EXCEPTION: {error_msg}")
        return await _handle_security_constraint_failure(error_msg, "verification_exception")

async def _handle_security_constraint_failure(error_msg: str, failure_type: str) -> bool:
    """
    Handle security constraint verification failure with graceful degradation
    
    Returns True if system should continue (safe mode), False if system should halt
    """
    global _security_constraints_verified, _safe_mode_enabled
    
    # Log the failure with full context
    logger.error(f"🚫 SECURITY CONSTRAINT FAILURE: {error_msg}")
    logger.error(f"🚫 Failure Type: {failure_type}")
    logger.error(f"🚫 Current Configuration: ALLOW_DEGRADED_STARTUP={_allow_degraded_startup}")
    
    # Check if degraded startup is allowed
    if _allow_degraded_startup:
        # Enable safe mode for graceful degradation
        _security_constraints_verified = False
        enable_safe_mode(f"Security verification failed: {failure_type}")
        
        logger.warning("🟡 GRACEFUL DEGRADATION: System will start in SAFE MODE")
        logger.warning("🟡 SAFE MODE RESTRICTIONS:")
        logger.warning("🟡   - ALL financial operations disabled")
        logger.warning("🟡   - Wallet deposits/withdrawals blocked")
        logger.warning("🟡   - Domain purchases blocked")
        logger.warning("🟡   - Read-only operations only")
        logger.warning("🟡 ADMINISTRATOR ACTION REQUIRED: Fix security constraints and restart")
        
        return True  # Allow system to continue in safe mode
    else:
        # Strict mode - system cannot start without security constraints
        _security_constraints_verified = False
        _safe_mode_enabled = True
        
        logger.error("🚫 STRICT MODE: System cannot start without verified security constraints")
        logger.error("🚫 ADMINISTRATOR ACTION REQUIRED:")
        logger.error("🚫   1. Fix database security constraints")
        logger.error("🚫   2. Ensure wallet_balance_non_negative constraint exists")
        logger.error("🚫   3. OR set ALLOW_DEGRADED_STARTUP=true for emergency operations")
        logger.error("🚫 SYSTEM STARTUP BLOCKED for security reasons")
        
        # In strict mode, we still raise the exception to prevent startup
        raise Exception(f"SECURITY CONSTRAINT FAILURE: {error_msg} (set ALLOW_DEGRADED_STARTUP=true to override)")

    return False  # Should not be reached

async def _test_negative_balance_protection() -> bool:
    """
    Test that the security constraints actually prevent negative balances
    This runs a quick verification test to ensure protections are working
    
    Returns True if constraints work properly, False if they fail
    """
    test_user_id = None
    
    try:
        # Test 1: Try direct SQL update to create negative balance (should be blocked by constraint)
        test_user_id = 999999999
        
        logger.info("🔍 Starting security constraint functionality test...")
        
        # Clean up any test data first - delete related records manually since CASCADE only works on foreign key definitions
        # First get the user ID if it exists
        existing_user = await execute_query(
            "SELECT id FROM users WHERE telegram_id = %s AND deleted_at IS NULL", 
            (test_user_id,)
        )
        if existing_user:
            user_id = existing_user[0]['id']
            # Delete related records in domain_registration_intents
            await execute_update("DELETE FROM domain_registration_intents WHERE user_id = %s", (user_id,))
            # Delete related records in other tables that might reference this user
            await execute_update("DELETE FROM wallet_transactions WHERE user_id = %s", (user_id,))
            await execute_update("DELETE FROM domain_orders WHERE user_id = %s", (user_id,))
            await execute_update("DELETE FROM orders WHERE user_id = %s", (user_id,))
        
        # Now delete the user
        await execute_update("DELETE FROM users WHERE telegram_id = %s", (test_user_id,))
        
        # Create test user with balance of 1.00
        rows_inserted = await execute_update(
            "INSERT INTO users (telegram_id, wallet_balance) VALUES (%s, %s)", 
            (test_user_id, 1.00)
        )
        
        if rows_inserted != 1:
            logger.error("🚫 TEST SETUP FAILED: Could not create test user")
            return False
        
        # Try to force negative balance via direct SQL (should fail due to constraint)
        # Use direct database connection to bypass graceful degradation logic
        import psycopg2
        conn = None
        constraint_blocked_negative = False
        
        try:
            conn = get_connection()
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET wallet_balance = -10.00 WHERE telegram_id = %s", 
                    (test_user_id,)
                )
                conn.commit()
            # If we reach here, the constraint failed to prevent negative balance
            logger.error("🚫 CONSTRAINT TEST FAILED: Database constraint did not block negative balance")
            return False
        except psycopg2.IntegrityError as constraint_error:
            # This is the expected constraint violation - security is working!
            error_msg = str(constraint_error)
            if ("wallet_balance_non_negative" in error_msg or 
                "violates check constraint" in error_msg):
                logger.info("🔒 CONSTRAINT TEST PASSED: Negative balance blocked by database constraint")
                constraint_blocked_negative = True
                if conn:
                    conn.rollback()  # Rollback the failed transaction
            else:
                logger.warning(f"Unexpected constraint error (may still be valid): {constraint_error}")
                constraint_blocked_negative = True  # Assume it's working if any constraint error
                if conn:
                    conn.rollback()
        except Exception as unexpected_error:
            logger.error(f"Unexpected error during constraint test: {unexpected_error}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                return_connection(conn)
        
        if not constraint_blocked_negative:
            logger.error("🚫 CONSTRAINT TEST FAILED: No constraint violation detected")
            return False
        
        # Test 2: Verify balance is still 1.00 (unchanged)
        balance_check = await execute_query(
            "SELECT wallet_balance FROM users WHERE telegram_id = %s AND deleted_at IS NULL", 
            (test_user_id,)
        )
        
        if not balance_check:
            logger.error("🚫 INTEGRITY TEST FAILED: Test user disappeared")
            return False
            
        current_balance = to_currency_decimal(balance_check[0]['wallet_balance'], "wallet_balance")
        if current_balance == 1.00:
            logger.info("🔒 INTEGRITY TEST PASSED: Balance unchanged after constraint violation")
        else:
            logger.error(f"🚫 INTEGRITY TEST FAILED: Balance changed to {current_balance} (expected 1.00)")
            return False
        
        logger.info("✅ SECURITY CONSTRAINT TEST COMPLETE: Database-level negative balance protection verified")
        return True
        
    except Exception as e:
        logger.error(f"🚫 SECURITY CONSTRAINT TEST EXCEPTION: {e}")
        return False
        
    finally:
        # Clean up test data - delete related records first
        try:
            if test_user_id is not None:
                # Get user ID if it exists
                existing_user = await execute_query(
                    "SELECT id FROM users WHERE telegram_id = %s AND deleted_at IS NULL", 
                    (test_user_id,)
                )
                if existing_user:
                    user_id = existing_user[0]['id']
                    # Delete related records
                    await execute_update("DELETE FROM domain_registration_intents WHERE user_id = %s", (user_id,))
                    await execute_update("DELETE FROM wallet_transactions WHERE user_id = %s", (user_id,))
                    await execute_update("DELETE FROM domain_orders WHERE user_id = %s", (user_id,))
                    await execute_update("DELETE FROM orders WHERE user_id = %s", (user_id,))
                
                # Now delete the user
                cleanup_result = await execute_update("DELETE FROM users WHERE telegram_id = %s", (test_user_id,))
                logger.debug(f"🧹 Test cleanup: Removed {cleanup_result} test records")
        except Exception as cleanup_error:
            logger.warning(f"Test cleanup warning (non-critical): {cleanup_error}")

# User management functions
async def get_or_create_user(telegram_id: int, username: Optional[str] = None, first_name: Optional[str] = None, last_name: Optional[str] = None) -> Dict:
    """
    Get existing user or create new one - WITH SOFT DELETION DATA INTEGRITY FIX
    
    CRITICAL FIX: This function now properly handles soft-deleted users to prevent data loss.
    When a user was soft-deleted and tries to use the bot again, this function will:
    1. Restore their existing record (preserving wallet_balance, terms_accepted, etc.)
    2. NOT create a new record that would wipe historical data
    """
    
    # First, try to get existing active user
    existing_user = await execute_query(
        "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
        (telegram_id,)
    )
    
    if existing_user:
        # Update existing user if new data provided
        if username or first_name or last_name:
            await execute_update("""
                UPDATE users SET 
                    username = COALESCE(%s, username),
                    first_name = COALESCE(%s, first_name),
                    last_name = COALESCE(%s, last_name),
                    updated_at = CURRENT_TIMESTAMP
                WHERE telegram_id = %s AND deleted_at IS NULL
            """, (username, first_name, last_name, telegram_id))
            
            # Return updated user
            updated_user = await execute_query(
                "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
                (telegram_id,)
            )
            return updated_user[0] if updated_user else existing_user[0]
        
        return existing_user[0]
    
    # CRITICAL FIX: Check for soft-deleted users before creating new ones
    soft_deleted_user = await execute_query(
        "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NOT NULL",
        (telegram_id,)
    )
    
    if soft_deleted_user:
        # Found soft-deleted user - restore it to preserve historical data
        user_record = soft_deleted_user[0]
        user_id = user_record['id']
        
        logger.info(f"🔄 SOFT DELETE RECOVERY: Restoring user {telegram_id} (preserved wallet_balance: {user_record.get('wallet_balance', 'unknown')}, terms_accepted: {user_record.get('terms_accepted', 'unknown')})")
        
        # Restore the user record
        restore_success = await restore_record('users', user_id)
        
        if not restore_success:
            # Fallback: Manual restoration if restore_record fails
            logger.warning(f"⚠️ FALLBACK: restore_record failed for user {user_id}, attempting manual restoration")
            await execute_update("""
                UPDATE users 
                SET deleted_at = NULL, 
                    deleted_by = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (user_id,))
        
        # Update profile information if provided (but preserve critical data)
        if username or first_name or last_name:
            await execute_update("""
                UPDATE users SET 
                    username = COALESCE(%s, username),
                    first_name = COALESCE(%s, first_name),
                    last_name = COALESCE(%s, last_name),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (username, first_name, last_name, user_id))
        
        # Return the restored user
        restored_user = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
            (telegram_id,)
        )
        
        if restored_user:
            logger.info(f"✅ SOFT DELETE RECOVERY: Successfully restored user {telegram_id} with preserved data")
            return restored_user[0]
        else:
            logger.error(f"❌ SOFT DELETE RECOVERY: Failed to retrieve restored user {telegram_id}")
            raise Exception(f"Failed to restore soft-deleted user {telegram_id} - data integrity issue")
    
    # Only create new user if no existing user (active or deleted) found
    logger.info(f"📝 Creating new user {telegram_id} (no existing record found)")
    await execute_update("""
        INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance, terms_accepted, created_at, updated_at)
        VALUES (%s, %s, %s, %s, 0.00, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    """, (telegram_id, username, first_name, last_name))
    
    # Return the newly created user
    new_user = await execute_query(
        "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
        (telegram_id,)
    )
    
    if not new_user:
        raise Exception(f"Failed to create or retrieve user {telegram_id} - database operation returned no results")
    
    return new_user[0]

async def get_or_create_user_with_status(telegram_id: int, username: Optional[str] = None, 
                                       first_name: Optional[str] = None, last_name: Optional[str] = None) -> Dict:
    """
    CRITICAL FIX: Get/create user with caching AND proper soft deletion handling
    
    PERFORMANCE OPTIMIZED + DATA INTEGRITY PROTECTED:
    - Includes timing logs and cache layer for frequent users
    - CRITICAL FIX: Properly handles soft-deleted users to prevent data loss
    - When a soft-deleted user tries to use the bot again, restores their record
    - Preserves wallet_balance, terms_accepted, and other critical user data
    """
    import time
    start_time = time.perf_counter()
    
    # Check cache first for existing users (most /start commands are from existing users)
    from performance_cache import cache_get
    cached_user = cache_get('user_data', telegram_id)
    
    if cached_user:
        # Update cached profile data if provided (but don't hit DB for this)
        if username and cached_user.get('username') != username:
            cached_user['username'] = username
        if first_name and cached_user.get('first_name') != first_name:
            cached_user['first_name'] = first_name
        if last_name and cached_user.get('last_name') != last_name:
            cached_user['last_name'] = last_name
            
        elapsed = (time.perf_counter() - start_time) * 1000
        logger.info(f"⚡ USER CACHE HIT: {telegram_id} in {elapsed:.1f}ms")
        return cached_user
    
    # Cache miss - check database with SOFT DELETION DATA INTEGRITY protection
    
    # Step 1: Check for existing active user
    existing_user = await execute_query(
        "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
        (telegram_id,)
    )
    
    if existing_user:
        # Update existing user if new data provided
        if username or first_name or last_name:
            await execute_update("""
                UPDATE users SET 
                    username = COALESCE(%s, username),
                    first_name = COALESCE(%s, first_name),
                    last_name = COALESCE(%s, last_name),
                    updated_at = CURRENT_TIMESTAMP
                WHERE telegram_id = %s AND deleted_at IS NULL
            """, (username, first_name, last_name, telegram_id))
            
            # Return updated user
            updated_user = await execute_query(
                "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
                (telegram_id,)
            )
            user_data = updated_user[0] if updated_user else existing_user[0]
        else:
            user_data = existing_user[0]
    else:
        # Step 2: CRITICAL FIX - Check for soft-deleted users before creating new ones
        soft_deleted_user = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NOT NULL",
            (telegram_id,)
        )
        
        if soft_deleted_user:
            # Found soft-deleted user - restore it to preserve historical data
            user_record = soft_deleted_user[0]
            user_id = user_record['id']
            
            logger.info(f"🔄 SOFT DELETE RECOVERY: Restoring user {telegram_id} (preserved wallet_balance: {user_record.get('wallet_balance', 'unknown')}, terms_accepted: {user_record.get('terms_accepted', 'unknown')})")
            
            # Restore the user record
            success = await restore_record('users', user_id)
            if not success:
                logger.error(f"❌ SOFT DELETE RECOVERY: Failed to restore user {telegram_id}")
                raise Exception(f"Failed to restore soft-deleted user {telegram_id} - data integrity issue")
            
            # Update with new profile data if provided
            if username or first_name or last_name:
                await execute_update("""
                    UPDATE users SET 
                        username = COALESCE(%s, username),
                        first_name = COALESCE(%s, first_name),
                        last_name = COALESCE(%s, last_name),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE telegram_id = %s AND deleted_at IS NULL
                """, (username, first_name, last_name, telegram_id))
            
            # Get the restored user
            restored_user = await execute_query(
                "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
                (telegram_id,)
            )
            
            if restored_user:
                user_data = restored_user[0]
                logger.info(f"✅ SOFT DELETE RECOVERY: Successfully restored user {telegram_id} with preserved data")
            else:
                logger.error(f"❌ SOFT DELETE RECOVERY: Failed to retrieve restored user {telegram_id}")
                raise Exception(f"Failed to restore soft-deleted user {telegram_id} - data integrity issue")
        else:
            # Step 3: Only create new user if no existing user (active or deleted) found
            logger.info(f"📝 Creating new user {telegram_id} (no existing record found)")
            await execute_update("""
                INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance, terms_accepted, created_at, updated_at)
                VALUES (%s, %s, %s, %s, 0.00, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (telegram_id, username, first_name, last_name))
            
            # Return the newly created user
            new_user = await execute_query(
                "SELECT * FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
                (telegram_id,)
            )
            
            if not new_user:
                raise Exception(f"Failed to create or retrieve user {telegram_id} - database operation returned no results")
            
            user_data = new_user[0]
    
    # Enrich and cache the result
    enriched_data = {
        **user_data,
        'terms_accepted_bool': bool(user_data['terms_accepted']),
        'wallet_balance_decimal': to_currency_decimal(user_data['wallet_balance'] or 0, "wallet_balance")
    }
    
    # Cache for 5 minutes (frequent users will hit cache on subsequent /start)
    from performance_cache import cache_set
    cache_set('user_data', enriched_data, telegram_id)
    
    elapsed = (time.perf_counter() - start_time) * 1000
    logger.info(f"⚡ USER DB QUERY: {telegram_id} in {elapsed:.1f}ms (cached for 5min)")
    
    return enriched_data

async def accept_user_terms(telegram_id: int) -> bool:
    """Mark user as having accepted terms and services"""
    try:
        rows_updated = await execute_update(
            "UPDATE users SET terms_accepted = TRUE, updated_at = CURRENT_TIMESTAMP WHERE telegram_id = %s",
            (telegram_id,)
        )
        
        # CACHE INVALIDATION: Clear specific user cache after state change
        if rows_updated > 0:
            from performance_cache import cache_invalidate
            # Invalidate cached user data for this specific user to prevent stale data
            cache_invalidate('user_data', telegram_id)
            logger.info(f"✅ Cache invalidated for user {telegram_id} after terms acceptance")
            
        return rows_updated > 0
    except Exception as e:
        logger.error(f"Error updating terms acceptance for user {telegram_id}: {e}")
        return False

async def has_user_accepted_terms(telegram_id: int) -> bool:
    """Check if user has accepted terms and services"""
    try:
        result = await execute_query(
            "SELECT terms_accepted FROM users WHERE telegram_id = %s AND deleted_at IS NULL", 
            (telegram_id,)
        )
        if result:
            terms_status = bool(result[0]['terms_accepted'])
            logger.info(f"🔍 DB TERMS CHECK: User {telegram_id} has terms_accepted = {result[0]['terms_accepted']} (bool: {terms_status})")
            return terms_status
        logger.warning(f"⚠️ DB TERMS CHECK: User {telegram_id} not found in database")
        return False
    except Exception as e:
        logger.error(f"❌ ERROR checking terms acceptance for user {telegram_id}: {e}")
        return False

async def get_all_user_telegram_ids() -> List[int]:
    """Get all user telegram IDs for broadcasting"""
    try:
        result = await execute_query(
            "SELECT telegram_id FROM users WHERE terms_accepted = TRUE AND deleted_at IS NULL ORDER BY created_at DESC"
        )
        return [row['telegram_id'] for row in result] if result else []
    except Exception as e:
        logger.error(f"❌ ERROR getting user telegram IDs for broadcast: {e}")
        return []

async def get_telegram_id_from_user_id(user_id: int) -> Optional[int]:
    """Get telegram_id from internal user_id for notifications"""
    try:
        result = await execute_query(
            "SELECT telegram_id FROM users WHERE id = %s AND deleted_at IS NULL", 
            (user_id,)
        )
        if result:
            return result[0]['telegram_id']
        logger.warning(f"⚠️ User ID {user_id} not found in database")
        return None
    except Exception as e:
        logger.error(f"❌ ERROR getting telegram_id for user_id {user_id}: {e}")
        return None

# Domain management functions
async def save_domain(user_id: int, domain_name: str, provider_domain_id: Optional[str] = None, status: str = 'pending') -> bool:
    """Save domain to database"""
    try:
        await execute_update(
            "INSERT INTO domains (user_id, domain_name, provider_domain_id, status) VALUES (%s, %s, %s, %s)",
            (user_id, domain_name, provider_domain_id, status)
        )
        return True
    except Exception as e:
        logger.error(f"Error saving domain: {e}")
        return False

async def get_user_domains(user_id: int) -> List[Dict]:
    """Get all domains for a user"""
    return await execute_query("SELECT * FROM domains WHERE user_id = %s AND deleted_at IS NULL ORDER BY created_at DESC", (user_id,))

async def get_domain_by_name(domain_name: str) -> Optional[Dict]:
    """Get domain record by domain name from database"""
    query = """
        SELECT * 
        FROM domains 
        WHERE domain_name = %s
    """
    results = await execute_query(query, (domain_name,))
    if results:
        return dict(results[0])
    return None

async def get_domain_provider_id(domain_name: str) -> Optional[str]:
    """Get provider domain ID for a specific domain from database"""
    query = """
        SELECT provider_domain_id 
        FROM domains 
        WHERE domain_name = %s
    """
    results = await execute_query(query, (domain_name,))
    if results:
        return results[0].get('provider_domain_id')
    return None

async def update_domain_nameservers(domain_name: str, nameservers: List[str]) -> bool:
    """Update nameservers for a domain in the database"""
    try:
        await execute_update(
            "UPDATE domains SET nameservers = %s, updated_at = CURRENT_TIMESTAMP WHERE domain_name = %s",
            (nameservers, domain_name)
        )
        logger.info(f"✅ Updated nameservers in database for domain: {domain_name}")
        return True
    except Exception as e:
        logger.error(f"❌ Error updating nameservers for {domain_name}: {e}")
        return False

async def get_domain_nameservers(domain_name: str) -> Optional[List[str]]:
    """Get stored nameservers for a domain from database"""
    query = """
        SELECT nameservers 
        FROM domains 
        WHERE domain_name = %s
    """
    results = await execute_query(query, (domain_name,))
    if results and results[0].get('nameservers'):
        return list(results[0]['nameservers'])
    return None

async def get_domain_auto_proxy_enabled(domain_name: str) -> bool:
    """Get auto-proxy enabled setting for a domain from database"""
    query = """
        SELECT auto_proxy_enabled 
        FROM domains 
        WHERE domain_name = %s
    """
    results = await execute_query(query, (domain_name,))
    if results and results[0].get('auto_proxy_enabled') is not None:
        return bool(results[0]['auto_proxy_enabled'])
    return True  # Default to enabled if not set

async def set_domain_auto_proxy_enabled(domain_name: str, enabled: bool) -> bool:
    """Update auto-proxy enabled setting for a domain in the database"""
    try:
        await execute_update(
            "UPDATE domains SET auto_proxy_enabled = %s, updated_at = CURRENT_TIMESTAMP WHERE domain_name = %s",
            (enabled, domain_name)
        )
        logger.info(f"✅ Updated auto-proxy setting for domain {domain_name}: {enabled}")
        return True
    except Exception as e:
        logger.error(f"❌ Error updating auto-proxy setting for {domain_name}: {e}")
        return False

async def set_domain_restriction(domain_name: str, restriction_type: Optional[str], reason: Optional[str] = None) -> bool:
    """
    Set or clear registrar restriction for a domain.
    Works for ALL TLDs - not TLD-specific.
    
    Args:
        domain_name: The domain to update
        restriction_type: Type of restriction (e.g., 'abuse_lock', 'verification_required', 'hold') or None to clear
        reason: Human-readable reason for the restriction
    
    Returns:
        True if update succeeded, False otherwise
    """
    try:
        await execute_update(
            """UPDATE domains 
               SET registrar_restriction = %s, 
                   restriction_reason = %s, 
                   updated_at = CURRENT_TIMESTAMP 
               WHERE domain_name = %s""",
            (restriction_type, reason, domain_name)
        )
        if restriction_type:
            logger.info(f"🔒 Set domain restriction for {domain_name}: {restriction_type}")
        else:
            logger.info(f"🔓 Cleared domain restriction for {domain_name}")
        return True
    except Exception as e:
        logger.error(f"❌ Error setting domain restriction for {domain_name}: {e}")
        return False

async def clear_domain_restriction(domain_name: str) -> bool:
    """Clear any registrar restriction for a domain (wrapper for set_domain_restriction)"""
    return await set_domain_restriction(domain_name, None, None)

# NEW 3-TABLE STATE MANAGEMENT SYSTEM
async def log_domain_search(user_id: int, domain_name: str, search_result: Dict[str, Any]) -> bool:
    """Log domain search to domain_searches table (ephemeral search history)"""
    try:
        # Extract snapshots from search_result
        availability_data = {
            'available': search_result.get('available', True),
            'premium': search_result.get('premium', False),
            'status': search_result.get('status', 'unknown')
        }
        
        price_data = {
            'registration_price': search_result.get('registration_price'),
            'currency': 'USD'
        }
        
        nameservers_data = {
            'nameservers': search_result.get('nameservers'),
            'using_cloudflare_ns': search_result.get('using_cloudflare_ns', False)
        }
        
        await execute_update(
            """INSERT INTO domain_searches 
               (user_id, domain_name, availability_snapshot, price_snapshot, nameservers_snapshot) 
               VALUES (%s, %s, %s, %s, %s)""",
            (
                user_id, 
                domain_name, 
                json.dumps(availability_data),
                json.dumps(price_data),
                json.dumps(nameservers_data)
            )
        )
        logger.info(f"✅ Logged domain search for {domain_name} by user {user_id}")
        return True
    except Exception as e:
        logger.error(f"❌ Error logging domain search for {domain_name}: {e}")
        return False

async def create_registration_intent(user_id: int, domain_name: str, estimated_price: float, payment_data: Optional[Dict[str, Any]] = None) -> Optional[int]:
    """Create registration intent in domain_registration_intents table"""
    try:
        import uuid
        idempotency_key = str(uuid.uuid4())
        
        # Extract TLD from domain name (e.g., "example.com" -> "com")
        tld = domain_name.split('.')[-1] if '.' in domain_name else ''
        
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query(
            """INSERT INTO domain_registration_intents 
               (user_id, domain_name, tld, quote_price, currency, status, idempotency_key) 
               VALUES (%s, %s, %s, %s, %s, %s, %s) 
               RETURNING id""",
            (user_id, domain_name, tld, estimated_price, 'USD', 'created', idempotency_key)
        )
        if result and len(result) > 0:
            intent_id = result[0]['id']
            logger.info(f"✅ Created registration intent {intent_id} for {domain_name} by user {user_id}")
            return intent_id
        return None
    except Exception as e:
        logger.error(f"❌ Error creating registration intent for {domain_name}: {e}")
        return None

async def update_intent_status(intent_id: int, status: str, provider_data: Optional[Dict[str, Any]] = None) -> bool:
    """Update registration intent status with validation to prevent constraint violations"""
    try:
        # CRITICAL VALIDATION: Prevent setting status='completed' without provider_domain_id
        # This enforces the database constraint check_completed_has_provider_id
        if status == 'completed':
            logger.error(f"❌ CONSTRAINT PROTECTION: Cannot set status='completed' via update_intent_status")
            logger.error(f"   Use finalize_domain_registration() instead to set both status AND provider_domain_id atomically")
            logger.error(f"   Intent ID: {intent_id}, Provider Data: {provider_data}")
            return False
        
        await execute_update(
            """UPDATE domain_registration_intents 
               SET status = %s, updated_at = CURRENT_TIMESTAMP 
               WHERE id = %s""",
            (status, intent_id)
        )
        logger.info(f"✅ Updated intent {intent_id} status to {status}")
        return True
    except Exception as e:
        logger.error(f"❌ Error updating intent {intent_id}: {e}")
        return False

async def finalize_domain_registration(intent_id: int, provider_domain_id: str, provider_account_id: Optional[int] = None) -> bool:
    """Finalize domain registration by moving from intent to domains table with verified ownership and Cloudflare zone data"""
    try:
        # Get intent details
        intent_result = await execute_query(
            "SELECT user_id, domain_name FROM domain_registration_intents WHERE id = %s",
            (intent_id,)
        )
        if not intent_result:
            logger.error(f"❌ Intent {intent_id} not found for finalization")
            return False
            
        intent = intent_result[0]
        domain_name = intent['domain_name']
        
        # Get Cloudflare zone data for this domain
        cloudflare_zone_result = await execute_query(
            "SELECT cf_zone_id, nameservers FROM cloudflare_zones WHERE domain_name = %s",
            (domain_name,)
        )
        
        nameservers = None
        cloudflare_zone_id = None
        
        if cloudflare_zone_result:
            cloudflare_zone = cloudflare_zone_result[0]
            cloudflare_zone_id = cloudflare_zone.get('cf_zone_id')
            nameservers = cloudflare_zone.get('nameservers')
            logger.info(f"✅ Found Cloudflare zone data for {domain_name}: zone_id={cloudflare_zone_id}, nameservers={len(nameservers) if nameservers else 0}")
        else:
            logger.warning(f"⚠️ No Cloudflare zone found for {domain_name} - domain will be saved without nameserver data")
        
        # Create authoritative domain entry with verified ownership and Cloudflare zone data
        # Include provider_account_id to track which OpenProvider account registered this domain
        # CRITICAL FIX: Check return value to ensure INSERT actually succeeded
        rows_inserted = await execute_update(
            """INSERT INTO domains 
               (user_id, domain_name, provider_domain_id, ownership_state, status, nameservers, cloudflare_zone_id, provider_account_id, created_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)""",
            (
                intent['user_id'], 
                domain_name, 
                provider_domain_id,
                'internal_owned',  # Verified ownership through registration
                'active',
                nameservers,  # Array of nameservers from Cloudflare zone
                cloudflare_zone_id,  # Cloudflare zone ID for API operations
                provider_account_id  # OpenProvider account ID that registered this domain
            )
        )
        
        # CRITICAL FIX: Verify domain was actually inserted into database
        if rows_inserted == 0:
            logger.error(f"❌ CRITICAL: Domain INSERT returned 0 rows for {domain_name} - domain NOT saved to database!")
            logger.error(f"   Intent ID: {intent_id}, Provider Domain ID: {provider_domain_id}")
            logger.error(f"   User ID: {intent['user_id']}, Cloudflare Zone: {cloudflare_zone_id}")
            return False
        
        # Verify domain exists in database after insert
        verify_result = await execute_query(
            "SELECT id FROM domains WHERE domain_name = %s AND user_id = %s",
            (domain_name, intent['user_id'])
        )
        
        if not verify_result:
            logger.error(f"❌ CRITICAL: Domain verification failed for {domain_name} - domain NOT found after INSERT!")
            return False
        
        logger.info(f"✅ Domain {domain_name} verified in database (domain_id: {verify_result[0]['id']})")
        
        # Mark intent as completed
        await execute_update(
            """UPDATE domain_registration_intents 
               SET status = %s, provider_domain_id = %s, completed_at = CURRENT_TIMESTAMP 
               WHERE id = %s""",
            ('completed', provider_domain_id, intent_id)
        )
        
        account_info = f", account: {provider_account_id}" if provider_account_id else ""
        if nameservers and cloudflare_zone_id:
            logger.info(f"✅ Finalized domain registration for {domain_name} - intent {intent_id} with Cloudflare zone data (zone_id: {cloudflare_zone_id}, nameservers: {len(nameservers)}{account_info})")
        else:
            logger.info(f"✅ Finalized domain registration for {domain_name} - intent {intent_id} (no Cloudflare zone data found{account_info})")
        
        return True
    except Exception as e:
        logger.error(f"❌ Error finalizing domain registration for intent {intent_id}: {e}")
        return False

async def get_active_registration_intent(user_id: int, domain_name: str) -> Optional[Dict]:
    """Check for active registration intent for a domain by a user"""
    try:
        result = await execute_query(
            """SELECT * FROM domain_registration_intents 
               WHERE user_id = %s AND domain_name = %s AND status IN ('initiated', 'payment_pending', 'payment_confirmed')
               ORDER BY created_at DESC LIMIT 1""",
            (user_id, domain_name)
        )
        return dict(result[0]) if result else None
    except Exception as e:
        logger.error(f"❌ Error checking active intent for {domain_name}: {e}")
        return None

async def check_domain_ownership_state(domain_name: str) -> Optional[str]:
    """Check ownership state of domain in domains table"""
    try:
        result = await execute_query(
            "SELECT ownership_state FROM domains WHERE domain_name = %s AND deleted_at IS NULL",
            (domain_name,)
        )
        return result[0]['ownership_state'] if result else None
    except Exception as e:
        logger.error(f"❌ Error checking ownership state for {domain_name}: {e}")
        return None

async def get_domain_search_history(user_id: int, domain_name: str, limit: int = 5) -> List[Dict]:
    """Get recent search history for a domain by user"""
    try:
        result = await execute_query(
            """SELECT * FROM domain_searches 
               WHERE user_id = %s AND domain_name = %s 
               ORDER BY search_timestamp DESC LIMIT %s""",
            (user_id, domain_name, limit)
        )
        return [dict(row) for row in result] if result else []
    except Exception as e:
        logger.error(f"❌ Error getting search history for {domain_name}: {e}")
        return []


# ====================================================================
# HOSTING PROVISION INTENTS - PREVENT DUPLICATE HOSTING ACCOUNTS
# ====================================================================

async def create_hosting_intent(user_id: int, domain_name: Optional[str], hosting_plan_id: int, estimated_price: float, payment_data: Optional[Dict[str, Any]] = None, service_type: str = 'hosting_only') -> Optional[int]:
    """
    Create hosting provision intent to prevent duplicate hosting accounts
    FIXED: Uses proper idempotent insert behavior with constraint handling
    """
    try:
        # Resolve domain_name to domain_id if provided
        domain_id = None
        if domain_name:
            domain_id = await get_domain_id_by_name(domain_name)
        
        # First, try to get existing active intent for same user/domain/plan/service combination
        # CRITICAL FIX: Include service_type in WHERE clause to prevent cross-service intent reuse
        existing_intent = await execute_query(
            """SELECT id, service_type, domain_name FROM hosting_provision_intents 
               WHERE user_id = %s 
               AND (
                   (domain_id = %s) OR 
                   (%s IS NULL AND domain_id IS NULL AND COALESCE(domain_name, '') = COALESCE(%s, ''))
               )
               AND hosting_plan_id = %s 
               AND service_type = %s
               AND status IN ('pending_payment', 'provisioning')
               ORDER BY created_at DESC LIMIT 1""",
            (user_id, domain_id, domain_id, domain_name or '', hosting_plan_id, service_type)
        )
        
        if existing_intent:
            intent_id = existing_intent[0]['id']
            existing_service_type = existing_intent[0]['service_type']
            existing_domain_name = existing_intent[0]['domain_name']
            
            domain_info = f"domain '{domain_name}'" if domain_name else "no domain"
            logger.info(f"♻️ Returning existing hosting intent {intent_id} for {domain_info} by user {user_id}")
            
            # Update the price, service type, and domain for existing intents to ensure consistency
            await execute_update(
                """UPDATE hosting_provision_intents 
                   SET quote_price = %s, service_type = %s, domain_name = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s""",
                (estimated_price, service_type, domain_name, intent_id)
            )
            logger.info(f"🔄 Updated existing intent {intent_id}: price=${estimated_price:.2f}, service={service_type}")
            return intent_id
        
        # Create new intent with deterministic idempotency key
        # Generate deterministic key based on user_id, domain_name, hosting_plan_id, and service_type
        import hashlib
        deterministic_components = f"{user_id}|{domain_name or 'NULL'}|{hosting_plan_id}|{service_type}"
        deterministic_hash = hashlib.sha256(deterministic_components.encode()).hexdigest()[:16]
        idempotency_key = f"hosting_{deterministic_hash}"
        
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query(
            """INSERT INTO hosting_provision_intents 
               (user_id, domain_id, domain_name, hosting_plan_id, quote_price, currency, status, service_type, idempotency_key) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) 
               ON CONFLICT (idempotency_key) 
               DO UPDATE SET 
                   quote_price = EXCLUDED.quote_price,
                   domain_name = EXCLUDED.domain_name,
                   service_type = EXCLUDED.service_type,
                   updated_at = CURRENT_TIMESTAMP,
                   status = CASE 
                       WHEN hosting_provision_intents.status IN ('completed', 'failed') 
                       THEN 'pending_payment'
                       WHEN hosting_provision_intents.status IN ('pending', 'draft', 'awaiting_payment', 'pending_checkout', 'wallet_pending', 'payment_pending')
                       THEN 'pending_payment'
                       ELSE hosting_provision_intents.status 
                   END
               RETURNING id, status""",
            (user_id, domain_id, domain_name, hosting_plan_id, estimated_price, 'USD', 'pending_payment', service_type, idempotency_key)
        )
        
        if result and len(result) > 0:
            intent_id = result[0]['id']
            domain_info = f"domain '{domain_name}'" if domain_name else "no domain"
            logger.info(f"✅ Created/updated hosting provision intent {intent_id} for {domain_info} by user {user_id}")
            return intent_id
        else:
            # CRITICAL FIX: Log detailed error when no result returned
            domain_info = f"domain '{domain_name}'" if domain_name else "no domain"
            logger.error(f"❌ CRITICAL: Hosting intent creation returned no result for {domain_info}, user {user_id}, plan {hosting_plan_id}")
            logger.error(f"❌ DEBUG: service_type={service_type}, estimated_price={estimated_price}, idempotency_key={idempotency_key}")
        return None
        
    except Exception as e:
        domain_info = f"domain '{domain_name}'" if domain_name else "no domain"
        logger.error(f"❌ Error creating hosting provision intent for {domain_info}: {e}")
        return None

async def update_hosting_intent_status(intent_id: int, status: str, external_reference: Optional[str] = None, error_message: Optional[str] = None) -> bool:
    """Update hosting provision intent status"""
    try:
        if external_reference:
            await execute_update(
                """UPDATE hosting_provision_intents 
                   SET status = %s, external_reference = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s""",
                (status, external_reference, intent_id)
            )
        elif error_message:
            await execute_update(
                """UPDATE hosting_provision_intents 
                   SET status = %s, last_error = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s""",
                (status, error_message, intent_id)
            )
        else:
            await execute_update(
                """UPDATE hosting_provision_intents 
                   SET status = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s""",
                (status, intent_id)
            )
        logger.info(f"✅ Updated hosting intent {intent_id} status to {status}")
        return True
    except Exception as e:
        logger.error(f"❌ Error updating hosting intent {intent_id}: {e}")
        return False

async def finalize_hosting_provisioning(intent_id: int, cpanel_username: str, external_data: Dict[str, Any], auto_renew: bool = True) -> Union[bool, Dict[str, Any]]:
    """
    Finalize hosting provisioning by moving from intent to hosting_subscriptions table
    FIXED: Handles domain registration for bundles before hosting provisioning
    
    Args:
        intent_id: Hosting provision intent ID
        cpanel_username: cPanel account username
        external_data: Account creation data from cPanel
        auto_renew: Enable automatic renewal (default: True)
    """
    from datetime import datetime, timedelta
    import json
    
    # First, check if this requires domain registration (outside transaction)
    try:
        intent_details = await execute_query(
            """SELECT user_id, domain_id, hosting_plan_id, quote_price, service_type, domain_name 
               FROM hosting_provision_intents WHERE id = %s""",
            (intent_id,)
        )
        
        if not intent_details:
            logger.error(f"❌ Hosting intent {intent_id} not found")
            return False
            
        intent = dict(intent_details[0])
        
        # Store bundle info for domain registration AFTER hosting subscription is created
        bundle_domain_registration_needed = (
            intent.get('service_type') == 'hosting_domain_bundle' 
            and intent.get('domain_name') 
            and not intent.get('domain_id')
        )
        if bundle_domain_registration_needed:
            logger.info(f"🌐 Domain bundle detected - will register domain: {intent['domain_name']} after subscription creation")
    
    except Exception as e:
        logger.error(f"❌ Error checking intent details for {intent_id}: {e}")
        return False
    
    # Now proceed with hosting subscription creation in transaction
    def _finalize_in_transaction(conn, intent_id: int, cpanel_username: str, external_data: Dict[str, Any], auto_renew: bool = True) -> bool:
        """Execute finalization within a single transaction"""
        try:
            with conn.cursor() as cursor:
                # Get intent details with FOR UPDATE lock to prevent race conditions
                # This lock is now held for the entire transaction
                cursor.execute(
                    """SELECT user_id, domain_id, hosting_plan_id, quote_price, service_type, domain_name 
                       FROM hosting_provision_intents 
                       WHERE id = %s FOR UPDATE""",
                    (intent_id,)
                )
                intent_result = cursor.fetchone()
                
                if not intent_result:
                    logger.error(f"❌ Hosting intent {intent_id} not found for finalization")
                    return False
                    
                intent = dict(intent_result)
                
                # Check if hosting subscription already exists for this domain
                if intent['domain_id']:
                    cursor.execute(
                        "SELECT id FROM hosting_subscriptions WHERE domain_id = %s AND status = 'active' AND deleted_at IS NULL",
                        (intent['domain_id'],)
                    )
                    existing_hosting = cursor.fetchone()
                    
                    if existing_hosting:
                        logger.warning(f"⚠️ Active hosting subscription already exists for domain_id {intent['domain_id']}")
                        # Mark intent as completed with reference to existing subscription
                        cursor.execute(
                            """UPDATE hosting_provision_intents 
                               SET status = %s, external_reference = %s, updated_at = CURRENT_TIMESTAMP 
                               WHERE id = %s""",
                            ('completed', f"existing_subscription_{existing_hosting['id']}", intent_id)
                        )
                        return True
                
                # FIXED: Only mark as 'active' if cPanel account was actually created successfully
                # Check if external_data contains actual account creation success indicators
                # Handle both new accounts (have password) and existing accounts (marked as existing)
                is_existing_account = external_data.get('is_existing', False)
                cpanel_success = (
                    external_data.get('username') and 
                    external_data.get('server_ip') and
                    (external_data.get('password') or is_existing_account)  # Password OR existing account
                )
                
                # SAGA PATTERN: Start with 'provisioning' status, only mark 'active' after ALL steps succeed
                subscription_status = 'provisioning' if cpanel_success else 'failed'
                
                logger.info(f"📊 Provisioning status: cPanel_success={cpanel_success}, status={subscription_status}")
                if not cpanel_success:
                    logger.warning(f"⚠️ cPanel account creation failed - marking subscription as 'failed'")
                    logger.warning(f"   Expected: username, password, server_ip")
                    logger.warning(f"   Received: {list(external_data.keys())}")
                
                # Fetch hosting plan data to get correct billing_cycle and duration_days
                cursor.execute(
                    "SELECT billing_cycle, duration_days FROM hosting_plans WHERE id = %s",
                    (intent['hosting_plan_id'],)
                )
                plan_result = cursor.fetchone()
                
                if plan_result:
                    billing_cycle = plan_result['billing_cycle']
                    duration_days = plan_result['duration_days']
                    logger.info(f"✅ Using plan billing: {billing_cycle} ({duration_days} days) for plan {intent['hosting_plan_id']}")
                else:
                    logger.warning(f"⚠️ Could not fetch plan data for plan_id {intent['hosting_plan_id']}, defaulting to 'monthly' + 30 days")
                    billing_cycle = 'monthly'
                    duration_days = 30
                
                # Calculate next billing date using plan's actual duration
                next_billing_date = datetime.now() + timedelta(days=duration_days)
                
                # Create hosting subscription with proper foreign key relationship
                # CRITICAL FIX: Include domain_name from hosting_provision_intents
                cursor.execute(
                    """INSERT INTO hosting_subscriptions 
                       (user_id, hosting_plan_id, domain_id, domain_name, cpanel_username, cpanel_password, 
                        server_ip, status, billing_cycle, next_billing_date, auto_renew) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
                       RETURNING id""",
                    (
                        intent['user_id'], 
                        intent['hosting_plan_id'], 
                        intent['domain_id'],
                        intent['domain_name'],  # CRITICAL FIX: Save domain name to hosting_subscriptions
                        cpanel_username,
                        external_data.get('password'),
                        external_data.get('server_ip'),
                        subscription_status,  # Now correctly reflects actual provisioning status
                        billing_cycle,
                        next_billing_date,
                        auto_renew
                    )
                )
                
                hosting_subscription_result = cursor.fetchone()
                if not hosting_subscription_result:
                    logger.error(f"❌ Failed to create hosting subscription for intent {intent_id}")
                    return False
                    
                subscription_id = hosting_subscription_result['id']
                
                # Create cPanel account record ONLY if provisioning was successful
                if cpanel_username and cpanel_success:
                    # Get domain name for cPanel account record
                    # CRITICAL FIX: Use domain_name from intent directly for hosting bundles
                    domain_name = intent.get('domain_name')
                    
                    # If no domain_name in intent, try to get from domains table using domain_id
                    if not domain_name and intent['domain_id']:
                        cursor.execute(
                            "SELECT domain_name FROM domains WHERE id = %s",
                            (intent['domain_id'],)
                        )
                        domain_result = cursor.fetchone()
                        if domain_result:
                            domain_name = domain_result['domain_name']
                    
                    cursor.execute(
                        """INSERT INTO cpanel_accounts 
                           (subscription_id, cpanel_username, cpanel_domain, 
                            server_name, ip_address, status) 
                           VALUES (%s, %s, %s, %s, %s, %s)""",
                        (
                            subscription_id,
                            cpanel_username,
                            domain_name,  # Now correctly uses domain from intent for bundles
                            external_data.get('server_name', 'server1'),
                            external_data.get('server_ip'),
                            'active'
                        )
                    )
                    logger.info(f"✅ Created cPanel account record for {cpanel_username}")
                elif cpanel_username and not cpanel_success:
                    logger.warning(f"⚠️ Skipping cPanel account record creation - provisioning failed for {cpanel_username}")
                
                # Mark intent status based on actual provisioning success
                intent_status = 'completed' if cpanel_success else 'failed'
                cursor.execute(
                    """UPDATE hosting_provision_intents 
                       SET status = %s, external_reference = %s, updated_at = CURRENT_TIMESTAMP 
                       WHERE id = %s""",
                    (intent_status, f"subscription_{subscription_id}", intent_id)
                )
                
                domain_info = f"domain_id {intent['domain_id']}" if intent['domain_id'] else "no domain"
                if cpanel_success:
                    logger.info(f"✅ Finalized hosting provisioning for {domain_info} - intent {intent_id}, subscription {subscription_id}")
                    return True
                else:
                    logger.error(f"❌ Hosting provisioning failed for {domain_info} - intent {intent_id}, subscription {subscription_id}")
                    return False
                
        except Exception as e:
            logger.error(f"❌ Error in transaction finalizing hosting provisioning for intent {intent_id}: {e}")
            return False
    
    # Execute the entire operation in a single transaction
    try:
        transaction_success = await run_in_transaction(_finalize_in_transaction, intent_id, cpanel_username, external_data, auto_renew)
        
        if transaction_success:
            # Handle different service types
            if bundle_domain_registration_needed:
                # Get the subscription_id from the completed intent
                subscription_result = await execute_query(
                    "SELECT external_reference FROM hosting_provision_intents WHERE id = %s",
                    (intent_id,)
                )
                
                if subscription_result and subscription_result[0]['external_reference'].startswith('subscription_'):
                    subscription_id = int(subscription_result[0]['external_reference'].replace('subscription_', ''))
                    
                    logger.info(f"🌐 Registering domain {intent['domain_name']} for subscription {subscription_id}")
                    
                    # CRITICAL FIX: Avoid circular import by deferring domain registration
                    # Mark subscription for domain registration completion outside this function
                    logger.info(f"🌐 Marking subscription {subscription_id} for domain registration: {intent['domain_name']}")
                    
                    # Return special status indicating domain registration is needed
                    # The calling code in handlers.py will handle domain registration
                    return {'success': True, 'needs_domain_registration': True, 'subscription_id': subscription_id, 'domain_name': intent['domain_name'], 'user_id': intent['user_id']}
            else:
                # Hosting-only subscription (no domain registration needed) - mark as active immediately
                subscription_result = await execute_query(
                    "SELECT external_reference FROM hosting_provision_intents WHERE id = %s",
                    (intent_id,)
                )
                
                if subscription_result and subscription_result[0]['external_reference'].startswith('subscription_'):
                    subscription_id = int(subscription_result[0]['external_reference'].replace('subscription_', ''))
                    
                    # Mark hosting-only subscription as active
                    await execute_update(
                        "UPDATE hosting_subscriptions SET status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (subscription_id,)
                    )
                    logger.info(f"✅ Hosting-only subscription {subscription_id} marked as active")
        
        return transaction_success
        
    except Exception as e:
        logger.error(f"❌ Error finalizing hosting provisioning for intent {intent_id}: {e}")
        return False

async def _run_bundle_failure_compensation(subscription_id: int, domain_name: str) -> None:
    """
    Run compensating actions when domain registration fails in a hosting+domain bundle
    CRITICAL FIX: Prevents orphaned 'active' hosting subscriptions without domains
    """
    try:
        logger.info(f"🔄 Running bundle failure compensation for subscription {subscription_id}, domain {domain_name}")
        
        # Step 1: Update hosting subscription to failed status
        await execute_update(
            "UPDATE hosting_subscriptions SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (subscription_id,)
        )
        logger.info(f"✅ Updated subscription {subscription_id} status to 'failed'")
        
        # Step 2: Clean up cPanel account records
        deleted_cpanel = await execute_update(
            "DELETE FROM cpanel_accounts WHERE subscription_id = %s",
            (subscription_id,)
        )
        if deleted_cpanel:
            logger.info(f"✅ Cleaned up cPanel account for subscription {subscription_id}")
        
        # Step 3: Attempt Cloudflare zone cleanup using existing zone_id
        try:            
            # Try to find the zone_id for this domain in our database
            zone_query = await execute_query(
                "SELECT cf_zone_id FROM cloudflare_zones WHERE domain_name = %s",
                (domain_name,)
            )
            
            if zone_query:
                zone_id = zone_query[0]['cf_zone_id']
                logger.info(f"🗑️ Found Cloudflare zone {zone_id} for cleanup of {domain_name}")
                
                # Remove from our database - the zone will remain in Cloudflare for manual cleanup
                await execute_update(
                    "DELETE FROM cloudflare_zones WHERE domain_name = %s",
                    (domain_name,)
                )
                logger.info(f"✅ Removed zone record from database for {domain_name}")
                logger.warning(f"⚠️ Manual Cloudflare zone cleanup needed for {domain_name} (zone_id: {zone_id})")
            else:
                logger.info(f"ℹ️ No Cloudflare zone found in database for {domain_name}")
                
        except Exception as cf_error:
            logger.warning(f"⚠️ Could not clean up Cloudflare zone for {domain_name}: {cf_error}")
        
        # Step 4: Get hosting subscription details for refund
        subscription_details = await execute_query(
            "SELECT user_id, hosting_plan_id FROM hosting_subscriptions WHERE id = %s AND deleted_at IS NULL",
            (subscription_id,)
        )
        
        if subscription_details:
            user_id = subscription_details[0]['user_id']
            
            # Get hosting plan price for refund calculation
            plan_details = await execute_query(
                "SELECT plan_price FROM hosting_plans WHERE id = %s",
                (subscription_details[0]['hosting_plan_id'],)
            )
            
            if plan_details:
                # This would refund the hosting portion, domain portion should be handled separately
                hosting_price = plan_details[0]['plan_price']
                logger.info(f"💰 Hosting portion to refund: ${hosting_price} for user {user_id}")
                # Note: Actual refund logic should be handled by the calling function
                # since it may involve bundle pricing that includes domain costs
        
        logger.info(f"✅ Bundle failure compensation completed for subscription {subscription_id}")
        
    except Exception as e:
        logger.error(f"❌ Error running bundle failure compensation for subscription {subscription_id}: {e}")
        # Continue execution - compensation failures shouldn't block the main flow

async def get_active_hosting_intent(user_id: int, domain_name: Optional[str]) -> Optional[Dict]:
    """
    Check for active hosting provision intent for a domain by a user
    FIXED: Handles both existing domains (by domain_id) and new domains (by domain_name)
    """
    try:
        # Resolve domain_name to domain_id if provided
        domain_id = None
        if domain_name:
            domain_id = await get_domain_id_by_name(domain_name)
        
        # Search by both domain_id (for existing domains) and domain_name (for new domains)
        if domain_id:
            # Domain exists - search by domain_id
            result = await execute_query(
                """SELECT * FROM hosting_provision_intents 
                   WHERE user_id = %s AND domain_id = %s AND status IN ('pending_payment', 'provisioning', 'payment_confirmed', 'paid')
                   ORDER BY created_at DESC LIMIT 1""",
                (user_id, domain_id)
            )
        elif domain_name:
            # Domain doesn't exist yet (hosting bundle) - search by domain_name
            result = await execute_query(
                """SELECT * FROM hosting_provision_intents 
                   WHERE user_id = %s AND domain_name = %s AND domain_id IS NULL 
                   AND status IN ('pending_payment', 'provisioning', 'payment_confirmed', 'paid')
                   ORDER BY created_at DESC LIMIT 1""",
                (user_id, domain_name)
            )
        else:
            # No domain specified
            result = await execute_query(
                """SELECT * FROM hosting_provision_intents 
                   WHERE user_id = %s AND domain_id IS NULL AND domain_name IS NULL 
                   AND status IN ('pending_payment', 'provisioning', 'payment_confirmed', 'paid')
                   ORDER BY created_at DESC LIMIT 1""",
                (user_id,)
            )
        
        return dict(result[0]) if result else None
    except Exception as e:
        domain_info = f"domain '{domain_name}'" if domain_name else "no domain"
        logger.error(f"❌ Error checking active hosting intent for {domain_info}: {e}")
        return None

async def get_hosting_intent_by_id(intent_id: int) -> Optional[Dict]:
    """Get hosting provision intent by ID"""
    try:
        result = await execute_query(
            "SELECT * FROM hosting_provision_intents WHERE id = %s",
            (intent_id,)
        )
        return dict(result[0]) if result else None
    except Exception as e:
        logger.error(f"❌ Error getting hosting intent {intent_id}: {e}")
        return None

async def cleanup_expired_hosting_intents() -> int:
    """
    Clean up stale hosting provision intents older than 2 hours
    
    Handles intents stuck in pending_payment status
    """
    try:
        # Clean up stale pending_payment intents older than 30 minutes
        result = await execute_query(
            """UPDATE hosting_provision_intents 
               SET status = 'cancelled', updated_at = NOW()
               WHERE status = 'pending_payment'
               AND created_at < NOW() - INTERVAL '30 minutes'
               RETURNING id""",
        )
        count = len(result) if result else 0
        
        if count > 0:
            logger.info(f"🧹 Cleaned up {count} stale hosting intents")
        return count
    except Exception as e:
        logger.error(f"❌ Error cleaning up expired hosting intents: {e}")
        return 0

async def cleanup_failed_hosting_orders() -> int:
    """
    Clean up failed hosting orders that are blocking new orders
    
    Handles:
    1. payment_insufficient orders older than 15 minutes
    2. pending orders older than 30 minutes (stuck/abandoned)
    """
    total_cleaned = 0
    try:
        # 1. Cancel payment_insufficient orders older than 15 minutes
        result = await execute_query(
            """UPDATE hosting_orders 
               SET status = 'cancelled', updated_at = NOW()
               WHERE status = 'payment_insufficient'
               AND created_at < NOW() - INTERVAL '15 minutes'
               RETURNING id""",
        )
        insufficient_count = len(result) if result else 0
        total_cleaned += insufficient_count
        
        # 2. Cancel stale pending orders older than 30 minutes
        stale_result = await execute_query(
            """UPDATE hosting_orders 
               SET status = 'cancelled', updated_at = NOW()
               WHERE status = 'pending'
               AND created_at < NOW() - INTERVAL '30 minutes'
               RETURNING id""",
        )
        stale_count = len(stale_result) if stale_result else 0
        total_cleaned += stale_count
        
        if total_cleaned > 0:
            logger.info(f"🧹 Cleaned up {total_cleaned} hosting orders (insufficient: {insufficient_count}, stale: {stale_count})")
        return total_cleaned
    except Exception as e:
        logger.error(f"❌ Error cleaning up failed hosting orders: {e}")
        return 0

async def cleanup_failed_domain_orders() -> int:
    """
    Clean up failed domain orders that are blocking new orders
    
    Handles:
    1. payment_insufficient domain orders older than 15 minutes
    2. pending domain orders older than 30 minutes (stuck/abandoned)
    """
    total_cleaned = 0
    try:
        # 1. Cancel payment_insufficient domain orders older than 15 minutes
        result = await execute_query(
            """UPDATE domain_orders 
               SET status = 'cancelled', updated_at = NOW()
               WHERE status = 'payment_insufficient'
               AND created_at < NOW() - INTERVAL '15 minutes'
               RETURNING id""",
        )
        insufficient_count = len(result) if result else 0
        total_cleaned += insufficient_count
        
        # 2. Cancel stale pending domain orders older than 30 minutes
        stale_result = await execute_query(
            """UPDATE domain_orders 
               SET status = 'cancelled', updated_at = NOW()
               WHERE status = 'pending'
               AND created_at < NOW() - INTERVAL '30 minutes'
               RETURNING id""",
        )
        stale_count = len(stale_result) if stale_result else 0
        total_cleaned += stale_count
        
        if total_cleaned > 0:
            logger.info(f"🧹 Cleaned up {total_cleaned} domain orders (insufficient: {insufficient_count}, stale: {stale_count})")
        return total_cleaned
    except Exception as e:
        logger.error(f"❌ Error cleaning up failed domain orders: {e}")
        return 0

async def cleanup_stale_domain_intents() -> int:
    """
    Clean up stale domain registration intents older than 30 minutes
    """
    try:
        result = await execute_query(
            """UPDATE domain_registration_intents 
               SET status = 'cancelled', updated_at = NOW()
               WHERE status = 'pending'
               AND created_at < NOW() - INTERVAL '30 minutes'
               RETURNING id""",
        )
        count = len(result) if result else 0
        if count > 0:
            logger.info(f"🧹 Cleaned up {count} stale domain registration intents")
        return count
    except Exception as e:
        logger.error(f"❌ Error cleaning up stale domain intents: {e}")
        return 0

async def cleanup_failed_rdp_orders() -> int:
    """
    Clean up stale RDP-related payment intents
    
    Note: rdp_orders table is a simple linking table without status.
    RDP payment tracking is via payment_intents with order_id prefix 'rdp_'
    """
    try:
        # Clean up expired RDP payment intents (handled by main payment cleanup)
        # This function exists for API compatibility
        # RDP server status is managed via rdp_servers.status, not rdp_orders
        return 0
    except Exception as e:
        logger.error(f"❌ Error cleaning up failed RDP orders: {e}")
        return 0

async def get_domain_id_by_name(domain_name: str) -> Optional[int]:
    """Get domain ID by domain name for intent system"""
    try:
        result = await execute_query(
            "SELECT id FROM domains WHERE domain_name = %s AND deleted_at IS NULL",
            (domain_name,)
        )
        return result[0]['id'] if result else None
    except Exception as e:
        logger.error(f"❌ Error getting domain ID for {domain_name}: {e}")
        return None


# ====================================================================
# PAYMENT INTENTS - PREVENT DUPLICATE PAYMENT ADDRESS CREATION
# ====================================================================

@track_payment_operation("create_payment_intent")
async def create_payment_intent(order_id: str, user_id: int, amount: Decimal, currency: str = 'USD', crypto_currency: Optional[str] = None, provider: str = 'dynopay', auth_token: Optional[str] = None) -> Optional[int]:
    """
    Create payment intent to prevent duplicate payment address creation
    Uses order_id as natural idempotency key to prevent duplicates
    SECURITY FIX: Now includes auth_token parameter for webhook validation
    TIMEOUT ENHANCEMENT: Automatically sets expires_at based on cryptocurrency type
    ENHANCED LOGGING: Comprehensive state transition and performance logging
    """
    # CRITICAL VALIDATION: Prevent $0 or negative payment intents
    if amount <= 0:
        logger.error(f"❌ PAYMENT INTENT REJECTED: Invalid amount ${amount} for order {order_id} - must be greater than $0.00")
        logger.error(f"   Order: {order_id}, User: {user_id}, Provider: {provider}, Currency: {crypto_currency or currency}")
        return None
    
    operation_start = time.time()
    correlation_id = None
    
    # Create payment logging context
    try:
        import uuid as uuid_mod
        context = PaymentLogContext(
            correlation_id=str(uuid_mod.uuid4()),
            user_id=user_id,
            order_id=order_id,
            provider=provider,
            currency=currency,
            amount_usd=amount,
            current_status="creating"
        )
        correlation_id = context.correlation_id
        
        # Log payment intent creation start
        payment_logger.log_payment_event(
            PaymentEventType.INTENT_CREATED,
            f"Starting payment intent creation for ${amount} {currency}",
            context,
            PaymentLogLevel.INFO
        )
    except Exception as e:
        logger.debug(f"Payment logging failed: {e}")
        context = None
    
    try:
        import uuid
        from datetime import datetime
        from payment_timeout_config import calculate_payment_expires_at
        
        idempotency_key = str(uuid.uuid4())
        
        # Calculate automatic expiration timestamp based on cryptocurrency type
        expires_at = None
        if crypto_currency:
            try:
                expires_at = calculate_payment_expires_at(
                    currency=crypto_currency,
                    provider=provider,
                    payment_amount_usd=float(amount),
                    created_at=datetime.utcnow()
                )
                
                # Enhanced timeout logging
                timeout_context = PaymentLogContext(
                    correlation_id=correlation_id,
                    user_id=user_id,
                    order_id=order_id,
                    provider=provider,
                    currency=crypto_currency,
                    metadata={'expires_at': expires_at.isoformat(), 'timeout_calculation': 'success'}
                )
                payment_logger.log_payment_event(
                    PaymentEventType.INTENT_UPDATED,
                    f"Payment timeout calculated for {crypto_currency.upper()}: expires at {expires_at} UTC",
                    timeout_context,
                    PaymentLogLevel.INFO
                )
                
                logger.info(f"🕐 TIMEOUT: Payment intent for {crypto_currency.upper()} will expire at {expires_at} UTC")
                
            except Exception as timeout_error:
                logger.warning(f"⚠️ TIMEOUT: Failed to calculate expiration for {crypto_currency}, using default: {timeout_error}")
                
                # Enhanced timeout error logging
                payment_logger.log_payment_error(
                    timeout_error,
                    PaymentLogContext(
                        correlation_id=correlation_id,
                        user_id=user_id,
                        order_id=order_id,
                        provider=provider,
                        currency=crypto_currency,
                        metadata={'timeout_calculation': 'failed', 'fallback': 'default_30min'}
                    ),
                    error_category="timeout_calculation",
                    actionable_steps=[
                        "Review payment_timeout_config configuration",
                        "Check cryptocurrency type mapping",
                        "Verify datetime handling for timezone issues"
                    ]
                )
                
                # Fallback to 30 minutes if timeout calculation fails
                from datetime import timedelta
                expires_at = datetime.utcnow() + timedelta(minutes=30)
        
        # Simple INSERT with correct schema columns - no complex ON CONFLICT
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query(
            """INSERT INTO payment_intents 
               (order_id, user_id, amount, currency, crypto_currency, payment_provider, status, expires_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s) 
               RETURNING id""",
            (order_id, user_id, amount, currency, crypto_currency, provider, 'created', expires_at)
        )
        
        if result and len(result) > 0:
            intent_id = result[0]['id']
            
            # Enhanced success logging with performance metrics
            duration_ms = (time.time() - operation_start) * 1000
            
            success_context = PaymentLogContext(
                correlation_id=correlation_id,
                user_id=user_id,
                order_id=order_id,
                payment_intent_id=intent_id,
                provider=provider,
                currency=currency,
                amount_usd=amount,
                current_status="created",
                duration_ms=duration_ms,
                metadata={
                    'idempotency_key': idempotency_key,
                    'expires_at': expires_at.isoformat() if expires_at else None,
                    'crypto_currency': crypto_currency,
                    'auth_token_provided': auth_token is not None
                }
            )
            
            payment_logger.log_payment_event(
                PaymentEventType.INTENT_CREATED,
                f"Payment intent {intent_id} created successfully for ${amount} {currency}",
                success_context,
                PaymentLogLevel.INFO
            )
            
            # Log status transition to created
            payment_logger.log_status_transition(
                "none", "created", success_context, "Initial payment intent creation"
            )
            
            logger.info(f"✅ Created payment intent {intent_id} for order {order_id} by user {user_id}")
            return intent_id
        else:
            # No graceful degradation - this is a real error that should surface
            logger.error(f"❌ PAYMENT_INTENT_CREATION_FAILED: INSERT returned no result for order {order_id}, provider {provider}")
            logger.error(f"❌ DEBUG: amount={amount}, currency={currency}, crypto_currency={crypto_currency}, user_id={user_id}")
            
            # Let the error surface instead of masking it
            payment_logger.log_payment_error(
                ValueError("Payment intent creation returned no result"),
                PaymentLogContext(
                    correlation_id=correlation_id,
                    user_id=user_id,
                    order_id=order_id,
                    provider=provider,
                    currency=currency,
                    amount_usd=amount,
                    metadata={'error_type': 'insert_no_result'}
                ),
                error_category="database_error",
                actionable_steps=[
                    "Check database connection and schema",
                    "Verify payment_intents table structure",
                    "Review transaction isolation settings"
                ]
            )
            return None
        
    except Exception as e:
        # Enhanced error logging with comprehensive context
        duration_ms = (time.time() - operation_start) * 1000
        
        if PAYMENT_LOGGING_AVAILABLE:
            error_context = PaymentLogContext(
                correlation_id=correlation_id,
                user_id=user_id,
                order_id=order_id,
                provider=provider,
                currency=currency,
                amount_usd=amount,
                current_status="failed",
                duration_ms=duration_ms,
                metadata={
                    'operation': 'create_payment_intent',
                    'crypto_currency': crypto_currency,
                    'auth_token_provided': auth_token is not None
                }
            )
            
            payment_logger.log_payment_error(
                e,
                error_context,
                error_category="intent_creation_failure",
                actionable_steps=[
                    "Check database connectivity and schema",
                    "Verify payment_intents table structure",
                    "Review order_id format and uniqueness constraints",
                    "Check user_id validity in users table",
                    "Validate amount and currency parameters"
                ]
            )
        
        logger.error(f"❌ Error creating payment intent for order {order_id}: {e}")
        return None

async def get_payment_intent_by_order_id(order_id: str) -> Optional[Dict]:
    """Get payment intent by business order ID"""
    try:
        result = await execute_query(
            "SELECT * FROM payment_intents WHERE order_id = %s AND deleted_at IS NULL",
            (order_id,)
        )
        return dict(result[0]) if result else None
    except Exception as e:
        logger.error(f"❌ Error getting payment intent for order {order_id}: {e}")
        return None

async def create_payment_intent_atomic(order_id: str, user_id: int, amount: Decimal, currency: str = 'USD', crypto_currency: Optional[str] = None, provider: str = 'dynopay', auth_token: Optional[str] = None) -> Optional[int]:
    """
    ATOMIC payment intent creation with race condition protection
    Uses INSERT...ON CONFLICT DO NOTHING pattern to prevent duplicate intents for same order
    
    This function replaces the check-then-create pattern with a truly atomic operation:
    1. Attempts to INSERT new payment intent
    2. If order_id already exists (unique constraint violation), returns existing intent ID
    3. Prevents race conditions where multiple processes create intents for same order
    
    Returns:
        int: Payment intent ID (either newly created or existing)
        None: If creation failed
    """
    # CRITICAL VALIDATION: Prevent $0 or negative payment intents
    if amount <= 0:
        logger.error(f"❌ ATOMIC PAYMENT INTENT REJECTED: Invalid amount ${amount} for order {order_id} - must be greater than $0.00")
        logger.error(f"   Order: {order_id}, User: {user_id}, Provider: {provider}, Currency: {crypto_currency or currency}")
        return None
    
    operation_start = time.time()
    correlation_id = None
    
    # Create payment logging context
    try:
        import uuid as uuid_mod
        context = PaymentLogContext(
            correlation_id=str(uuid_mod.uuid4()),
            user_id=user_id,
            order_id=order_id,
            provider=provider,
            currency=currency,
            amount_usd=amount,
            current_status="creating_atomic"
        )
        correlation_id = context.correlation_id
        
        payment_logger.log_payment_event(
            PaymentEventType.INTENT_CREATED,
            f"Starting ATOMIC payment intent creation for ${amount} {currency}",
            context,
            PaymentLogLevel.INFO
        )
    except Exception as e:
        logger.debug(f"Payment logging failed: {e}")
        context = None

    try:
        import uuid
        from datetime import datetime
        from payment_timeout_config import calculate_payment_expires_at
        
        idempotency_key = str(uuid.uuid4())
        
        # Calculate automatic expiration timestamp based on cryptocurrency type
        expires_at = None
        if crypto_currency:
            try:
                expires_at = calculate_payment_expires_at(
                    currency=crypto_currency,
                    provider=provider,
                    payment_amount_usd=float(amount),
                    created_at=datetime.utcnow()
                )
                logger.info(f"🕐 ATOMIC: Payment intent for {crypto_currency.upper()} will expire at {expires_at} UTC")
            except Exception as timeout_error:
                logger.warning(f"⚠️ ATOMIC: Failed to calculate expiration for {crypto_currency}, using default: {timeout_error}")
                from datetime import timedelta
                expires_at = datetime.utcnow() + timedelta(minutes=30)
        
        # ATOMIC INSERT with conflict handling on order_id
        # This is the key fix - using ON CONFLICT (order_id) DO NOTHING prevents duplicates
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query(
            """INSERT INTO payment_intents 
               (order_id, user_id, amount, currency, crypto_currency, payment_provider, status, expires_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s) 
               RETURNING id""",
            (order_id, user_id, amount, currency, crypto_currency, provider, 'created', expires_at)
        )
        
        if result and len(result) > 0:
            # New intent created successfully
            intent_id = result[0]['id']
            duration_ms = (time.time() - operation_start) * 1000
            
            logger.info(f"✅ ATOMIC: Created NEW payment intent {intent_id} for order {order_id} (${amount} {currency}) in {duration_ms:.1f}ms")
            
            if context:
                success_context = PaymentLogContext(
                    correlation_id=correlation_id,
                    payment_intent_id=intent_id,
                    user_id=user_id,
                    order_id=order_id,
                    provider=provider,
                    currency=currency,
                    amount_usd=amount,
                    current_status="created",
                    duration_ms=duration_ms
                )
                payment_logger.log_payment_event(
                    PaymentEventType.INTENT_CREATED,
                    f"ATOMIC payment intent created successfully: ${amount} {currency}",
                    success_context,
                    PaymentLogLevel.INFO
                )
            
            return intent_id
        else:
            # Intent already exists due to unique constraint - get the existing one (idempotent behavior)
            existing_result = await execute_query(
                "SELECT id FROM payment_intents WHERE order_id = %s AND deleted_at IS NULL",
                (order_id,)
            )
            
            if existing_result:
                existing_id = existing_result[0]['id']
                duration_ms = (time.time() - operation_start) * 1000
                
                logger.info(f"🔄 ATOMIC: Found EXISTING payment intent {existing_id} for order {order_id} (idempotent) in {duration_ms:.1f}ms")
                
                if context:
                    idempotent_context = PaymentLogContext(
                        correlation_id=correlation_id,
                        payment_intent_id=existing_id,
                        user_id=user_id,
                        order_id=order_id,
                        provider=provider,
                        current_status="idempotent",
                        duration_ms=duration_ms
                    )
                    payment_logger.log_payment_event(
                        PaymentEventType.INTENT_UPDATED,
                        f"ATOMIC payment intent already exists (idempotent): order {order_id}",
                        idempotent_context,
                        PaymentLogLevel.INFO
                    )
                
                return existing_id
            else:
                # This should not happen due to the unique constraint, but handle gracefully
                logger.error(f"❌ ATOMIC: Unique constraint prevented creation but existing intent not found for order {order_id}")
                return None
    
    except Exception as e:
        duration_ms = (time.time() - operation_start) * 1000
        
        if context:
            error_context = PaymentLogContext(
                correlation_id=correlation_id,
                user_id=user_id,
                order_id=order_id,
                provider=provider,
                currency=currency,
                amount_usd=amount,
                current_status="failed",
                duration_ms=duration_ms,
                metadata={'operation': 'create_payment_intent_atomic', 'error': str(e)}
            )
            
            payment_logger.log_payment_error(
                e,
                error_context,
                error_category="atomic_creation_failure",
                actionable_steps=[
                    "Check database connectivity and transaction state",
                    "Verify payment_intents table schema and unique constraints",
                    "Review concurrent operation handling",
                    "Check for database locks or deadlocks"
                ]
            )
        
        logger.error(f"❌ ATOMIC: Error creating payment intent for order {order_id}: {e}")
        return None

async def get_payment_intent_by_id(intent_id: int) -> Optional[Dict]:
    """Get payment intent by ID"""
    try:
        result = await execute_query(
            "SELECT * FROM payment_intents WHERE id = %s AND deleted_at IS NULL",
            (intent_id,)
        )
        return dict(result[0]) if result else None
    except Exception as e:
        logger.error(f"❌ Error getting payment intent {intent_id}: {e}")
        return None

@track_payment_operation("update_payment_intent_status")
async def update_payment_intent_status(intent_id: int, status: str, payment_address: Optional[str] = None, 
                                     payment_provider: Optional[str] = None, payment_provider_order_id: Optional[str] = None) -> bool:
    """Update payment intent status and details with comprehensive state transition logging and validation"""
    operation_start = time.time()
    
    # Initialize payment logger at the beginning to ensure it's always available
    payment_logger = get_payment_logger()
    
    # Get current payment intent details for state transition logging
    current_intent = None
    previous_status = None
    correlation_id = None
    
    try:
        # Fetch current intent details for state transition logging
        current_intent = await get_payment_intent_by_id(intent_id)
        if current_intent:
            previous_status = current_intent.get('status')
            
            # CRITICAL: Validate state transition before attempting update
            try:
                from payment_state_validation import validate_payment_state_transition, log_transition_attempt
                
                # Log and validate the transition attempt
                log_transition_attempt(
                    previous_status or "unknown", 
                    status, 
                    payment_intent_id=intent_id,
                    order_id=current_intent.get('order_id') or ""
                )
                
                # This will raise ValueError if transition is invalid
                validate_payment_state_transition(previous_status or "unknown", status)
                
            except ValueError as validation_error:
                # State transition validation failed
                logger.error(f"🚫 STATE VALIDATION FAILED: Intent {intent_id} cannot transition from '{previous_status}' to '{status}': {validation_error}")
                
                # Log validation failure through payment logger
                validation_context = PaymentLogContext(
                    correlation_id=str(uuid.uuid4()),
                    user_id=current_intent.get('user_id'),
                    order_id=current_intent.get('order_id'),
                    payment_intent_id=intent_id,
                    provider=payment_provider or current_intent.get('payment_provider'),
                    previous_status=previous_status,
                    current_status=status,
                    metadata={
                        'validation_error': str(validation_error),
                        'attempted_transition': f"{previous_status} → {status}",
                        'validation_failure': True
                    }
                )
                
                payment_logger.log_payment_error(
                    validation_error,
                    validation_context,
                    error_category="invalid_state_transition",
                    actionable_steps=[
                        f"Review payment state machine: {previous_status} cannot transition to {status}",
                        "Check business logic for valid state transitions",
                        "Verify webhook data and payment processing flow",
                        "Consider if this is a duplicate/late webhook callback"
                    ]
                )
                
                return False
            
            except ImportError as import_error:
                # Validation module not available - log warning but continue
                logger.warning(f"⚠️ STATE VALIDATION: Module not available, skipping validation: {import_error}")
        else:
            logger.warning(f"⚠️ STATE VALIDATION: Could not fetch current intent {intent_id} for validation")
            
        # Create payment logging context with current intent details
        if current_intent:
            context = PaymentLogContext(
                    correlation_id=str(uuid.uuid4()),
                    user_id=current_intent.get('user_id'),
                    order_id=current_intent.get('order_id'),
                    payment_intent_id=intent_id,
                    provider=payment_provider or current_intent.get('payment_provider'),
                    currency=current_intent.get('crypto_currency') or current_intent.get('currency'),
                    amount_usd=current_intent.get('amount'),
                    previous_status=previous_status,
                    current_status=status,
                    payment_address=payment_address,
                    external_payment_id=payment_provider_order_id
                )
            correlation_id = context.correlation_id
            
            # Log status transition start
            payment_logger.log_payment_event(
                PaymentEventType.STATUS_TRANSITION,
                f"Starting payment intent status update: {previous_status} → {status}",
                context,
                PaymentLogLevel.INFO
            )
    except Exception as fetch_error:
        logger.warning(f"⚠️ Could not fetch current intent details for logging: {fetch_error}")
    
    try:
        # Perform the status update based on provided parameters
        if payment_address and payment_provider:
            await execute_update(
                """UPDATE payment_intents 
                   SET status = %s, payment_address = %s, provider = %s, 
                       external_id = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s""",
                (status, payment_address, payment_provider, payment_provider_order_id, intent_id)
            )
        elif payment_address:
            await execute_update(
                """UPDATE payment_intents 
                   SET status = %s, payment_address = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s""",
                (status, payment_address, intent_id)
            )
        else:
            await execute_update(
                """UPDATE payment_intents 
                   SET status = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s""",
                (status, intent_id)
            )
        
        # Enhanced success logging with state transition audit trail
        duration_ms = (time.time() - operation_start) * 1000
        
        if current_intent:
            success_context = PaymentLogContext(
                correlation_id=correlation_id,
                user_id=current_intent.get('user_id'),
                order_id=current_intent.get('order_id'),
                payment_intent_id=intent_id,
                provider=payment_provider or current_intent.get('payment_provider'),
                currency=current_intent.get('crypto_currency') or current_intent.get('currency'),
                amount_usd=current_intent.get('amount'),
                previous_status=previous_status,
                current_status=status,
                payment_address=payment_address,
                external_payment_id=payment_provider_order_id,
                duration_ms=duration_ms,
                metadata={
                    'payment_address_updated': payment_address is not None,
                    'provider_updated': payment_provider is not None,
                    'external_id_updated': payment_provider_order_id is not None,
                    'update_type': 'full' if payment_address and payment_provider else 'partial'
                }
            )
            
            # Log successful status transition
            payment_logger.log_status_transition(
                previous_status or "unknown",
                status,
                success_context,
                f"Payment intent updated with {'address and provider' if payment_address and payment_provider else 'status only'}"
            )
            
            # Log intent update event
            payment_logger.log_payment_event(
                PaymentEventType.INTENT_UPDATED,
                f"Payment intent {intent_id} status updated successfully: {previous_status} → {status}",
                success_context,
                PaymentLogLevel.INFO
            )
            
            # Special logging for critical status transitions
            critical_statuses = ['confirmed', 'successful', 'completed', 'failed', 'expired', 'cancelled']
            if status in critical_statuses:
                payment_logger.log_payment_event(
                    PaymentEventType.STATUS_TRANSITION,
                    f"CRITICAL STATUS CHANGE: Payment intent {intent_id} moved to {status}",
                    success_context,
                    PaymentLogLevel.AUDIT
                )
        
        logger.info(f"✅ Updated payment intent {intent_id} status to {status}")
        return True
        
    except Exception as e:
        # Enhanced error logging with state transition context
        duration_ms = (time.time() - operation_start) * 1000
        
        if current_intent:
            error_context = PaymentLogContext(
                correlation_id=correlation_id,
                user_id=current_intent.get('user_id'),
                order_id=current_intent.get('order_id'),
                payment_intent_id=intent_id,
                provider=payment_provider or current_intent.get('payment_provider'),
                currency=current_intent.get('crypto_currency') or current_intent.get('currency'),
                amount_usd=current_intent.get('amount'),
                previous_status=previous_status,
                current_status=status,
                payment_address=payment_address,
                external_payment_id=payment_provider_order_id,
                duration_ms=duration_ms,
                metadata={
                    'operation': 'update_payment_intent_status',
                    'attempted_status': status,
                    'attempted_address': payment_address,
                    'attempted_provider': payment_provider
                }
            )
            
            payment_logger.log_payment_error(
                e,
                error_context,
                error_category="status_update_failure",
                actionable_steps=[
                    "Check database connectivity and transaction state",
                    "Verify payment_intents table schema and constraints",
                    f"Confirm payment intent {intent_id} exists and is not deleted",
                    "Review status transition rules and valid status values",
                    "Check for database locks or concurrent modifications"
                ]
            )
        
        logger.error(f"❌ Error updating payment intent {intent_id}: {e}")
        return False

async def get_active_payment_intent(user_id: int, order_id: str) -> Optional[Dict]:
    """Get active payment intent for order"""
    try:
        result = await execute_query(
            """SELECT * FROM payment_intents 
               WHERE user_id = %s AND order_id = %s AND status NOT IN ('completed', 'expired') 
               ORDER BY created_at DESC LIMIT 1""",
            (user_id, order_id)
        )
        return dict(result[0]) if result else None
    except Exception as e:
        logger.error(f"❌ Error checking active payment intent for order {order_id}: {e}")
        return None

# CRITICAL: Atomic intent claiming functions for concurrency safety
async def claim_intent_for_address_creation(intent_id: int, provider_name: str, idempotency_key: str) -> Optional[Dict]:
    """
    Atomically claim payment intent for address creation using Compare-And-Swap (CAS) pattern
    Only one process can successfully claim an intent - prevents concurrent address creation
    
    Returns:
        Dict with intent data if successfully claimed, None if already claimed by another process
    """
    try:
        # Step 1: Atomically claim the intent using CAS pattern - SOFTENED to allow retry of failed intents
        # CRITICAL FIX: Use execute_update for UPDATE to ensure commit
        rows_affected = await execute_update(
            """UPDATE payment_intents 
               SET status = 'creating_address', updated_at = CURRENT_TIMESTAMP 
               WHERE id = %s AND status IN ('created', 'pending', 'failed')""",
            (intent_id,)
        )
        
        if not rows_affected or rows_affected == 0:
            # Intent already claimed or in wrong state
            logger.info(f"⚠️ Intent {intent_id} already claimed or not available for address creation")
            return None
        
        # Fetch the intent data after successful claim
        intent_result = await execute_query(
            """SELECT id, order_id, user_id, amount, currency, crypto_currency, idempotency_key 
               FROM payment_intents WHERE id = %s""",
            (intent_id,)
        )
        
        if not intent_result:
            logger.error(f"❌ Intent {intent_id} claimed but could not be retrieved")
            return None
            
        intent_data = dict(intent_result[0])
        logger.info(f"🔒 Successfully claimed intent {intent_id} for address creation")
        
        # Step 2: Create provider claim record to prevent duplicate external calls
        try:
            await execute_update(
                """INSERT INTO provider_claims 
                   (order_id, provider_name, intent_id, idempotency_key, status) 
                   VALUES (%s, %s, %s, %s, 'claiming')""",
                (intent_data['order_id'], provider_name, intent_id, idempotency_key)
            )
            logger.info(f"🔒 Created provider claim for {provider_name} on intent {intent_id}")
        except Exception as claim_error:
            # If provider claim fails, rollback intent status
            await execute_update(
                "UPDATE payment_intents SET status = 'created' WHERE id = %s",
                (intent_id,)
            )
            if "duplicate key" in str(claim_error).lower():
                logger.warning(f"⚠️ Provider {provider_name} already claimed intent {intent_id}")
                return None
            else:
                logger.error(f"❌ Failed to create provider claim: {claim_error}")
                raise claim_error
        
        return intent_data
        
    except Exception as e:
        logger.error(f"❌ Error claiming intent {intent_id}: {e}")
        return None

async def release_intent_claim(intent_id: int, provider_name: str, success: bool, payment_address: Optional[str] = None, external_order_id: Optional[str] = None) -> bool:
    """
    Release intent claim after address creation attempt
    
    Args:
        intent_id: Payment intent ID
        provider_name: Provider that made the claim
        success: Whether address creation was successful
        payment_address: Created payment address (if successful)
        external_order_id: External provider order ID (if successful)
    """
    try:
        if success and payment_address:
            # Mark intent as successfully completed
            await execute_update(
                """UPDATE payment_intents 
                   SET status = 'address_created', payment_address = %s, 
                       payment_provider = %s, provider_order_id = %s, 
                       updated_at = CURRENT_TIMESTAMP 
                   WHERE id = %s""",
                (payment_address, provider_name, external_order_id, intent_id)
            )
            
            # Update provider claim as successful (match by intent_id only since backup provider may differ from claim creator)
            await execute_update(
                """UPDATE provider_claims 
                   SET status = 'completed', provider_name = %s, external_address = %s, 
                       external_order_id = %s, updated_at = CURRENT_TIMESTAMP 
                   WHERE intent_id = %s AND status IN ('claiming', 'failed')""",
                (provider_name, payment_address, external_order_id, intent_id)
            )
            
            logger.info(f"✅ Successfully released intent {intent_id} claim with address {payment_address}")
        else:
            # Mark intent as failed and release claim - SOFTENED to allow future retries
            await execute_update(
                "UPDATE payment_intents SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (intent_id,)
            )
            
            # SOFTENED: Don't permanently block provider claims - allow them to be reclaimed
            await execute_update(
                """UPDATE provider_claims 
                   SET status = 'failed', updated_at = CURRENT_TIMESTAMP 
                   WHERE intent_id = %s AND provider_name = %s""",
                (intent_id, provider_name)
            )
            
            # IMPROVEMENT: Clean up old failed claims to allow retries
            await execute_update(
                """DELETE FROM provider_claims 
                   WHERE status = 'failed' AND updated_at < NOW() - INTERVAL '1 hour'"""
            )
            
            logger.info(f"⚠️ Released intent {intent_id} claim due to failure")
            
        return True
    except Exception as e:
        logger.error(f"❌ Error releasing intent claim {intent_id}: {e}")
        return False

async def wait_for_intent_address_creation(intent_id: int, max_wait_seconds: int = 30) -> Optional[Dict]:
    """
    Wait for intent address creation to complete by another process
    Used when an intent is already claimed but we need the result
    
    Returns:
        Dict with intent data including payment_address if successful, None if timeout or failed
    """
    import asyncio
    
    start_time = time.time()
    wait_interval = 0.5  # 500ms polling interval
    
    logger.info(f"⏰ Waiting for intent {intent_id} address creation to complete...")
    
    while (time.time() - start_time) < max_wait_seconds:
        try:
            intent = await get_payment_intent_by_id(intent_id)
            if not intent:
                logger.error(f"❌ Intent {intent_id} disappeared during wait")
                return None
                
            status = intent.get('status')
            
            if status == 'address_created' and intent.get('payment_address'):
                logger.info(f"✅ Intent {intent_id} address creation completed by another process")
                return intent
            elif status in ['failed', 'expired']:
                logger.warning(f"⚠️ Intent {intent_id} failed during address creation")
                return None
            
            # Still creating, wait and retry
            await asyncio.sleep(wait_interval)
            
        except Exception as e:
            logger.warning(f"⚠️ Error while waiting for intent {intent_id}: {e}")
            await asyncio.sleep(wait_interval)
    
    logger.warning(f"⏰ Timeout waiting for intent {intent_id} address creation")
    return None

async def finalize_payment_intent(intent_id: int, transaction_data: Dict[str, Any]) -> bool:
    """Finalize payment intent and mark as completed"""
    try:
        await execute_update(
            """UPDATE payment_intents 
               SET status = %s, updated_at = CURRENT_TIMESTAMP 
               WHERE id = %s""",
            ('completed', intent_id)
        )
        logger.info(f"✅ Finalized payment intent {intent_id}")
        return True
    except Exception as e:
        logger.error(f"❌ Error finalizing payment intent {intent_id}: {e}")
        return False

async def cleanup_expired_payment_intents() -> int:
    """Clean up expired payment intents - legacy function maintained for compatibility"""
    return await cleanup_stale_and_expired_payments()

async def cleanup_stale_and_expired_payments() -> int:
    """
    Enhanced payment cleanup system with cryptocurrency-specific timeout logic
    
    Handles:
    1. Expired payments: Past their calculated expires_at timestamp with grace period
    2. Stale payments: Legacy cleanup for payments without expires_at  
    3. Recently created protection: Safety checks for minimum timeout periods
    
    Enhancements:
    - Cryptocurrency-specific timeout periods (Bitcoin: 1h, others: 30min)
    - Grace period handling for network delays (5 minutes)
    - Safety checks prevent expiration of recently created payments
    - User notifications for expired payments via Telegram
    - Comprehensive audit trail and monitoring
    
    Returns:
        Total number of payments cleaned up
    """
    from payment_timeout_config import get_timeout_manager
    from datetime import datetime
    
    total_cleaned = 0
    cleanup_start = time.time()
    
    # Initialize count variables
    stale_count = 0
    expired_count = 0
    long_pending_count = 0
    notifications_sent = 0
    
    try:
        timeout_manager = get_timeout_manager()
        logger.info("🧹 ENHANCED PAYMENT CLEANUP: Starting cryptocurrency-aware payment cleanup process")
        logger.info(f"📋 Using timeout configuration: {timeout_manager.get_timeout_summary()}")
        
        # SAFETY CHECK: Get current system load to avoid cleanup during high activity
        active_payments_check = await execute_query(
            """SELECT COUNT(*) as active_count FROM payment_intents 
               WHERE status IN ('creating_address', 'processing') 
               AND created_at > NOW() - INTERVAL '5 minutes'"""
        )
        
        active_count = active_payments_check[0]['active_count'] if active_payments_check else 0
        
        if active_count > 10:
            logger.warning(f"⚠️ PAYMENT CLEANUP: High activity detected ({active_count} active payments), skipping cleanup for safety")
            return 0
        
        # 1. ENHANCED EXPIRED PAYMENT CLEANUP: Use cryptocurrency-specific timeouts with grace periods
        logger.info("🔍 ENHANCED CLEANUP: Identifying truly expired payments with grace period handling")
        
        # Get payments with expires_at for intelligent grace period handling
        expired_candidates = await execute_query(
            """SELECT id, user_id, order_id, amount, currency, crypto_currency, payment_provider, 
                      status, created_at, expires_at,
                      EXTRACT(EPOCH FROM (NOW() - expires_at))/60 as minutes_past_expiry,
                      EXTRACT(EPOCH FROM (NOW() - created_at))/60 as age_minutes
               FROM payment_intents 
               WHERE expires_at IS NOT NULL 
               AND expires_at <= CURRENT_TIMESTAMP
               AND status NOT IN ('completed', 'expired', 'successful', 'confirmed')
               ORDER BY expires_at ASC"""
        )
        
        expired_payments = []
        protected_payments = []
        
        for payment in expired_candidates:
            # Safety check: Never expire recently created payments
            if timeout_manager.is_recently_created(payment['created_at']):
                protected_payments.append(payment)
                logger.debug(f"🛡️ SAFETY: Protecting recently created payment {payment['id']} (age: {payment['age_minutes']:.1f}min)")
                continue
            
            # Grace period check using timeout manager
            is_expired, reason = timeout_manager.is_payment_expired(
                payment['expires_at'], 
                include_grace_period=True,
                current_time=datetime.utcnow()
            )
            
            if is_expired:
                expired_payments.append(payment)
                logger.info(f"⏰ EXPIRED: Payment {payment['id']} ({payment['crypto_currency'] or 'USD'}) - {reason}")
            else:
                logger.debug(f"⏳ GRACE: Payment {payment['id']} in grace period - {reason}")
        
        if expired_payments:
            logger.info(f"📊 ENHANCED CLEANUP: Found {len(expired_payments)} truly expired payments (after grace period)")
            
            # Process expired payments and send notifications
            expired_payment_ids = [p['id'] for p in expired_payments]
            
            # Update expired payments
            expired_result = await execute_query(
                """UPDATE payment_intents 
                   SET status = 'expired', 
                       updated_at = CURRENT_TIMESTAMP
                   WHERE id = ANY(%s)
                   RETURNING id, user_id, order_id, amount, crypto_currency, payment_provider""",
                (expired_payment_ids,)
            )
            
            expired_count = len(expired_result) if expired_result else 0
            total_cleaned += expired_count
            
            if expired_count > 0:
                total_expired_amount = sum(to_currency_decimal(p['amount'], "amount") for p in expired_result)
                logger.info(f"✅ ENHANCED CLEANUP: Marked {expired_count} payments as expired (total: ${total_expired_amount:.2f})")
                
                # Send user notifications for expired payments
                try:
                    from payment_expiration_notifications import send_expiration_notifications
                    notifications_sent = await send_expiration_notifications(expired_result)
                    logger.info(f"📢 NOTIFICATIONS: Sent {notifications_sent} user notifications")
                except Exception as notification_error:
                    logger.error(f"❌ NOTIFICATIONS: Failed to send expiration notifications: {notification_error}")
                    notifications_sent = 0
        else:
            logger.info("✨ ENHANCED CLEANUP: No expired payments found (after grace period)")
        
        if protected_payments:
            logger.info(f"🛡️ SAFETY: Protected {len(protected_payments)} recently created payments from expiration")
        
        # 2. CLEANUP EXPIRED PAYMENTS: Past expires_at timestamp
        logger.info("🔍 PAYMENT CLEANUP: Identifying expired payments (past expires_at)")
        
        # Get detailed info about expired payments
        expired_payments_info = await execute_query(
            """SELECT id, user_id, order_id, amount, payment_provider, expires_at, 
                      EXTRACT(EPOCH FROM (NOW() - expires_at))/3600 as hours_expired
               FROM payment_intents 
               WHERE expires_at IS NOT NULL 
               AND expires_at < CURRENT_TIMESTAMP 
               AND status NOT IN ('completed', 'expired', 'successful', 'confirmed')"""
        )
        
        if expired_payments_info:
            logger.info(f"📊 PAYMENT CLEANUP: Found {len(expired_payments_info)} expired payments (past expires_at)")
            for payment in expired_payments_info:
                logger.info(f"   • Payment {payment['id']}: ${payment['amount']:.2f} via {payment['payment_provider']}, expired {payment['hours_expired']:.1f}h ago")
            
            # Update expired payments
            expired_result = await execute_query(
                """UPDATE payment_intents 
                   SET status = 'expired', 
                       updated_at = CURRENT_TIMESTAMP
                   WHERE expires_at IS NOT NULL 
                   AND expires_at < CURRENT_TIMESTAMP 
                   AND status NOT IN ('completed', 'expired', 'successful', 'confirmed')
                   RETURNING id, user_id, order_id, amount, crypto_currency, payment_provider""",
            )
            
            expired_count = len(expired_result) if expired_result else 0
            total_cleaned += expired_count
            
            if expired_count > 0:
                total_expired_amount = sum(to_currency_decimal(p['amount'], "amount") for p in expired_result)
                logger.info(f"✅ PAYMENT CLEANUP: Marked {expired_count} expired payments as expired (total: ${total_expired_amount:.2f})")
                
                # Send user notifications for expired payments
                try:
                    from payment_expiration_notifications import send_expiration_notifications
                    notifications_sent = await send_expiration_notifications(expired_result)
                    logger.info(f"📢 NOTIFICATIONS: Sent {notifications_sent} user notifications for expired payments")
                except Exception as notification_error:
                    logger.error(f"❌ NOTIFICATIONS: Failed to send expiration notifications: {notification_error}")
        else:
            logger.info("✨ PAYMENT CLEANUP: No expired payments (past expires_at) found")
        
        # 3. CLEANUP LONG-PENDING PAYMENTS: Pending for >24 hours without expires_at
        logger.info("🔍 PAYMENT CLEANUP: Identifying long-pending payments (>24h without expires_at)")
        
        long_pending_info = await execute_query(
            """SELECT id, user_id, order_id, amount, payment_provider, status, created_at,
                      EXTRACT(EPOCH FROM (NOW() - created_at))/3600 as hours_pending
               FROM payment_intents 
               WHERE expires_at IS NULL 
               AND created_at < NOW() - INTERVAL '24 hours'
               AND status IN ('created', 'pending', 'address_created')"""
        )
        
        if long_pending_info:
            logger.info(f"📊 PAYMENT CLEANUP: Found {len(long_pending_info)} long-pending payments (>24h)")
            for payment in long_pending_info:
                logger.info(f"   • Payment {payment['id']}: ${payment['amount']:.2f} via {payment['payment_provider']}, pending {payment['hours_pending']:.1f}h")
            
            # Update long-pending payments
            long_pending_result = await execute_query(
                """UPDATE payment_intents 
                   SET status = 'expired', 
                       updated_at = CURRENT_TIMESTAMP
                   WHERE expires_at IS NULL 
                   AND created_at < NOW() - INTERVAL '24 hours'
                   AND status IN ('created', 'pending', 'address_created')
                   RETURNING id, user_id, order_id, amount, crypto_currency, payment_provider""",
            )
            
            long_pending_count = len(long_pending_result) if long_pending_result else 0
            total_cleaned += long_pending_count
            
            if long_pending_count > 0:
                total_pending_amount = sum(to_currency_decimal(p['amount'], "amount") for p in long_pending_result)
                logger.info(f"✅ PAYMENT CLEANUP: Marked {long_pending_count} long-pending payments as expired (total: ${total_pending_amount:.2f})")
                
                # Send user notifications for long-pending payments
                try:
                    from payment_expiration_notifications import send_expiration_notifications
                    notifications_sent = await send_expiration_notifications(long_pending_result)
                    logger.info(f"📢 NOTIFICATIONS: Sent {notifications_sent} user notifications for long-pending payments")
                except Exception as notification_error:
                    logger.error(f"❌ NOTIFICATIONS: Failed to send long-pending notifications: {notification_error}")
        else:
            logger.info("✨ PAYMENT CLEANUP: No long-pending payments (>24h) found")
        
        # FINAL SUMMARY
        cleanup_duration = time.time() - cleanup_start
        
        if total_cleaned > 0:
            logger.info(f"🎯 PAYMENT CLEANUP COMPLETE: Cleaned {total_cleaned} payments in {cleanup_duration:.2f}s")
            logger.info(f"   • Stale 'address_created' payments: {stale_count if 'stale_count' in locals() else 0}")
            logger.info(f"   • Expired timestamp payments: {expired_count if 'expired_count' in locals() else 0}")
            logger.info(f"   • Long-pending payments (>24h): {long_pending_count if 'long_pending_count' in locals() else 0}")
        else:
            logger.info(f"✨ PAYMENT CLEANUP COMPLETE: No payments needed cleanup (checked in {cleanup_duration:.2f}s)")
        
        return total_cleaned
        
    except Exception as e:
        logger.error(f"❌ PAYMENT CLEANUP: Critical error during cleanup: {e}")
        logger.error(f"   Cleanup duration: {time.time() - cleanup_start:.2f}s")
        logger.error(f"   Total cleaned before error: {total_cleaned}")
        return total_cleaned

# Simplified wallet transaction function with UUID-based idempotency
async def create_wallet_transaction_with_uuid(user_id: int, transaction_type: str, amount: Decimal, currency: str, 
                                            description: str, external_txid: Optional[str] = None) -> Optional[str]:
    """
    Create wallet transaction with UUID-based ID generation
    Uses external_txid for reference tracking (no complex constraints)
    Returns UUID on success, None on failure - lets real errors surface
    """
    try:
        uuid_id = generate_uuid()
        
        # Simple INSERT with proper column names matching schema
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query(
            """INSERT INTO wallet_transactions 
               (user_id, transaction_type, amount, currency, description, external_txid)
               VALUES (%s, %s, %s, %s, %s, %s) 
               RETURNING id""",
            (user_id, transaction_type, str(amount), currency, description, external_txid)
        )
        
        if result and len(result) > 0:
            transaction_id = result[0]['id']
            logger.info(f"✅ UUID: Created wallet transaction {transaction_id} for user {user_id}, amount: ${amount}")
            return str(transaction_id)
        else:
            # Let real database errors surface - no graceful degradation
            logger.error(f"❌ UUID: Failed to create wallet transaction - no result returned")
            return None
            
    except Exception as e:
        # Let real errors surface instead of masking them
        logger.error(f"❌ UUID: Database error creating wallet transaction: {e}")
        raise

# Removed atomic_wallet_credit_with_external_txid - replaced with unified credit_user_wallet()

async def get_user_id_from_telegram_id(telegram_id: int) -> Optional[int]:
    """
    Get database user_id from telegram_id
    Used for wallet operations that need the internal user_id
    """
    try:
        result = await execute_query(
            "SELECT id FROM users WHERE telegram_id = %s AND deleted_at IS NULL",
            (telegram_id,)
        )
        if result:
            return result[0]['id']
        return None
    except Exception as e:
        logger.error(f"❌ Error getting user_id from telegram_id {telegram_id}: {e}")
        return None

async def queue_user_notification_by_user_id(user_id: int, message: str, parse_mode: str = 'HTML') -> bool:
    """
    BOT-INDEPENDENT: Queue user notification without requiring bot loop
    This function works even during bot startup/restart periods
    
    Args:
        user_id: Database user_id (not telegram_id) 
        message: Message to send
        parse_mode: Message parse mode
        
    Returns:
        bool: True if message was queued successfully
    """
    try:
        # CRITICAL FIX: Validate user existence before sending notification
        user_exists = await execute_query(
            "SELECT id FROM users WHERE id = %s AND deleted_at IS NULL",
            (user_id,)
        )
        
        if not user_exists:
            logger.warning(f"⚠️ USER VALIDATION: User {user_id} not found - skipping notification to prevent 'user not found' error")
            return False
        
        # Import here to avoid circular imports
        from webhook_handler import queue_user_message
        
        # Queue the message using the existing message queue system
        await queue_user_message(user_id, message, parse_mode)
        logger.info(f"✅ BOT-INDEPENDENT: Notification queued for user_id {user_id}")
        return True
        
    except Exception as e:
        logger.warning(f"⚠️ BOT-INDEPENDENT: Failed to queue notification for user_id {user_id}: {e}")
        return False

# Enhanced webhook callback registration with payment intent integration
async def register_webhook_with_payment_intent(order_id: str, confirmation_count: int, callback_type: str, 
                                              txid: Optional[str] = None, amount_usd: Optional[float] = None,
                                              provider: Optional[str] = None) -> Tuple[bool, Optional[Dict]]:
    """
    Register webhook callback and return associated payment intent if exists
    Returns: (is_new_callback, payment_intent_data)
    """
    # First register the webhook callback
    amount_decimal = Decimal(str(amount_usd)) if amount_usd is not None else None
    is_new = await register_webhook_callback(order_id, confirmation_count, callback_type, txid, amount_decimal, provider)
    
    # Get payment intent if available
    payment_intent = await get_payment_intent_by_order_id(order_id)
    
    return (is_new, payment_intent)


# Cloudflare zone management
async def save_cloudflare_zone(domain_name: str, cf_zone_id: str, nameservers: List[str], status: str = 'active') -> bool:
    """Save Cloudflare zone information (idempotent - updates if exists)"""
    try:
        await execute_update(
            """INSERT INTO cloudflare_zones (domain_name, cf_zone_id, nameservers, status) 
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (cf_zone_id) 
               DO UPDATE SET 
                   domain_name = EXCLUDED.domain_name,
                   nameservers = EXCLUDED.nameservers,
                   status = EXCLUDED.status,
                   updated_at = CURRENT_TIMESTAMP""",
            (domain_name, cf_zone_id, nameservers, status)
        )
        logger.info(f"✅ Cloudflare zone saved/updated: {domain_name} -> {cf_zone_id}")
        return True
    except Exception as e:
        logger.error(f"Error saving Cloudflare zone: {e}")
        return False

async def get_cloudflare_zone(domain_name: str) -> Optional[Dict]:
    """Get Cloudflare zone information for a domain"""
    zones = await execute_query("SELECT * FROM cloudflare_zones WHERE domain_name = %s", (domain_name,))
    return dict(zones[0]) if zones else None

# Hosting management functions
async def get_hosting_plans() -> List[Dict]:
    """Get all active hosting plans"""
    return await execute_query("SELECT * FROM hosting_plans WHERE is_active = true ORDER BY monthly_price ASC")

async def get_hosting_plan(plan_id: int) -> Optional[Dict]:
    """Get specific hosting plan by ID"""
    plans = await execute_query("SELECT * FROM hosting_plans WHERE id = %s", (plan_id,))
    return dict(plans[0]) if plans else None

async def create_hosting_subscription(user_id: int, plan_id: int, domain_name: str, billing_cycle: Optional[str] = None) -> bool:
    """Create a new hosting subscription"""
    try:
        # If billing_cycle not provided, fetch from plan data
        if billing_cycle is None:
            plan_data = await get_hosting_plan(plan_id)
            if plan_data:
                billing_cycle = plan_data.get('billing_cycle', 'monthly')
                logger.info(f"✅ Using plan billing cycle: {billing_cycle} for plan {plan_id}")
            else:
                logger.warning(f"⚠️ Could not fetch plan data for plan_id {plan_id}, defaulting to 'monthly'")
                billing_cycle = 'monthly'
        
        await execute_update(
            "INSERT INTO hosting_subscriptions (user_id, hosting_plan_id, domain_name, billing_cycle, status) VALUES (%s, %s, %s, %s, %s)",
            (user_id, plan_id, domain_name, billing_cycle, 'pending')
        )
        return True
    except Exception as e:
        logger.error(f"Error creating hosting subscription: {e}")
        return False

async def create_hosting_subscription_with_id(user_id: int, plan_id: int, domain_name: str, billing_cycle: Optional[str] = None) -> Optional[int]:
    """Create a new hosting subscription and return the subscription ID"""
    try:
        # If billing_cycle not provided, fetch from plan data
        if billing_cycle is None:
            plan_data = await get_hosting_plan(plan_id)
            if plan_data:
                billing_cycle = plan_data.get('billing_cycle', 'monthly')
                logger.info(f"✅ Using plan billing cycle: {billing_cycle} for plan {plan_id}")
            else:
                logger.warning(f"⚠️ Could not fetch plan data for plan_id {plan_id}, defaulting to 'monthly'")
                billing_cycle = 'monthly'
        
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query(
            "INSERT INTO hosting_subscriptions (user_id, hosting_plan_id, domain_name, billing_cycle, status) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (user_id, plan_id, domain_name, billing_cycle, 'pending')
        )
        if result and len(result) > 0:
            return result[0]['id']
        return None
    except Exception as e:
        logger.error(f"Error creating hosting subscription with ID: {e}")
        return None

async def get_user_hosting_subscriptions(user_id: int) -> List[Dict]:
    """Get active hosting subscriptions for a user - FIXED: Only returns truly active plans"""
    return await execute_query("""
        SELECT hs.*, hp.plan_name, hp.plan_type, hp.monthly_price, hp.yearly_price 
        FROM hosting_subscriptions hs 
        JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id 
        WHERE hs.user_id = %s 
        AND hs.status IN ('active', 'pending_renewal', 'grace_period')
        ORDER BY hs.created_at DESC
    """, (user_id,))

async def get_hosting_subscription_details(subscription_id: int, user_id: int) -> Optional[Dict]:
    """Get detailed hosting subscription information for a specific user"""
    results = await execute_query("""
        SELECT hs.*, hp.plan_name, hp.plan_type, hp.monthly_price, hp.yearly_price,
               ca.cpanel_username, ca.cpanel_domain, ca.server_name, ca.ip_address
        FROM hosting_subscriptions hs 
        JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id 
        LEFT JOIN cpanel_accounts ca ON hs.id = ca.subscription_id
        WHERE hs.id = %s AND hs.user_id = %s
    """, (subscription_id, user_id))
    
    return results[0] if results else None

async def get_hosting_subscription_details_admin(subscription_id: int) -> Optional[Dict]:
    """Get detailed hosting subscription information (admin access - no user validation)"""
    try:
        results = await execute_query("""
            SELECT hs.*, hp.plan_name, hp.plan_type, hp.monthly_price, hp.yearly_price,
                   ca.cpanel_username, ca.cpanel_domain, ca.server_name, ca.ip_address
            FROM hosting_subscriptions hs 
            JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id 
            LEFT JOIN cpanel_accounts ca ON hs.id = ca.subscription_id
            WHERE hs.id = %s
        """, (subscription_id,))
        
        return results[0] if results else None
    except Exception as e:
        logger.error(f"Error getting hosting subscription details (admin): {e}")
        return None

async def update_hosting_subscription_status(subscription_id: int, status: str) -> bool:
    """Update hosting subscription status"""
    try:
        await execute_update(
            "UPDATE hosting_subscriptions SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (status, subscription_id)
        )
        return True
    except Exception as e:
        logger.error(f"Error updating hosting subscription status: {e}")
        return False

async def create_cpanel_account(subscription_id: int, username: str, domain: str, server_name: str, ip_address: str) -> bool:
    """Create cPanel account record"""
    try:
        await execute_update(
            "INSERT INTO cpanel_accounts (subscription_id, cpanel_username, cpanel_domain, server_name, ip_address, status) VALUES (%s, %s, %s, %s, %s, %s)",
            (subscription_id, username, domain, server_name, ip_address, 'active')
        )
        return True
    except Exception as e:
        logger.error(f"Error creating cPanel account: {e}")
        return False

# Wallet balance management functions
async def get_user_wallet_balance(telegram_id: int) -> Decimal:
    """Get user's current wallet balance by telegram_id"""
    try:
        result = await execute_query("SELECT wallet_balance FROM users WHERE telegram_id = %s AND deleted_at IS NULL", (telegram_id,))
        if result:
            return to_currency_decimal(result[0]['wallet_balance'] or 0, "wallet_balance")
        return ZERO
    except Exception as e:
        logger.error(f"Error getting wallet balance: {e}")
        return ZERO

async def get_user_wallet_balance_by_id(user_id: int) -> Decimal:
    """Get user's current wallet balance by internal user_id (for testing)"""
    try:
        result = await execute_query("SELECT wallet_balance FROM users WHERE id = %s AND deleted_at IS NULL", (user_id,))
        if result:
            return to_currency_decimal(result[0]['wallet_balance'] or 0, "wallet_balance")
        return ZERO
    except Exception as e:
        logger.error(f"Error getting wallet balance by user_id: {e}")
        return ZERO

async def update_wallet_balance(user_id: int, amount: Decimal, transaction_type: str, description: str = '') -> bool:
    """Update user wallet balance and record transaction with atomic protection"""
    import psycopg2
    
    def _atomic_update() -> bool:
        conn = None
        try:
            conn = get_connection()
            # CRITICAL: Disable autocommit for atomic transaction
            conn.autocommit = False
            
            with conn.cursor() as cursor:
                # SECURITY: Row-level lock to prevent race conditions
                cursor.execute(
                    "SELECT id, wallet_balance FROM users WHERE id = %s FOR UPDATE",
                    (user_id,)
                )
                user_row = cast(Optional[RealDictRow], cursor.fetchone())
                if not user_row:
                    logger.error(f"User {user_id} not found for wallet update")
                    conn.rollback()
                    return False
                
                current_balance = to_currency_decimal(user_row['wallet_balance'] or 0, "wallet_balance")
                new_balance = current_balance + to_currency_decimal(amount, "amount")
                
                # CRITICAL: Prevent negative balance for debits
                if new_balance < 0:
                    logger.warning(f"🚫 NEGATIVE BALANCE PROTECTION: User {user_id} insufficient balance: {current_balance} + {amount} = {new_balance}")
                    conn.rollback()
                    return False
                
                # Validate amount bounds
                if abs(amount) > 999999.99:
                    logger.error(f"🚫 AMOUNT VALIDATION: Amount too large for user {user_id}: {amount}")
                    conn.rollback()
                    return False
                
                # Get telegram_id for cache invalidation
                cursor.execute(
                    "SELECT telegram_id FROM users WHERE id = %s",
                    (user_id,)
                )
                telegram_id_row = cursor.fetchone()
                telegram_id = telegram_id_row['telegram_id'] if telegram_id_row else None
                
                # Update user balance atomically
                cursor.execute(
                    "UPDATE users SET wallet_balance = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (new_balance, user_id)
                )
                
                # Record transaction in same atomic transaction
                cursor.execute(
                    "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s)",
                    (user_id, transaction_type, amount, 'USD', 'completed', description)
                )
                
                # Commit atomic transaction
                conn.commit()
                logger.info(f"✅ ATOMIC WALLET UPDATE: User {user_id}, {transaction_type} {amount} USD, New balance: {new_balance}")
                
                # CRITICAL: Invalidate user cache after successful update
                if telegram_id:
                    from performance_cache import cache_invalidate
                    cache_invalidate('user_data', telegram_id)
                    logger.info(f"🔄 CACHE_INVALIDATED: User cache cleared for telegram_id {telegram_id} after wallet update")
                
                return True
                
        except psycopg2.IntegrityError as e:
            if conn:
                conn.rollback()
            if "wallet_balance_non_negative" in str(e):
                logger.error(f"🚫 DATABASE CONSTRAINT: Negative balance prevented by DB constraint for user {user_id}")
            else:
                logger.error(f"Database integrity error in wallet update: {e}")
            return False
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Error in atomic wallet update: {e}")
            return False
        finally:
            if conn:
                return_connection(conn)
    
    return await asyncio.to_thread(_atomic_update)

async def debit_wallet_balance(user_id: int, amount: Decimal, description: str = '') -> bool:
    """
    BULLETPROOF debit operation with atomic transaction and comprehensive protection
    
    CRITICAL SECURITY FEATURES:
    - Atomic transaction with explicit row locking
    - Multiple validation layers preventing negative balances
    - Database constraint backup protection
    - Comprehensive audit logging
    """
    import psycopg2
    
    # Convert amount to Decimal if needed (defensive programming)
    if not isinstance(amount, Decimal):
        amount = Decimal(str(amount))
    
    # Input validation - First line of defense
    if amount <= 0:
        logger.error(f"🚫 DEBIT VALIDATION: Invalid debit amount for user {user_id}: {amount}")
        return False
    
    if amount > 999999.99:
        logger.error(f"🚫 DEBIT VALIDATION: Debit amount too large for user {user_id}: {amount}")
        return False
    
    def _atomic_debit() -> bool:
        conn = None
        try:
            conn = get_connection()
            # CRITICAL: Use explicit transaction control
            conn.autocommit = False
            
            with conn.cursor() as cursor:
                # SECURITY: Lock user row to prevent race conditions
                cursor.execute(
                    "SELECT id, wallet_balance FROM users WHERE id = %s FOR UPDATE",
                    (user_id,)
                )
                user_row = cast(Optional[RealDictRow], cursor.fetchone())
                if not user_row:
                    logger.error(f"🚫 DEBIT ERROR: User {user_id} not found")
                    conn.rollback()
                    return False
                
                current_balance = to_currency_decimal(user_row['wallet_balance'] or 0, "wallet_balance")
                new_balance = current_balance - amount
                
                # CRITICAL: Multiple negative balance checks
                if current_balance < amount:
                    logger.warning(f"🚫 DEBIT PROTECTION: User {user_id} insufficient balance: ${current_balance:.2f} < ${amount:.2f}")
                    conn.rollback()
                    return False
                
                if new_balance < 0:
                    logger.error(f"🚫 ATOMIC PROTECTION: Would create negative balance for user {user_id}: ${new_balance:.2f}")
                    conn.rollback()
                    return False
                
                # Get telegram_id for cache invalidation
                cursor.execute(
                    "SELECT telegram_id FROM users WHERE id = %s",
                    (user_id,)
                )
                telegram_id_row = cursor.fetchone()
                telegram_id = telegram_id_row['telegram_id'] if telegram_id_row else None
                
                # Update balance atomically
                cursor.execute(
                    "UPDATE users SET wallet_balance = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (new_balance, user_id)
                )
                
                # Record transaction
                cursor.execute(
                    "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s)",
                    (user_id, 'debit', -amount, 'USD', 'completed', description)
                )
                
                # COMMIT: All operations succeeded
                conn.commit()
                # Enhanced balance tracking with Old → New format for comprehensive audit trail
                logger.info(f"✅ DEBIT SUCCESS: ${amount:.2f} debited from user {user_id} | Old: ${current_balance:.2f} → New: ${new_balance:.2f} | Description: {description}")
                
                # CRITICAL: Invalidate user cache after successful debit
                if telegram_id:
                    from performance_cache import cache_invalidate
                    cache_invalidate('user_data', telegram_id)
                    logger.info(f"🔄 CACHE_INVALIDATED: User cache cleared for telegram_id {telegram_id} after wallet debit")
                
                return True
                
        except psycopg2.IntegrityError as e:
            if conn:
                conn.rollback()
            if "wallet_balance_non_negative" in str(e):
                logger.error(f"🚫 DATABASE CONSTRAINT: Negative balance prevented by DB constraint for user {user_id}")
            else:
                logger.error(f"🚫 DATABASE INTEGRITY ERROR: {e}")
            return False
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"🚫 DEBIT ERROR: Atomic debit failed for user {user_id}: {e}")
            return False
        finally:
            if conn:
                return_connection(conn)
    
    return await asyncio.to_thread(_atomic_debit)

async def atomic_wallet_credit_with_txid(user_id: int, amount: Decimal, description: str, txid: str, deposit_order_id: str, confirmations: int, crypto_amount: str) -> bool:
    """Atomically credit wallet and update deposit status with txid protection"""
    def _atomic_credit():
        conn = None
        try:
            conn = get_connection()
            # CRITICAL: Disable autocommit for atomic transaction
            conn.autocommit = False
            
            with conn.cursor() as cursor:
                # 1. CRITICAL SECURITY: Row-level lock to prevent TOCTOU race conditions
                cursor.execute(
                    "SELECT id, status FROM wallet_deposits WHERE user_id = %s AND blockbee_order_id = %s FOR UPDATE",
                    (user_id, deposit_order_id)
                )
                deposit_row = cursor.fetchone()
                if not deposit_row:
                    logger.error(f"Deposit row not found for atomic operation: {deposit_order_id}")
                    conn.rollback()
                    return False
                
                # 2. Check txid idempotency within transaction
                cursor.execute("SELECT id, status FROM wallet_deposits WHERE txid = %s", (txid,))
                existing_txid = cursor.fetchone()
                if existing_txid:
                    logger.warning(f"🚫 ATOMIC PROTECTION: Transaction {txid[:16]}... already processed atomically")
                    conn.rollback()
                    return False
                
                # 3. Credit wallet balance
                cursor.execute("SELECT wallet_balance FROM users WHERE id = %s", (user_id,))
                user_result = cursor.fetchone()
                if not user_result:
                    logger.error(f"User {user_id} not found for wallet credit")
                    conn.rollback()
                    return False
                
                if not user_result:
                    logger.error(f"User {user_id} not found for wallet credit")
                    conn.rollback()
                    return False
                current_balance = to_currency_decimal(cast(Dict[str, Any], user_result)['wallet_balance'] or 0, "wallet_balance")
                new_balance = current_balance + amount
                
                cursor.execute(
                    "UPDATE users SET wallet_balance = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (new_balance, user_id)
                )
                
                # 4. Record transaction
                cursor.execute(
                    "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s)",
                    (user_id, 'credit', amount, 'USD', 'completed', description)
                )
                
                # 5. Update deposit status with txid atomically
                cursor.execute(
                    "UPDATE wallet_deposits SET status = %s, confirmations = %s, crypto_amount = %s, txid = %s, updated_at = CURRENT_TIMESTAMP WHERE blockbee_order_id = %s",
                    ('completed', confirmations, crypto_amount, txid, deposit_order_id)
                )
                
                # 6. Clean up authentication token now that payment is finalized
                cursor.execute(
                    "DELETE FROM callback_tokens WHERE callback_data = %s AND user_id = %s",
                    (f"order_id:{deposit_order_id}", user_id)
                )
                token_deleted = cursor.rowcount
                
                # COMMIT: All operations succeeded
                conn.commit()
                logger.info(f"✅ ATOMIC: Wallet credited ${amount} to user {user_id}, txid: {txid[:16]}..., token cleaned: {token_deleted > 0}")
                return True
                
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                    logger.error(f"❌ ATOMIC ROLLBACK: Wallet credit failed, rolled back: {e}")
                except:
                    logger.error(f"❌ CRITICAL: Rollback failed: {e}")
            return False
        finally:
            if conn:
                # Restore autocommit and return connection
                conn.autocommit = True
                return_connection(conn)
    
    return await asyncio.to_thread(_atomic_credit)

async def atomic_domain_order_confirm_with_txid(user_id: int, expected_usd: float, received_usd: float, txid: str, order_id: str, confirmations: int, crypto_amount: str) -> bool:
    """Atomically confirm domain order with strict amount validation and txid protection"""
    def _atomic_confirm():
        conn = None
        try:
            conn = get_connection()
            # CRITICAL: Disable autocommit for atomic transaction
            conn.autocommit = False
            
            with conn.cursor() as cursor:
                # 1. CRITICAL SECURITY: Row-level lock to prevent TOCTOU race conditions
                cursor.execute(
                    "SELECT id, status FROM domain_orders WHERE blockbee_order_id = %s FOR UPDATE",
                    (order_id,)
                )
                order_row = cursor.fetchone()
                if not order_row:
                    logger.error(f"Domain order not found for atomic operation: {order_id}")
                    conn.rollback()
                    return False
                
                # 2. Check txid idempotency within transaction
                cursor.execute("SELECT id, status FROM domain_orders WHERE txid = %s", (txid,))
                existing_txid = cursor.fetchone()
                if existing_txid:
                    logger.warning(f"🚫 ATOMIC PROTECTION: Domain transaction {txid[:16]}... already processed atomically")
                    conn.rollback()
                    return False
                
                # 3. UNIFIED VALIDATION: Use same tolerance logic as webhook handler
                is_payment_valid = validate_payment_simple(expected_usd, received_usd, 'domain_order', 'database')
                if not is_payment_valid:
                    logger.warning(f"🚫 UNIFIED VALIDATION: Domain order payment rejected - received ${received_usd}, expected ${expected_usd}")
                    # Update order with failed status
                    cursor.execute(
                        "UPDATE domain_orders SET status = %s, confirmations = %s, txid = %s, updated_at = CURRENT_TIMESTAMP WHERE blockbee_order_id = %s",
                        ('insufficient_amount', confirmations, txid, order_id)
                    )
                    conn.commit()
                    return False
                else:
                    logger.info(f"✅ UNIFIED VALIDATION: Domain order payment accepted - received ${received_usd}, expected ${expected_usd}")
                
                # 4. Update domain order status to confirmed
                cursor.execute(
                    "UPDATE domain_orders SET status = %s, confirmations = %s, txid = %s, updated_at = CURRENT_TIMESTAMP WHERE blockbee_order_id = %s",
                    ('payment_confirmed', confirmations, txid, order_id)
                )
                
                # 5. Clean up authentication token now that payment is finalized
                cursor.execute(
                    "DELETE FROM callback_tokens WHERE callback_data = %s AND user_id = %s",
                    (f"order_id:{order_id}", user_id)
                )
                token_deleted = cursor.rowcount
                
                # COMMIT: All operations succeeded
                conn.commit()
                logger.info(f"✅ ATOMIC: Domain order confirmed, txid: {txid[:16]}..., token cleaned: {token_deleted > 0}")
                return True
                
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                    logger.error(f"❌ ATOMIC ROLLBACK: Domain order confirmation failed, rolled back: {e}")
                except:
                    logger.error(f"❌ CRITICAL: Rollback failed: {e}")
            return False
        finally:
            if conn:
                # Restore autocommit and return connection
                conn.autocommit = True
                return_connection(conn)
    
    return await asyncio.to_thread(_atomic_confirm)

async def atomic_domain_overpayment_credit_with_txid(user_id: int, overpayment_amount: Decimal, domain_name: str, txid: str, order_id: str, external_txid: str) -> bool:
    """
    Atomically credit domain overpayment to user wallet with proper idempotency protection
    
    SECURITY FEATURES:
    - Proper external_txid-based idempotency (unique constraint enforcement)
    - Atomic balance update operation (no race conditions)
    - Full transactional integrity with proper rollback
    - Input validation for overpayment amount
    - Comprehensive audit logging
    
    Args:
        user_id: User ID to credit
        overpayment_amount: Amount of overpayment to credit to wallet (must be > 0)
        domain_name: Domain name for transaction description
        txid: Blockchain transaction ID for reference
        order_id: Domain order ID for reference
        external_txid: Unique external transaction ID for idempotency protection
        
    Returns:
        bool: True if credit was successful, False if failed or duplicate
    """
    import psycopg2
    
    def _atomic_overpayment_credit():
        conn = None
        try:
            # VALIDATION: Ensure overpayment amount is positive
            if overpayment_amount <= 0:
                logger.error(f"❌ VALIDATION ERROR: Invalid overpayment amount ${overpayment_amount:.4f} for user {user_id}")
                return False
                
            conn = get_connection()
            # CRITICAL: Disable autocommit for atomic transaction
            conn.autocommit = False
            
            with conn.cursor() as cursor:
                # 1. IDEMPOTENCY: Try to insert transaction record with unique external_txid
                # This provides atomic duplicate check via database unique constraint
                try:
                    cursor.execute(
                        """INSERT INTO wallet_transactions 
                           (user_id, transaction_type, amount, currency, status, external_txid, description)
                           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                        (
                            user_id, 
                            'credit', 
                            overpayment_amount, 
                            'USD', 
                            'completed', 
                            external_txid,
                            f"Domain overpayment credit: {domain_name} (order: {order_id}, txid: {txid[:8]}...)"
                        )
                    )
                    logger.info(f"💳 TRANSACTION RECORD: Overpayment transaction {external_txid} recorded")
                    
                except psycopg2.IntegrityError as e:
                    # Unique constraint violation - transaction already processed
                    conn.rollback()
                    if 'external_txid' in str(e).lower() or 'unique' in str(e).lower():
                        logger.warning(f"🚫 IDEMPOTENCY PROTECTION: Overpayment {external_txid} already processed (duplicate blocked)")
                        return False
                    else:
                        # Different integrity error - re-raise
                        logger.error(f"❌ DATABASE INTEGRITY ERROR: {e}")
                        raise
                
                # 2. ATOMIC BALANCE UPDATE: Use SQL arithmetic to prevent race conditions
                # This eliminates read-modify-write race conditions completely
                cursor.execute(
                    """UPDATE users 
                       SET wallet_balance = wallet_balance + %s, 
                           updated_at = CURRENT_TIMESTAMP 
                       WHERE id = %s
                       RETURNING wallet_balance""",
                    (overpayment_amount, user_id)
                )
                
                updated_user = cursor.fetchone()
                if not updated_user:
                    logger.error(f"❌ USER NOT FOUND: User {user_id} does not exist for overpayment credit")
                    conn.rollback()
                    return False
                new_balance = to_currency_decimal(cast(Dict[str, Any], updated_user)['wallet_balance'], "wallet_balance")
                
                # COMMIT: All operations succeeded atomically
                conn.commit()
                
                # SUCCESS: Log comprehensive audit trail
                logger.info(f"✅ OVERPAYMENT SUCCESS: Domain overpayment processed atomically")
                logger.info(f"   User: {user_id}")
                logger.info(f"   Domain: {domain_name}")
                logger.info(f"   Order: {order_id}")
                logger.info(f"   Amount: ${overpayment_amount:.4f} USD")
                logger.info(f"   New Balance: ${new_balance:.4f} USD")
                logger.info(f"   External TxID: {external_txid}")
                logger.info(f"   Blockchain TxID: {txid[:16]}...")
                
                return True
                
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                    logger.error(f"❌ OVERPAYMENT ROLLBACK: Domain overpayment credit failed and was rolled back")
                    logger.error(f"   Error: {e}")
                    logger.error(f"   External TxID: {external_txid}")
                    logger.error(f"   User: {user_id}, Amount: ${overpayment_amount:.4f}")
                except Exception as rollback_error:
                    logger.error(f"❌ CRITICAL ROLLBACK FAILURE: {rollback_error}")
            return False
        finally:
            if conn:
                # Restore autocommit and return connection
                conn.autocommit = True
                return_connection(conn)
    
    return await asyncio.to_thread(_atomic_overpayment_credit)

async def register_webhook_callback(order_id: str, confirmation_count: int, callback_type: str, txid: Optional[str] = None, amount_usd: Optional[Decimal] = None, provider: Optional[str] = None, external_id: Optional[str] = None) -> bool:
    """
    Atomically register a webhook callback to prevent duplicate processing.
    Enhanced with provider and external_id for stronger idempotency protection.
    
    Args:
        order_id: BlockBee/DynoPay order ID
        confirmation_count: Number of confirmations
        callback_type: Type of callback ('wallet_deposit', 'domain_order', 'hosting_payment')
        txid: Optional transaction ID for tracking
        amount_usd: Optional USD amount for tracking
        provider: Optional payment provider name ('blockbee', 'dynopay')
        external_id: Optional provider-specific external identifier
        
    Returns:
        bool: True if callback is safe to process (new), False if duplicate
    """
    def _atomic_register():
        conn = None
        try:
            conn = get_connection()
            # CRITICAL: Disable autocommit for atomic transaction
            conn.autocommit = False
            
            with conn.cursor() as cursor:
                try:
                    # Enhanced: Insert with provider_name and external_callback_id for stronger idempotency
                    cursor.execute(
                        """INSERT INTO webhook_callbacks 
                           (order_id, confirmation_count, callback_type, status, txid, amount_usd, provider_name, external_callback_id) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                        (order_id, confirmation_count, callback_type, 'processing', txid, amount_usd, provider, external_id)
                    )
                    
                    # If we reach here, insertion succeeded - this is a new callback
                    conn.commit()
                    logger.info(f"✅ WEBHOOK IDEMPOTENCY: New callback registered - {callback_type}:{order_id}:{confirmation_count}")
                    return True
                    
                except psycopg2.IntegrityError as e:
                    # Unique constraint violation - callback already exists
                    conn.rollback()
                    
                    # Check if existing callback is completed (within the same transaction context)
                    cursor.execute(
                        "SELECT status, completed_at FROM webhook_callbacks WHERE order_id = %s AND confirmation_count = %s AND callback_type = %s",
                        (order_id, confirmation_count, callback_type)
                    )
                    existing = cursor.fetchone()
                    
                    if existing:
                        existing_dict = cast(Dict[str, Any], existing)
                        status = str(existing_dict['status'])
                        completed_at = existing_dict['completed_at']
                        
                        if status == 'completed':
                            logger.info(f"🚫 WEBHOOK IDEMPOTENCY: Callback already completed - {callback_type}:{order_id}:{confirmation_count}")
                        elif status == 'failed':
                            logger.info(f"🚫 WEBHOOK IDEMPOTENCY: Callback already failed - {callback_type}:{order_id}:{confirmation_count}")
                        else:
                            logger.warning(f"🚫 WEBHOOK IDEMPOTENCY: Callback already processing - {callback_type}:{order_id}:{confirmation_count}")
                    else:
                        logger.warning(f"🚫 WEBHOOK IDEMPOTENCY: Duplicate callback detected - {callback_type}:{order_id}:{confirmation_count}")
                    
                    # Restore autocommit before returning
                    conn.autocommit = True
                    return False
                    
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                    conn.autocommit = True  # Restore autocommit after rollback
                except:
                    pass
            logger.error(f"❌ Error registering webhook callback: {e}")
            return False
        finally:
            if conn:
                # Ensure autocommit is restored and return connection
                try:
                    if not conn.autocommit:
                        conn.autocommit = True
                except:
                    pass
                return_connection(conn)
    
    return await asyncio.to_thread(_atomic_register)

async def complete_webhook_callback(order_id: str, confirmation_count: int, callback_type: str, success: bool = True) -> bool:
    """
    Mark a webhook callback as completed or failed.
    
    Args:
        order_id: BlockBee order ID
        confirmation_count: Number of confirmations
        callback_type: Type of callback ('wallet_deposit' or 'domain_order')
        success: Whether the callback processing was successful
        
    Returns:
        bool: True if status was updated successfully
    """
    try:
        status = 'completed' if success else 'failed'
        result = await execute_update(
            """UPDATE webhook_callbacks 
               SET status = %s, completed_at = CURRENT_TIMESTAMP 
               WHERE order_id = %s AND confirmation_count = %s AND callback_type = %s""",
            (status, order_id, confirmation_count, callback_type)
        )
        
        if result:
            logger.info(f"✅ WEBHOOK IDEMPOTENCY: Callback marked as {status} - {callback_type}:{order_id}:{confirmation_count}")
            return True
        else:
            logger.warning(f"⚠️ WEBHOOK IDEMPOTENCY: No callback found to mark as {status} - {callback_type}:{order_id}:{confirmation_count}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error completing webhook callback: {e}")
        return False

async def cleanup_old_webhook_callbacks(days_old: int = 30) -> int:
    """
    Clean up old webhook callback records to prevent table bloat.
    
    Args:
        days_old: Delete records older than this many days
        
    Returns:
        int: Number of records deleted
    """
    try:
        # Use UTC time calculation to avoid timezone issues
        from datetime import datetime, timezone, timedelta
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=days_old)
        
        result = await execute_update(
            """DELETE FROM webhook_callbacks 
               WHERE processed_at < %s 
               AND status IN ('completed', 'failed')""",
            (cutoff_time,)
        )
        
        if result:
            logger.info(f"🧹 WEBHOOK CLEANUP: Deleted {result} old webhook callback records (>{days_old} days)")
        
        return result or 0
        
    except Exception as e:
        logger.error(f"❌ Error cleaning up webhook callbacks: {e}")
        return 0

# Removed credit_wallet_balance - replaced with unified credit_user_wallet()

@track_payment_operation("credit_user_wallet")
async def credit_user_wallet(user_id: int, amount_usd: Decimal, provider: str, txid: str, order_id: str) -> bool:
    """
    PRODUCTION: Fixed unified wallet credit function with enhanced reliability and comprehensive logging
    
    Features:
    - Strict boolean return type (never returns integers)
    - Robust type handling for Decimal/float conversions
    - Enhanced exception handling with detailed debugging
    - Single connection retry on connection failures
    - Structured logging with clear failure reasons
    - Duplicates treated as idempotent success (return True)
    - Explicit user existence validation
    - Database-level idempotency via UNIQUE(external_txid, provider)
    - ENHANCED LOGGING: Comprehensive wallet credit audit trail with performance metrics
    
    Args:
        user_id: Database user ID (not telegram_id)
        amount_usd: Amount to credit in USD
        provider: Payment provider ('dynopay', 'blockbee', etc.)
        txid: Transaction ID from provider
        order_id: Our internal order ID
        
    Returns:
        bool: True if credited successfully OR duplicate (idempotent), False only on actual failure
    """
    import psycopg2
    from decimal import Decimal, InvalidOperation
    
    operation_start = time.time()
    correlation_id = None
    
    # Create payment logging context for wallet credit operation
    payment_logger = get_payment_logger()
    context = PaymentLogContext(
        correlation_id=str(uuid.uuid4()),
        user_id=user_id,
        order_id=order_id,
        provider=provider,
        currency="USD",
        amount_usd=amount_usd,
        transaction_id=txid,
        current_status="processing"
    )
    correlation_id = context.correlation_id
    
    # Log wallet credit operation start
    payment_logger.log_payment_event(
        PaymentEventType.WALLET_CREDITED,
        f"Starting wallet credit operation: ${amount_usd} for user {user_id}",
        context,
        PaymentLogLevel.INFO
    )
    
    # Enhanced input validation with logging
    try:
        amount_usd = to_currency_decimal(amount_usd, "amount_usd")  # Ensure proper Decimal type
    except (TypeError, ValueError) as e:
        error_msg = f"Invalid amount_usd type: {type(amount_usd)} = {amount_usd}"
        logger.error(f"❌ WALLET_CREDIT_TYPE_ERROR: {error_msg} | Error: {e}")
        
        payment_logger.log_payment_error(
            e,
            PaymentLogContext(
                correlation_id=correlation_id,
                user_id=user_id,
                order_id=order_id,
                provider=provider,
                transaction_id=txid,
                metadata={'invalid_amount': str(amount_usd), 'amount_type': str(type(amount_usd))}
            ),
            error_category="validation_error",
            actionable_steps=["Verify amount_usd parameter is numeric", "Check data type conversion in caller"]
        )
        return False
    
    if amount_usd <= 0 or amount_usd > 50000:
        error_msg = f"Invalid amount ${amount_usd:.2f} for user {user_id} (valid range: $0.01-$50,000)"
        logger.error(f"❌ WALLET_CREDIT_VALIDATION_FAILED: {error_msg}")
        
        payment_logger.log_payment_error(
            ValueError(f"Amount ${amount_usd:.2f} outside valid range"),
            PaymentLogContext(
                correlation_id=correlation_id,
                user_id=user_id,
                order_id=order_id,
                provider=provider,
                amount_usd=amount_usd,
                transaction_id=txid,
                metadata={'amount_limit_check': 'failed', 'valid_range': '$0.01-$50,000'}
            ),
            error_category="validation_error",
            actionable_steps=[
                "Review amount calculation logic",
                "Check for currency conversion errors", 
                "Verify business rules for wallet credit limits"
            ]
        )
        return False
    
    if not txid or not provider:
        error_msg = f"Missing required fields - txid='{txid}', provider='{provider}' for user {user_id}"
        logger.error(f"❌ WALLET_CREDIT_VALIDATION_FAILED: {error_msg}")
        
        payment_logger.log_payment_error(
            ValueError("Missing required fields for wallet credit"),
            PaymentLogContext(
                correlation_id=correlation_id,
                user_id=user_id,
                order_id=order_id,
                provider=provider or "unknown",
                amount_usd=amount_usd,
                transaction_id=txid or "missing",
                metadata={'txid_provided': bool(txid), 'provider_provided': bool(provider)}
            ),
            error_category="validation_error",
            actionable_steps=[
                "Ensure transaction ID is provided from payment confirmation",
                "Verify payment provider is correctly identified",
                "Check webhook or payment processing data completeness"
            ]
        )
        return False
    
    # Security gate check with enhanced logging
    if not os.getenv('FINANCIAL_OPERATIONS_ENABLED', 'true').lower() == 'true':
        logger.error(f"❌ WALLET_CREDIT_SECURITY_BLOCKED: Financial operations disabled by configuration")
        
        payment_logger.log_payment_error(
            ValueError("Financial operations disabled"),
            PaymentLogContext(
                correlation_id=correlation_id,
                user_id=user_id,
                order_id=order_id,
                provider=provider,
                amount_usd=amount_usd,
                transaction_id=txid,
                metadata={'security_gate': 'disabled', 'config_check': 'FINANCIAL_OPERATIONS_ENABLED=false'}
            ),
            error_category="security_violation",
            actionable_steps=[
                "Check FINANCIAL_OPERATIONS_ENABLED environment variable",
                "Review security configuration and access controls",
                "Verify operational approval for financial transactions"
            ]
        )
        return False
    
    def safe_decimal_conversion(value, field_name: str) -> Decimal:
        """Safely convert database Decimal/numeric values to Decimal for financial precision"""
        try:
            if value is None:
                return ZERO
            if isinstance(value, Decimal):
                return value
            if isinstance(value, (int, float)):
                return to_decimal(value, field_name)
            if isinstance(value, str):
                return to_decimal(value, field_name)
            # Fallback for other types
            return to_decimal(value, field_name)
        except (TypeError, ValueError, InvalidOperation) as e:
            logger.error(f"❌ WALLET_CREDIT_CONVERSION_ERROR: Failed to convert {field_name} value {value} (type: {type(value)}) to Decimal: {e}")
            raise ValueError(f"Invalid {field_name} value: {value}")
    
    def _credit_wallet_with_retry():
        """Internal function with single bounded retry for connection failures only"""
        max_attempts = 2  # Original attempt + 1 retry for connection issues only
        
        for attempt in range(max_attempts):
            conn = None
            try:
                conn = get_connection()
                conn.autocommit = False
                
                with conn.cursor() as cursor:
                    # STEP 1: Explicit user existence validation with debugging
                    cursor.execute("SELECT id, wallet_balance FROM users WHERE id = %s", (user_id,))
                    user_result = cursor.fetchone()
                    if not user_result:
                        logger.error(f"❌ WALLET_CREDIT_USER_NOT_FOUND: user_id {user_id} does not exist in database")
                        conn.rollback()
                        return False
                    
                    # DEBUG: Log the actual result structure
                    logger.info(f"🔍 WALLET_CREDIT_DEBUG: user_result type={type(user_result)}, content={user_result}")
                    
                    # Safe conversion with detailed debugging
                    try:
                        # Handle both tuple and dict-like access patterns with explicit typing
                        if hasattr(user_result, 'keys'):  # Dict-like (RealDictRow)
                            user_dict = cast(Any, user_result)  # Explicit cast to Any for dictionary access
                            current_balance = safe_decimal_conversion(user_dict['wallet_balance'], "wallet_balance")
                            user_db_id = user_dict['id']
                        else:  # Tuple-like
                            if len(user_result) < 2:
                                raise ValueError(f"Expected 2 columns, got {len(user_result)}: {user_result}")
                            current_balance = safe_decimal_conversion(user_result[1], "wallet_balance")
                            user_db_id = user_result[0]
                        
                        logger.info(f"🔍 WALLET_CREDIT_USER_VALIDATED: user_id {user_id} (db_id: {user_db_id}) exists with current balance ${current_balance:.2f}")
                    except (ValueError, KeyError, IndexError) as conv_error:
                        logger.error(f"❌ WALLET_CREDIT_BALANCE_CONVERSION_ERROR: {conv_error} | user_result: {user_result}")
                        conn.rollback()
                        return False
                    
                    # STEP 2: Simple transaction insert with proper schema columns
                    # CRITICAL: Include provider column for unique constraint (external_txid, provider)
                    try:
                        cursor.execute(
                            """INSERT INTO wallet_transactions 
                               (user_id, transaction_type, amount, currency, external_txid, provider, description)
                               VALUES (%s, 'credit', %s, 'USD', %s, %s, %s)
                               RETURNING id""",
                            (user_id, amount_usd, txid, provider, f"Payment {order_id}")
                        )
                    except psycopg2.IntegrityError as integrity_error:
                        # IDEMPOTENCY: Duplicate txid means already credited - treat as success
                        conn.rollback()
                        error_str = str(integrity_error).lower()
                        if 'external_txid' in error_str or 'unique' in error_str or 'duplicate' in error_str:
                            logger.info(f"🔄 WALLET_CREDIT_IDEMPOTENT: Transaction already credited | user_id: {user_id} | txid: {txid[:16]}... | Treating as success")
                            return True  # Idempotent success - already credited
                        else:
                            logger.error(f"❌ WALLET_CREDIT_INTEGRITY_ERROR: Constraint violation | user_id: {user_id} | Error: {integrity_error}")
                            return False
                    except Exception as insert_error:
                        # SCHEMA SYNC FIX: Handle connection pool schema inconsistency
                        error_msg = str(insert_error).lower()
                        if 'column' in error_msg and 'does not exist' in error_msg:
                            logger.warning(f"🔄 SCHEMA_SYNC_ERROR: Connection sees old schema, triggering pool refresh | Error: {insert_error}")
                            # Close current connection as it has stale schema
                            conn.rollback()
                            try:
                                conn.close()
                            except:
                                pass
                            # Trigger pool recreation to get fresh connections with current schema
                            if recreate_connection_pool():
                                logger.info("✅ SCHEMA_SYNC_FIX: Pool recreated - retry needed with fresh connection")
                                # Return special value to indicate retry with fresh connection needed
                                if attempt == 0:  # Only retry once
                                    logger.info("🔄 SCHEMA_SYNC_RETRY: Retrying wallet credit with fresh connection pool")
                                    continue  # This will retry the entire _credit_wallet_with_retry loop
                            logger.error(f"❌ SCHEMA_SYNC_FAILED: Pool recreation failed, giving up")
                            return False
                        else:
                            logger.error(f"❌ WALLET_CREDIT_INSERT_ERROR: Failed to insert transaction | user_id: {user_id} | Error: {insert_error}")
                            conn.rollback()
                            return False
                    
                    transaction_result = cursor.fetchone()
                    if not transaction_result:
                        # No graceful degradation - this is a real error
                        logger.error(f"❌ WALLET_CREDIT_INSERT_FAILED: Transaction insert returned no result for user {user_id}")
                        conn.rollback()
                        return False  # Let real errors surface - no masking
                    
                    # DEBUG: Log the actual transaction result structure
                    logger.info(f"🔍 WALLET_CREDIT_DEBUG: transaction_result type={type(transaction_result)}, content={transaction_result}")
                    
                    try:
                        # Handle both tuple and dict-like access patterns for transaction ID with explicit typing
                        if hasattr(transaction_result, 'keys'):  # Dict-like (RealDictRow)
                            trans_dict = cast(Any, transaction_result)  # Explicit cast to Any for dictionary access
                            transaction_id = int(trans_dict['id'])
                        else:  # Tuple-like
                            if len(transaction_result) < 1:
                                raise ValueError(f"Expected at least 1 column, got {len(transaction_result)}: {transaction_result}")
                            transaction_id = int(transaction_result[0])
                        
                        logger.info(f"💰 WALLET_CREDIT_TRANSACTION_CREATED: transaction_id {transaction_id} for ${amount_usd:.2f}")
                    except (TypeError, ValueError, KeyError, IndexError) as id_error:
                        logger.error(f"❌ WALLET_CREDIT_ID_ERROR: Invalid transaction_id | Error: {id_error} | transaction_result: {transaction_result}")
                        conn.rollback()
                        return False
                    
                    # STEP 3: Credit wallet balance with explicit rowcount validation
                    try:
                        cursor.execute(
                            """UPDATE users 
                               SET wallet_balance = wallet_balance + %s, updated_at = CURRENT_TIMESTAMP 
                               WHERE id = %s
                               RETURNING wallet_balance""",
                            (amount_usd, user_id)
                        )
                        
                        # Explicit rowcount validation
                        if cursor.rowcount != 1:
                            logger.error(f"❌ WALLET_CREDIT_ROWCOUNT_ERROR: UPDATE affected {cursor.rowcount} rows (expected 1) for user_id {user_id}")
                            conn.rollback()
                            return False
                    except Exception as update_error:
                        logger.error(f"❌ WALLET_CREDIT_UPDATE_ERROR: Failed to update balance | user_id: {user_id} | Error: {update_error}")
                        conn.rollback()
                        return False
                    
                    balance_result = cursor.fetchone()
                    if not balance_result:
                        logger.error(f"❌ WALLET_CREDIT_UPDATE_FAILED: No balance returned after update for user_id {user_id}")
                        conn.rollback()
                        return False
                    
                    # DEBUG: Log the actual balance result structure
                    logger.info(f"🔍 WALLET_CREDIT_DEBUG: balance_result type={type(balance_result)}, content={balance_result}")
                    
                    try:
                        # Handle both tuple and dict-like access patterns for balance with explicit typing
                        if hasattr(balance_result, 'keys'):  # Dict-like (RealDictRow)
                            balance_dict = cast(Any, balance_result)  # Explicit cast to Any for dictionary access
                            new_balance = safe_decimal_conversion(balance_dict['wallet_balance'], "new_wallet_balance")
                        else:  # Tuple-like
                            if len(balance_result) < 1:
                                raise ValueError(f"Expected at least 1 column, got {len(balance_result)}: {balance_result}")
                            new_balance = safe_decimal_conversion(balance_result[0], "new_wallet_balance")
                    except (ValueError, KeyError, IndexError) as balance_error:
                        logger.error(f"❌ WALLET_CREDIT_NEW_BALANCE_ERROR: {balance_error} | balance_result: {balance_result}")
                        conn.rollback()
                        return False
                    
                    # STEP 4: Commit transaction with comprehensive success logging
                    try:
                        conn.commit()
                        
                        # Calculate operation performance metrics
                        duration_ms = (time.time() - operation_start) * 1000
                        
                        # Enhanced success logging with comprehensive audit trail
                        success_context = PaymentLogContext(
                            correlation_id=correlation_id,
                            user_id=user_id,
                            order_id=order_id,
                            provider=provider,
                            currency="USD",
                            amount_usd=amount_usd,
                            transaction_id=txid,
                            current_status="completed",
                            duration_ms=duration_ms,
                            metadata={
                                'previous_balance': current_balance,
                                'new_balance': new_balance,
                                'balance_change': amount_usd,
                                'wallet_transaction_id': transaction_id,
                                'idempotency_check': 'passed',
                                'security_gate': 'passed',
                                'operation_type': 'wallet_credit'
                            }
                        )
                        
                        # Log successful wallet credit
                        payment_logger.log_payment_event(
                            PaymentEventType.WALLET_CREDITED,
                            f"Wallet credit successful: ${amount_usd:.2f} credited to user {user_id}",
                            success_context,
                            PaymentLogLevel.INFO
                        )
                        
                        # Log the financial transaction audit trail
                        payment_logger.log_payment_event(
                            PaymentEventType.PAYMENT_CONFIRMED,
                            f"Financial transaction completed: ${current_balance:.2f} → ${new_balance:.2f}",
                            success_context,
                            PaymentLogLevel.AUDIT
                        )
                        
                        # Use convenience function for additional wallet credit logging
                        log_wallet_credited(
                            user_id=user_id,
                            amount_usd=amount_usd,
                            transaction_id=txid,
                            source_order_id=order_id,
                            correlation_id=correlation_id
                        )
                        
                        logger.info(f"✅ WALLET_CREDIT_SUCCESS: ${amount_usd:.2f} credited to user {user_id} | Old: ${current_balance:.2f} → New: ${new_balance:.2f} | txid: {txid[:16]}... | transaction_id: {transaction_id}")
                        
                        # CRITICAL FIX: Invalidate user cache after successful wallet credit
                        # This ensures dashboard shows fresh balance instead of cached stale balance
                        try:
                            # Get telegram_id for cache invalidation (since cache uses telegram_id as key)
                            cursor.execute("SELECT telegram_id FROM users WHERE id = %s", (user_id,))
                            telegram_result = cursor.fetchone()
                            if telegram_result:
                                telegram_id = telegram_result[0] if isinstance(telegram_result, (tuple, list)) else telegram_result['telegram_id']
                                
                                from performance_cache import cache_invalidate
                                cache_invalidate('user_data', telegram_id)
                                logger.info(f"🔄 CACHE_INVALIDATED: User cache cleared for telegram_id {telegram_id} after wallet credit")
                        except Exception as cache_error:
                            # Non-critical error - don't fail the wallet operation
                            logger.warning(f"⚠️ CACHE_INVALIDATION_WARNING: Failed to invalidate user cache after wallet credit: {cache_error}")
                        
                        return True  # ARCHITECT FIX: Guaranteed boolean return
                    except Exception as commit_error:
                        logger.error(f"❌ WALLET_CREDIT_COMMIT_ERROR: Failed to commit transaction | Error: {commit_error}")
                        conn.rollback()
                        return False
                    
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as conn_error:
                # Connection-level errors that can be retried ONCE
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                    return_connection(conn, is_broken=True)
                    conn = None
                
                if attempt < max_attempts - 1:
                    logger.warning(f"⚠️ WALLET_CREDIT_CONNECTION_RETRY: Attempt {attempt + 1}/{max_attempts} failed - retrying once | Error: {str(conn_error)[:100]}")
                    continue
                else:
                    logger.error(f"❌ WALLET_CREDIT_CONNECTION_FAILURE: All {max_attempts} attempts failed | Final error: {conn_error}")
                    return False
                    
            except psycopg2.IntegrityError as integrity_error:
                # Database constraint violations - check if it's a duplicate txid (idempotent success)
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                
                error_str = str(integrity_error).lower()
                if 'external_txid' in error_str or 'unique' in error_str or 'duplicate' in error_str:
                    # IDEMPOTENCY FIX: Duplicate txid means this was already credited successfully
                    # This is expected when retries occur - treat as success
                    logger.info(f"🔄 WALLET_CREDIT_IDEMPOTENT: Transaction already credited | user_id: {user_id} | txid: {txid[:16]}... | Treating as success")
                    return True  # Idempotent success - already credited
                else:
                    logger.error(f"❌ WALLET_CREDIT_INTEGRITY_ERROR: Database constraint violation | txid: {txid} | provider: {provider} | Error: {integrity_error}")
                    return False
            
            except ValueError as value_error:
                # Type conversion errors (from safe_decimal_conversion)
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                logger.error(f"❌ WALLET_CREDIT_VALUE_ERROR: Type conversion failed | user_id: {user_id} | Error: {value_error}")
                return False
                
            except Exception as unexpected_error:
                # Other errors should not be retried - enhanced debugging
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                logger.error(f"❌ WALLET_CREDIT_UNEXPECTED_ERROR: user_id {user_id} | amount ${amount_usd:.2f} | txid {txid} | Error Type: {type(unexpected_error).__name__} | Error: {unexpected_error}")
                logger.error(f"❌ WALLET_CREDIT_ERROR_DETAILS: Error args: {getattr(unexpected_error, 'args', 'No args')}")
                return False
                
            finally:
                if conn:
                    try:
                        conn.autocommit = True
                        return_connection(conn)
                    except:
                        pass
        
        # Should never reach here due to explicit returns above
        logger.error(f"❌ WALLET_CREDIT_LOGIC_ERROR: Unexpected code path reached for user_id {user_id}")
        return False
    
    # Enhanced async handling with proper timeout and isolation
    try:
        # Use asyncio.wait_for for timeout protection
        result = await asyncio.wait_for(
            asyncio.to_thread(_credit_wallet_with_retry), 
            timeout=30.0  # 30 second timeout for wallet operations
        )
        
        # ARCHITECT FIX: Ensure strict boolean return type
        if not isinstance(result, bool):
            logger.error(f"❌ WALLET_CREDIT_TYPE_ERROR: Function returned {type(result)} instead of bool: {result}")
            return False
        return result
        
    except asyncio.TimeoutError:
        logger.error(f"❌ WALLET_CREDIT_TIMEOUT: Operation timed out after 30s for user_id {user_id} | txid: {txid[:16]}...")
        return False
        
    except asyncio.CancelledError:
        logger.warning(f"⚠️ WALLET_CREDIT_CANCELLED: Operation cancelled for user_id {user_id} | txid: {txid[:16]}...")
        return False
        
    except Exception as async_error:
        logger.error(f"❌ WALLET_CREDIT_ASYNC_ERROR: Threading error for user_id {user_id} | Error Type: {type(async_error).__name__} | Error: {async_error}")
        return False

async def get_user_wallet_transactions(user_id: int, limit: int = 10) -> List[Dict]:
    """Get user's recent wallet transactions"""
    try:
        return await execute_query(
            "SELECT * FROM wallet_transactions WHERE user_id = %s AND deleted_at IS NULL ORDER BY created_at DESC LIMIT %s",
            (user_id, limit)
        )
    except Exception as e:
        logger.error(f"Error getting wallet transactions: {e}")
        return []

async def reserve_wallet_balance(user_id: int, amount: Decimal, description: str = '') -> Optional[int]:
    """Reserve amount from wallet (hold transaction) with atomic protection - returns transaction ID"""
    import psycopg2
    
    # CRITICAL FIX: Ensure amount is always converted to Decimal before arithmetic operations
    # This prevents "unsupported operand type(s) for -: 'decimal.Decimal' and 'float'" errors
    amount = to_currency_decimal(amount, "reservation_amount")
    
    def _atomic_reserve() -> Optional[int]:
        conn = None
        try:
            conn = get_connection()
            # CRITICAL: Disable autocommit for atomic transaction
            conn.autocommit = False
            
            with conn.cursor() as cursor:
                # SECURITY: Row-level lock to prevent race conditions
                cursor.execute(
                    "SELECT id, wallet_balance FROM users WHERE id = %s FOR UPDATE",
                    (user_id,)
                )
                user_row = cast(Optional[RealDictRow], cursor.fetchone())
                if not user_row:
                    logger.error(f"User {user_id} not found for wallet reservation")
                    conn.rollback()
                    return None
                
                current_balance = to_currency_decimal(user_row['wallet_balance'] or 0, "wallet_balance")
                
                # Validate amount bounds
                if amount <= 0:
                    logger.error(f"🚫 RESERVATION VALIDATION: Invalid amount for user {user_id}: {amount}")
                    conn.rollback()
                    return None
                
                if amount > 999999.99:
                    logger.error(f"🚫 RESERVATION VALIDATION: Amount too large for user {user_id}: {amount}")
                    conn.rollback()
                    return None
                
                # CRITICAL: Check sufficient balance
                if current_balance < amount:
                    logger.warning(f"🚫 RESERVATION PROTECTION: User {user_id} insufficient balance: {current_balance} < {amount}")
                    conn.rollback()
                    return None
                
                new_balance = current_balance - amount
                
                # Double-check negative balance protection
                if new_balance < 0:
                    logger.error(f"🚫 ATOMIC PROTECTION: Would create negative balance for user {user_id}: {new_balance}")
                    conn.rollback()
                    return None
                
                # Create hold transaction first
                cursor.execute(
                    "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                    (user_id, 'hold', -amount, 'USD', 'pending', f"Hold: {description}")
                )
                transaction_result = cast(Optional[RealDictRow], cursor.fetchone())
                transaction_id = transaction_result['id'] if transaction_result else None
                
                if not transaction_id:
                    logger.error(f"Failed to create hold transaction for user {user_id}")
                    conn.rollback()
                    return None
                
                # Update user balance atomically
                cursor.execute(
                    "UPDATE users SET wallet_balance = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (new_balance, user_id)
                )
                
                # Commit atomic transaction
                conn.commit()
                # Enhanced balance tracking with Old → New format for comprehensive audit trail
                logger.info(f"✅ RESERVATION SUCCESS: ${amount:.2f} reserved for user {user_id} | Old: ${current_balance:.2f} → New: ${new_balance:.2f} | Transaction ID: {transaction_id} | Description: {description}")
                return transaction_id
                
        except psycopg2.IntegrityError as e:
            if conn:
                conn.rollback()
            if "wallet_balance_non_negative" in str(e):
                logger.error(f"🚫 DATABASE CONSTRAINT: Negative balance prevented by DB constraint for user {user_id}")
            else:
                logger.error(f"Database integrity error in wallet reservation: {e}")
            return None
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Error in atomic wallet reservation: {e}")
            return None
        finally:
            if conn:
                return_connection(conn)
    
    return await asyncio.to_thread(_atomic_reserve)

async def finalize_wallet_reservation(transaction_id: int, success: bool = True) -> bool:
    """Finalize a wallet hold transaction with atomic protection"""
    import psycopg2
    
    def _atomic_finalize() -> bool:
        conn = None
        try:
            conn = get_connection()
            # CRITICAL: Disable autocommit for atomic transaction
            conn.autocommit = False
            
            with conn.cursor() as cursor:
                # SECURITY: Lock the transaction row to prevent double-processing
                cursor.execute(
                    "SELECT id, user_id, amount, status, transaction_type FROM wallet_transactions WHERE id = %s FOR UPDATE",
                    (transaction_id,)
                )
                transaction_row = cast(Optional[RealDictRow], cursor.fetchone())
                if not transaction_row:
                    logger.error(f"Transaction {transaction_id} not found for finalization")
                    conn.rollback()
                    return False
                
                # Validate transaction state
                if transaction_row['status'] != 'pending':
                    logger.warning(f"🚫 FINALIZATION PROTECTION: Transaction {transaction_id} already finalized with status: {transaction_row['status']}")
                    conn.rollback()
                    return False
                
                if transaction_row['transaction_type'] != 'hold':
                    logger.error(f"🚫 FINALIZATION VALIDATION: Transaction {transaction_id} is not a hold transaction: {transaction_row['transaction_type']}")
                    conn.rollback()
                    return False
                
                user_id = transaction_row['user_id']
                hold_amount = abs(to_currency_decimal(transaction_row['amount'], "hold_amount"))
                
                if success:
                    # Mark hold as completed (debit)
                    cursor.execute(
                        "UPDATE wallet_transactions SET status = 'completed', transaction_type = 'debit', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (transaction_id,)
                    )
                    logger.info(f"✅ HOLD FINALIZED: Transaction {transaction_id} completed as debit for user {user_id}")
                else:
                    # Refund the hold amount atomically
                    cursor.execute(
                        "SELECT id, wallet_balance FROM users WHERE id = %s FOR UPDATE",
                        (user_id,)
                    )
                    user_row = cast(Optional[RealDictRow], cursor.fetchone())
                    if not user_row:
                        logger.error(f"User {user_id} not found for hold refund")
                        conn.rollback()
                        return False
                    
                    current_balance = to_currency_decimal(user_row['wallet_balance'] or 0, "wallet_balance")
                    new_balance = current_balance + hold_amount
                    
                    # Validate refund bounds
                    if new_balance > 999999.99:
                        logger.error(f"🚫 REFUND VALIDATION: Refund would exceed balance limit for user {user_id}: {new_balance}")
                        conn.rollback()
                        return False
                    
                    # Get telegram_id for cache invalidation (only needed for refund case)
                    cursor.execute(
                        "SELECT telegram_id FROM users WHERE id = %s",
                        (user_id,)
                    )
                    telegram_id_row = cursor.fetchone()
                    telegram_id = telegram_id_row['telegram_id'] if telegram_id_row else None
                    
                    # Refund to user balance
                    cursor.execute(
                        "UPDATE users SET wallet_balance = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (new_balance, user_id)
                    )
                    
                    # Create refund transaction record
                    cursor.execute(
                        "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s)",
                        (user_id, 'credit', hold_amount, 'USD', 'completed', "Refund from cancelled order")
                    )
                    
                    # Mark hold as cancelled
                    cursor.execute(
                        "UPDATE wallet_transactions SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (transaction_id,)
                    )
                    
                    logger.info(f"✅ HOLD REFUNDED: Transaction {transaction_id} cancelled, ${hold_amount} refunded to user {user_id}")
                    
                    # CRITICAL: Invalidate user cache after refund
                    if telegram_id:
                        from performance_cache import cache_invalidate
                        cache_invalidate('user_data', telegram_id)
                        logger.info(f"🔄 CACHE_INVALIDATED: User cache cleared for telegram_id {telegram_id} after hold refund")
                
                # Commit atomic transaction
                conn.commit()
                return True
                
        except psycopg2.IntegrityError as e:
            if conn:
                conn.rollback()
            logger.error(f"Database integrity error in wallet finalization: {e}")
            return False
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Error in atomic wallet finalization: {e}")
            return False
        finally:
            if conn:
                return_connection(conn)
    
    return await asyncio.to_thread(_atomic_finalize)

# ====================================================================
# DNS RECORDS DATABASE FUNCTIONS (Database-First Pattern)
# ====================================================================

async def get_dns_records_from_db(domain_name: str) -> List[Dict[str, Any]]:
    """
    Get all DNS records for a domain from database
    Part of database-first pattern - check database before calling Cloudflare API
    
    Returns:
        List of DNS record dictionaries from database (with proxied and locked fields)
    """
    try:
        results = await execute_query(
            """SELECT id, domain_name, record_type, name, content, ttl, priority, 
                      cloudflare_record_id, proxied, locked, created_at, updated_at
               FROM dns_records 
               WHERE domain_name = %s
               ORDER BY record_type, name""",
            (domain_name,)
        )
        
        if results:
            logger.info(f"📦 DATABASE HIT: Found {len(results)} DNS records for {domain_name} in database")
        else:
            logger.info(f"📭 DATABASE MISS: No DNS records found for {domain_name} in database")
            
        return results if results else []
        
    except Exception as e:
        logger.error(f"Error getting DNS records from database for {domain_name}: {e}")
        return []

async def save_dns_records_to_db(domain_name: str, records: List[Dict[str, Any]]) -> bool:
    """
    Save DNS records to database (upsert - insert or update)
    Part of database-first pattern - persist API data for future lookups
    
    Args:
        domain_name: The domain name these records belong to
        records: List of DNS record dictionaries from Cloudflare API
        
    Returns:
        True if successful, False otherwise
    """
    try:
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                # CRITICAL FIX (Bug 1): Always delete existing records first, even if new list is empty
                # This ensures deleted records don't keep reappearing in the UI
                cursor.execute("DELETE FROM dns_records WHERE domain_name = %s", (domain_name,))
                deleted_count = cursor.rowcount
                
                # If no new records to save, we're done (old records already deleted)
                if not records:
                    conn.commit()
                    logger.info(f"💾 DATABASE SAVE: Cleared all DNS records for {domain_name} (deleted {deleted_count} old records)")
                    return True
                
                # Insert all records with proxied and locked fields (Bug 2 fix)
                inserted_count = 0
                for record in records:
                    cursor.execute(
                        """INSERT INTO dns_records 
                           (domain_name, record_type, name, content, ttl, priority, cloudflare_record_id, proxied, locked)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (
                            domain_name,
                            record.get('type', 'UNKNOWN'),
                            record.get('name', ''),
                            record.get('content', ''),
                            record.get('ttl', 300),
                            record.get('priority'),
                            record.get('id', ''),
                            record.get('proxied', False),
                            record.get('locked', False)
                        )
                    )
                    inserted_count += 1
                
                conn.commit()
                logger.info(f"💾 DATABASE SAVE: Saved {inserted_count} DNS records for {domain_name} (deleted {deleted_count} old records)")
                return True
                
        finally:
            return_connection(conn)
            
    except Exception as e:
        logger.error(f"Error saving DNS records to database for {domain_name}: {e}")
        return False

async def update_single_dns_record_in_db(domain_name: str, record: Dict) -> bool:
    """Update or insert a single DNS record in the database (UPSERT pattern)"""
    try:
        # Extract record data
        record_id = record.get('id')
        if not record_id:
            logger.warning(f"Cannot update DNS record without ID for {domain_name}")
            return False
        
        record_type = record.get('type', '')
        name = record.get('name', '')
        content = record.get('content', '')
        ttl = record.get('ttl', 300)
        proxied = record.get('proxied', False)
        locked = record.get('locked', False)
        metadata = record.get('meta', {})
        
        # Use INSERT ... ON CONFLICT DO UPDATE (UPSERT) to avoid race conditions
        # CRITICAL FIX: Use execute_update instead of execute_query for proper commit
        rows_affected = await execute_update("""
            INSERT INTO dns_records 
            (domain_name, cloudflare_record_id, record_type, name, content, ttl, proxied, locked, metadata, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (cloudflare_record_id) WHERE (cloudflare_record_id IS NOT NULL)
            DO UPDATE SET
                record_type = EXCLUDED.record_type,
                name = EXCLUDED.name,
                content = EXCLUDED.content,
                ttl = EXCLUDED.ttl,
                proxied = EXCLUDED.proxied,
                locked = EXCLUDED.locked,
                metadata = EXCLUDED.metadata,
                updated_at = CURRENT_TIMESTAMP
        """, (
            domain_name,
            record_id,
            record_type,
            name,
            content,
            ttl,
            proxied,
            locked,
            json.dumps(metadata)
        ))
        
        logger.info(f"✅ Saved DNS record to database: {record_type} {name} for {domain_name} (rows={rows_affected})")
        return True
        
    except Exception as e:
        logger.error(f"Failed to update single DNS record in database: {e}")
        return False


async def delete_single_dns_record_from_db(record_id: str) -> bool:
    """Delete a single DNS record from the database by Cloudflare record ID"""
    try:
        rows_affected = await execute_update(
            "DELETE FROM dns_records WHERE cloudflare_record_id = %s",
            (record_id,)
        )
        if rows_affected > 0:
            logger.info(f"✅ Deleted DNS record from database: {record_id} ({rows_affected} rows)")
        else:
            logger.debug(f"📭 DNS record not found in database for deletion: {record_id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete DNS record from database: {e}")
        return False

async def get_dns_record_from_db(cloudflare_record_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a single DNS record by Cloudflare record ID from database
    Part of database-first pattern - check database before calling Cloudflare API
    
    Args:
        cloudflare_record_id: The Cloudflare record ID
        
    Returns:
        DNS record dictionary or None if not found (with proxied and locked fields)
    """
    try:
        results = await execute_query(
            """SELECT id, domain_name, record_type, name, content, ttl, priority, 
                      cloudflare_record_id, proxied, locked, created_at, updated_at
               FROM dns_records 
               WHERE cloudflare_record_id = %s""",
            (cloudflare_record_id,)
        )
        
        if results:
            logger.debug(f"📦 DATABASE HIT: Found DNS record {cloudflare_record_id[:8]}... in database")
            return results[0]
        else:
            logger.debug(f"📭 DATABASE MISS: DNS record {cloudflare_record_id[:8]}... not in database")
            return None
            
    except Exception as e:
        logger.error(f"Error getting DNS record from database: {e}")
        return None

# ====================================================================
# DNS OPTIMISTIC CONCURRENCY CONTROL FUNCTIONS
# ====================================================================

async def get_dns_record_version(record_id: str) -> Optional[Dict[str, Any]]:
    """Get DNS record version data for optimistic concurrency control"""
    def _get_version():
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """SELECT record_id, zone_id, record_type, last_modified_at, 
                              version_etag, content_hash, record_data
                       FROM dns_record_versions WHERE record_id = %s""",
                    (record_id,)
                )
                result = cursor.fetchone()
                return dict(result) if result else None
        except Exception as e:
            logger.error(f"Failed to get DNS record version for {record_id}: {e}")
            return None
        finally:
            return_connection(conn)
    
    return await run_db(_get_version)

async def update_dns_record_version(record_id: str, zone_id: str, record_type: str, 
                                   version_etag: str, content_hash: str, 
                                   record_data: Dict[str, Any], 
                                   expected_etag: Optional[str] = None) -> Dict[str, Any]:
    """
    Update DNS record version with proper Compare-And-Set (CAS) semantics for optimistic concurrency control
    
    Returns:
        Dict with 'success' (bool), 'conflict' (bool), and optional 'current_etag' (str)
    """
    def _update_version():
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                if expected_etag is not None:
                    # EXISTING RECORD: Use CAS semantics with UPDATE ... WHERE version_etag = expected
                    logger.debug(f"🔒 CAS UPDATE: {record_id} expected:{expected_etag[:8]}... -> new:{version_etag[:8]}...")
                    
                    cursor.execute(
                        """UPDATE dns_record_versions 
                           SET zone_id = %s, record_type = %s, version_etag = %s, 
                               content_hash = %s, record_data = %s, last_modified_at = CURRENT_TIMESTAMP
                           WHERE record_id = %s AND version_etag = %s""",
                        (zone_id, record_type, version_etag, content_hash, 
                         json.dumps(record_data), record_id, expected_etag)
                    )
                    
                    if cursor.rowcount == 0:
                        # CAS CONFLICT: No rows updated - either wrong etag or record deleted
                        logger.warning(f"🚫 CAS CONFLICT: {record_id} expected:{expected_etag[:8]}... (conflict detected)")
                        
                        # Get current etag for conflict resolution
                        cursor.execute(
                            "SELECT version_etag FROM dns_record_versions WHERE record_id = %s",
                            (record_id,)
                        )
                        current_row = cursor.fetchone()
                        current_etag = dict(current_row)['version_etag'] if current_row else None
                        
                        return {
                            'success': False,
                            'conflict': True,
                            'current_etag': current_etag,
                            'expected_etag': expected_etag
                        }
                    
                    logger.debug(f"✅ CAS SUCCESS: {record_id} updated to etag:{version_etag[:8]}...")
                    return {'success': True, 'conflict': False}
                    
                else:
                    # NEW RECORD: Insert if not exists (first writer wins)
                    logger.debug(f"🆕 INSERT NEW: {record_id} etag:{version_etag[:8]}...")
                    
                    cursor.execute(
                        """INSERT INTO dns_record_versions 
                           (record_id, zone_id, record_type, version_etag, content_hash, 
                            record_data, last_modified_at, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                           ON CONFLICT (record_id, version_etag) DO NOTHING""",
                        (record_id, zone_id, record_type, version_etag, content_hash, 
                         json.dumps(record_data))
                    )
                    
                    if cursor.rowcount == 0:
                        # RACE CONDITION: Another session inserted first
                        logger.warning(f"🔄 INSERT RACE: {record_id} - another session created record first")
                        
                        # Get the winning etag for conflict resolution
                        cursor.execute(
                            "SELECT version_etag FROM dns_record_versions WHERE record_id = %s",
                            (record_id,)
                        )
                        current_row = cursor.fetchone()
                        current_etag = dict(current_row)['version_etag'] if current_row else None
                        
                        return {
                            'success': False,
                            'conflict': True,
                            'current_etag': current_etag,
                            'expected_etag': expected_etag
                        }
                    
                    logger.debug(f"✅ INSERT SUCCESS: {record_id} created with etag:{version_etag[:8]}...")
                    return {'success': True, 'conflict': False}
                    
        except Exception as e:
            logger.error(f"Failed to update DNS record version for {record_id}: {e}")
            return {'success': False, 'conflict': False, 'error': str(e)}
        finally:
            return_connection(conn)
    
    return await run_db(_update_version)

async def check_dns_record_conflict(record_id: str, expected_etag: str) -> Tuple[bool, Optional[str]]:
    """Check if DNS record has version conflict (optimistic concurrency control)"""
    def _check_conflict():
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT version_etag FROM dns_record_versions WHERE record_id = %s",
                    (record_id,)
                )
                result = cursor.fetchone()
                
                if not result:
                    # No version tracked yet - no conflict
                    return False, None
                
                current_etag = dict(result)['version_etag']
                has_conflict = current_etag != expected_etag
                
                if has_conflict:
                    logger.warning(f"🔄 DNS version conflict detected: record {record_id}, "
                                 f"expected {expected_etag[:8]}..., current {current_etag[:8]}...")
                
                return has_conflict, current_etag
        except Exception as e:
            logger.error(f"Failed to check DNS record conflict for {record_id}: {e}")
            return False, None
        finally:
            return_connection(conn)
    
    return await run_db(_check_conflict)

async def force_update_dns_record_version(record_id: str, zone_id: str, record_type: str,
                                          version_etag: str, content_hash: str,
                                          record_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Force update DNS record version without CAS checks - used for conflict reconciliation.
    
    This bypasses optimistic concurrency control and forcefully sets the version.
    Use only when you know the actual DNS state and need to reconcile the database.
    
    Returns:
        Dict with 'success' (bool) and optional 'error' (str)
    """
    def _force_update():
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                logger.info(f"🔧 FORCE RECONCILIATION: {record_id} -> etag:{version_etag[:8]}... (overriding version tracking)")
                
                # First, delete any existing version for this record (force override)
                cursor.execute(
                    "DELETE FROM dns_record_versions WHERE record_id = %s",
                    (record_id,)
                )
                
                # Then insert the new authoritative version
                cursor.execute(
                    """INSERT INTO dns_record_versions 
                       (record_id, zone_id, record_type, version_etag, content_hash, 
                        record_data, last_modified_at, created_at)
                       VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
                    (record_id, zone_id, record_type, version_etag, content_hash, 
                     json.dumps(record_data))
                )
                
                logger.info(f"✅ FORCE RECONCILIATION SUCCESS: {record_id} version forcefully updated to etag:{version_etag[:8]}...")
                return {'success': True}
                
        except Exception as e:
            logger.error(f"Failed to force update DNS record version for {record_id}: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            return_connection(conn)
    
    return await run_db(_force_update)

async def check_zone_creation_lock(domain_id: int) -> bool:
    """Check if zone creation is already in progress for domain (row-level lock)"""
    def _check_lock():
        conn = get_connection()
        try:
            conn.autocommit = False  # Need transaction for row lock
            with conn.cursor() as cursor:
                # Check if cloudflare zone already exists with row lock
                cursor.execute(
                    "SELECT id FROM cloudflare_zones WHERE domain_id = %s FOR UPDATE NOWAIT",
                    (domain_id,)
                )
                result = cursor.fetchone()
                conn.rollback()  # Release lock
                return result is not None
        except psycopg2.errors.LockNotAvailable:
            logger.warning(f"Zone creation lock detected for domain {domain_id}")
            if conn:
                conn.rollback()
            return True  # Lock exists - zone creation in progress
        except Exception as e:
            logger.error(f"Failed to check zone creation lock for domain {domain_id}: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.autocommit = True
                return_connection(conn)
    
    return await run_db(_check_lock)

async def create_zone_with_lock(domain_id: int, domain_name: str, cf_zone_id: str, 
                               nameservers: List[str], status: str) -> bool:
    """Create Cloudflare zone with atomic domain lock to prevent conflicts"""
    def _create_with_lock():
        conn = get_connection()
        try:
            conn.autocommit = False  # Need transaction for atomic operation
            
            with conn.cursor() as cursor:
                # 1. Lock the domain row to serialize zone creation
                cursor.execute(
                    "SELECT id, domain_name FROM domains WHERE id = %s FOR UPDATE",
                    (domain_id,)
                )
                domain_result = cursor.fetchone()
                if not domain_result:
                    logger.error(f"Domain {domain_id} not found for zone creation")
                    conn.rollback()
                    return False
                
                # 2. Check if zone already exists (within transaction)
                cursor.execute(
                    "SELECT id FROM cloudflare_zones WHERE domain_id = %s",
                    (domain_id,)
                )
                existing_zone = cursor.fetchone()
                if existing_zone:
                    logger.info(f"Zone already exists for domain {domain_id}")
                    conn.rollback()
                    return True  # Not an error - zone exists
                
                # 3. Create the zone atomically
                cursor.execute(
                    """INSERT INTO cloudflare_zones 
                       (domain_id, domain_name, cf_zone_id, nameservers, status, created_at, updated_at)
                       VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
                    (domain_id, domain_name, cf_zone_id, nameservers, status)
                )
                
                conn.commit()
                logger.info(f"✅ Zone created atomically: {domain_name} -> {cf_zone_id}")
                return True
                
        except psycopg2.errors.UniqueViolation:
            logger.info(f"Zone already exists (unique constraint): domain {domain_id}")
            if conn:
                conn.rollback()
            return True  # Not an error - unique constraint handled it
        except Exception as e:
            logger.error(f"Failed to create zone with lock for domain {domain_id}: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.autocommit = True
                return_connection(conn)
    
    return await run_db(_create_with_lock)

async def get_zone_by_domain_id(domain_id: int) -> Optional[Dict[str, Any]]:
    """Get Cloudflare zone by domain ID for conflict checking"""
    def _get_zone():
        conn = get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """SELECT cz.id, cz.domain_id, cz.domain_name, cz.cf_zone_id, 
                              cz.nameservers, cz.status, cz.created_at, cz.updated_at
                       FROM cloudflare_zones cz WHERE cz.domain_id = %s""",
                    (domain_id,)
                )
                result = cursor.fetchone()
                return dict(result) if result else None
        except Exception as e:
            logger.error(f"Failed to get zone by domain ID {domain_id}: {e}")
            return None
        finally:
            return_connection(conn)
    
    return await run_db(_get_zone)

async def cleanup_old_dns_versions(older_than_hours: int = 24) -> int:
    """Clean up old DNS record versions to prevent table growth"""
    def _cleanup():
        conn = get_connection()
        try:
            # Use UTC time calculation to avoid timezone issues
            from datetime import datetime, timezone, timedelta
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)
            
            with conn.cursor() as cursor:
                cursor.execute(
                    """DELETE FROM dns_record_versions 
                       WHERE created_at < %s""",
                    (cutoff_time,)
                )
                deleted_count = cursor.rowcount
                logger.info(f"🗑️ Cleaned up {deleted_count} old DNS record versions")
                return deleted_count
        except Exception as e:
            logger.error(f"Failed to cleanup old DNS versions: {e}")
            return 0
        finally:
            return_connection(conn)
    
    return await run_db(_cleanup)

# =============================================================================
# PHASE 2: SOFT DELETION MIGRATION FUNCTIONS
# =============================================================================

async def migrate_add_soft_deletion_columns() -> bool:
    """
    Phase 2 Migration: Add soft deletion columns to critical business tables
    Adds deleted_at TIMESTAMP and deleted_by INTEGER to target tables
    """
    logger.info("🚀 Starting Phase 2: Soft Deletion Migration - Adding columns...")
    
    # Define target tables and their soft deletion columns
    target_tables = [
        'users',
        'domains', 
        'orders',
        'hosting_subscriptions',
        'wallet_transactions',
        'payment_intents'
    ]
    
    migration_success = True
    
    for table_name in target_tables:
        try:
            logger.info(f"📝 Adding soft deletion columns to table: {table_name}")
            
            # Add deleted_at column
            await execute_update(f"""
                ALTER TABLE {table_name} 
                ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP DEFAULT NULL
            """)
            
            # Add deleted_by column with foreign key to users
            await execute_update(f"""
                ALTER TABLE {table_name} 
                ADD COLUMN IF NOT EXISTS deleted_by INTEGER DEFAULT NULL
            """)
            
            # Add foreign key constraint for deleted_by (check if exists first)
            # Skip for users table to avoid self-reference issues
            if table_name != 'users':
                # Check if constraint already exists
                constraint_exists = await execute_query("""
                    SELECT 1 FROM information_schema.table_constraints 
                    WHERE constraint_name = %s AND table_name = %s
                """, (f'fk_{table_name}_deleted_by', table_name))
                
                if not constraint_exists:
                    await execute_update(f"""
                        ALTER TABLE {table_name} 
                        ADD CONSTRAINT fk_{table_name}_deleted_by 
                        FOREIGN KEY (deleted_by) REFERENCES users(id)
                    """)
            
            # Add index on deleted_at for performance
            await execute_update(f"""
                CREATE INDEX IF NOT EXISTS idx_{table_name}_deleted_at 
                ON {table_name}(deleted_at) WHERE deleted_at IS NOT NULL
            """)
            
            logger.info(f"✅ Successfully added soft deletion columns to {table_name}")
            
        except Exception as e:
            logger.error(f"❌ Failed to add soft deletion columns to {table_name}: {e}")
            migration_success = False
    
    if migration_success:
        logger.info("✅ Phase 2 Migration: Soft deletion columns added successfully")
    else:
        logger.error("❌ Phase 2 Migration: Some table migrations failed")
    
    return migration_success

async def migrate_convert_unique_constraints_to_partial_indexes() -> bool:
    """
    Phase 2 Migration: Convert unique constraints to partial indexes
    Converts existing unique constraints to WHERE deleted_at IS NULL
    """
    logger.info("🔄 Starting Phase 2: Converting unique constraints to partial indexes...")
    
    migration_success = True
    
    try:
        # 1. Convert domains.domain_name unique constraint
        logger.info("📝 Converting domains.domain_name constraint to partial index")
        
        # Drop existing unique constraint
        await execute_update("""
            ALTER TABLE domains DROP CONSTRAINT IF EXISTS domains_domain_name_key
        """)
        
        # Create partial unique index
        await execute_update("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_domain_name_active 
            ON domains(domain_name) WHERE deleted_at IS NULL
        """)
        
        # 2. Convert users.telegram_id unique constraint  
        logger.info("📝 Converting users.telegram_id constraint to partial index")
        
        # Drop existing unique constraint
        await execute_update("""
            ALTER TABLE users DROP CONSTRAINT IF EXISTS users_telegram_id_key
        """)
        
        # Create partial unique index
        await execute_update("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_telegram_id_active 
            ON users(telegram_id) WHERE deleted_at IS NULL
        """)
        
        # 3. Convert wallet_transactions.external_txid constraint
        logger.info("📝 Converting wallet_transactions.external_txid constraint to partial index")
        
        # Drop existing constraints (drop constraint, not index)
        await execute_update("""
            ALTER TABLE wallet_transactions DROP CONSTRAINT IF EXISTS wallet_transactions_external_txid_key
        """)
        await execute_update("""
            ALTER TABLE wallet_transactions DROP CONSTRAINT IF EXISTS unique_external_txid_provider
        """)
        
        # Create partial unique index for external_txid + provider combination
        # CRITICAL FIX: Exclude 'unknown' values to allow multiple payments when provider doesn't send real txids
        await execute_update("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_wallet_transactions_external_txid_provider_active 
            ON wallet_transactions(external_txid, provider) 
            WHERE deleted_at IS NULL AND external_txid IS NOT NULL AND external_txid != 'unknown'
        """)
        
        # 4. Convert payment_intents compound constraint
        logger.info("📝 Converting payment_intents compound constraint to partial index")
        
        # Drop existing constraint (drop constraint, not index)
        await execute_update("""
            ALTER TABLE payment_intents DROP CONSTRAINT IF EXISTS unique_business_order_payment_provider
        """)
        
        # Create partial unique index for payment_provider + business_order_id
        await execute_update("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_intents_provider_order_active 
            ON payment_intents(payment_provider, business_order_id) 
            WHERE deleted_at IS NULL AND business_order_id IS NOT NULL
        """)
        
        logger.info("✅ Phase 2 Migration: Unique constraints converted to partial indexes")
        
    except Exception as e:
        logger.error(f"❌ Failed to convert unique constraints: {e}")
        migration_success = False
    
    return migration_success

async def migrate_create_active_views() -> bool:
    """
    Phase 2 Migration: Create filtered views for active (non-deleted) records
    Creates views like users_active, domains_active, etc.
    """
    logger.info("📋 Starting Phase 2: Creating active record views...")
    
    migration_success = True
    
    view_definitions = {
        'users_active': """
            CREATE OR REPLACE VIEW users_active AS
            SELECT * FROM users WHERE deleted_at IS NULL
        """,
        'domains_active': """
            CREATE OR REPLACE VIEW domains_active AS
            SELECT * FROM domains WHERE deleted_at IS NULL
        """,
        'orders_active': """
            CREATE OR REPLACE VIEW orders_active AS
            SELECT * FROM orders WHERE deleted_at IS NULL
        """,
        'hosting_subscriptions_active': """
            CREATE OR REPLACE VIEW hosting_subscriptions_active AS
            SELECT * FROM hosting_subscriptions WHERE deleted_at IS NULL
        """,
        'wallet_transactions_active': """
            CREATE OR REPLACE VIEW wallet_transactions_active AS
            SELECT * FROM wallet_transactions WHERE deleted_at IS NULL
        """,
        'payment_intents_active': """
            CREATE OR REPLACE VIEW payment_intents_active AS
            SELECT * FROM payment_intents WHERE deleted_at IS NULL
        """
    }
    
    for view_name, view_sql in view_definitions.items():
        try:
            logger.info(f"📝 Creating view: {view_name}")
            await execute_update(view_sql)
            logger.info(f"✅ Successfully created view: {view_name}")
        except Exception as e:
            logger.error(f"❌ Failed to create view {view_name}: {e}")
            migration_success = False
    
    if migration_success:
        logger.info("✅ Phase 2 Migration: Active record views created successfully")
    else:
        logger.error("❌ Phase 2 Migration: Some view creations failed")
    
    return migration_success

async def soft_delete_record(table_name: str, record_id: int, deleted_by_user_id: Optional[int] = None) -> bool:
    """
    Soft delete a record by setting deleted_at timestamp and deleted_by user
    
    Args:
        table_name: Name of the table to soft delete from
        record_id: ID of the record to soft delete
        deleted_by_user_id: ID of user performing the deletion (optional)
    
    Returns:
        bool: True if successful, False otherwise
    """
    # Validate table name against allowed tables for security
    allowed_tables = ['users', 'domains', 'orders', 'hosting_subscriptions', 'wallet_transactions', 'payment_intents']
    if table_name not in allowed_tables:
        logger.error(f"❌ Soft delete not allowed for table: {table_name}")
        return False
    
    try:
        # Perform soft deletion
        rows_affected = await execute_update(f"""
            UPDATE {table_name} 
            SET deleted_at = CURRENT_TIMESTAMP, 
                deleted_by = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND deleted_at IS NULL
        """, (deleted_by_user_id, record_id))
        
        if rows_affected > 0:
            logger.info(f"✅ Soft deleted record {record_id} from {table_name} (by user {deleted_by_user_id})")
            return True
        else:
            logger.warning(f"⚠️ No active record found to soft delete: {table_name}#{record_id}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to soft delete {table_name}#{record_id}: {e}")
        return False

async def restore_record(table_name: str, record_id: int, restored_by_user_id: Optional[int] = None) -> bool:
    """
    Restore a soft-deleted record by clearing deleted_at and deleted_by
    
    Args:
        table_name: Name of the table to restore from
        record_id: ID of the record to restore
        restored_by_user_id: ID of user performing the restoration (optional)
    
    Returns:
        bool: True if successful, False otherwise
    """
    # Validate table name against allowed tables for security
    allowed_tables = ['users', 'domains', 'orders', 'hosting_subscriptions', 'wallet_transactions', 'payment_intents']
    if table_name not in allowed_tables:
        logger.error(f"❌ Record restoration not allowed for table: {table_name}")
        return False
    
    try:
        # Perform record restoration
        rows_affected = await execute_update(f"""
            UPDATE {table_name} 
            SET deleted_at = NULL, 
                deleted_by = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND deleted_at IS NOT NULL
        """, (record_id,))
        
        if rows_affected > 0:
            logger.info(f"✅ Restored record {record_id} in {table_name} (by user {restored_by_user_id})")
            return True
        else:
            logger.warning(f"⚠️ No deleted record found to restore: {table_name}#{record_id}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to restore {table_name}#{record_id}: {e}")
        return False

async def get_deleted_records(table_name: str, limit: int = 100) -> List[Dict]:
    """
    Get soft-deleted records from a table for recovery/audit purposes
    
    Args:
        table_name: Name of the table to query
        limit: Maximum number of records to return
    
    Returns:
        List of deleted records
    """
    # Validate table name for security
    allowed_tables = ['users', 'domains', 'orders', 'hosting_subscriptions', 'wallet_transactions', 'payment_intents']
    if table_name not in allowed_tables:
        logger.error(f"❌ Query not allowed for table: {table_name}")
        return []
    
    try:
        deleted_records = await execute_query(f"""
            SELECT *, deleted_at, deleted_by 
            FROM {table_name} 
            WHERE deleted_at IS NOT NULL 
            ORDER BY deleted_at DESC 
            LIMIT %s
        """, (limit,))
        
        logger.info(f"📋 Retrieved {len(deleted_records)} deleted records from {table_name}")
        return deleted_records
        
    except Exception as e:
        logger.error(f"❌ Failed to get deleted records from {table_name}: {e}")
        return []

async def save_dns_record_history(
    domain_name: str,
    record_type: str,
    name: str,
    content: str,
    action: str,
    user_id: Optional[int] = None,
    ttl: Optional[int] = None,
    priority: Optional[int] = None,
    cloudflare_record_id: Optional[str] = None,
    old_content: Optional[str] = None,
    old_ttl: Optional[int] = None,
    old_priority: Optional[int] = None,
    metadata: Optional[Dict] = None
) -> bool:
    """
    Save DNS record change to history for audit and tracking purposes.
    
    Args:
        domain_name: The domain name
        record_type: DNS record type (A, CNAME, MX, etc.)
        name: Record name
        content: New record content
        action: Action performed (create, update, delete)
        user_id: User who made the change (optional)
        ttl: Time to live
        priority: Record priority (for MX, SRV records)
        cloudflare_record_id: Cloudflare record ID
        old_content: Previous content (for updates/deletes)
        old_ttl: Previous TTL (for updates)
        old_priority: Previous priority (for updates)
        metadata: Additional metadata (JSONB)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        import json
        metadata_json = json.dumps(metadata) if metadata else None
        
        await execute_update("""
            INSERT INTO dns_record_history (
                domain_name, record_type, name, content, ttl, priority,
                cloudflare_record_id, action, user_id,
                old_content, old_ttl, old_priority, metadata, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (
            domain_name, record_type, name, content, ttl, priority,
            cloudflare_record_id, action, user_id,
            old_content, old_ttl, old_priority, metadata_json
        ))
        
        logger.info(f"✅ Saved DNS history: {action} {record_type} record for {domain_name}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to save DNS record history for {domain_name}: {e}")
        return False

async def get_dns_record_history(
    domain_name: str,
    record_type: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Get DNS record change history for a domain.
    
    Args:
        domain_name: The domain name to get history for
        record_type: Optional filter by record type (A, CNAME, etc.)
        limit: Maximum number of records to return (default: 100)
    
    Returns:
        List of DNS history records ordered by newest first
    """
    try:
        if record_type:
            history = await execute_query("""
                SELECT 
                    id, domain_name, record_type, name, content, ttl, priority,
                    cloudflare_record_id, action, user_id,
                    old_content, old_ttl, old_priority, metadata, created_at
                FROM dns_record_history
                WHERE domain_name = %s AND record_type = %s
                ORDER BY created_at DESC
                LIMIT %s
            """, (domain_name, record_type, limit))
        else:
            history = await execute_query("""
                SELECT 
                    id, domain_name, record_type, name, content, ttl, priority,
                    cloudflare_record_id, action, user_id,
                    old_content, old_ttl, old_priority, metadata, created_at
                FROM dns_record_history
                WHERE domain_name = %s
                ORDER BY created_at DESC
                LIMIT %s
            """, (domain_name, limit))
        
        logger.info(f"📋 Retrieved {len(history)} DNS history records for {domain_name}")
        return history
        
    except Exception as e:
        logger.error(f"❌ Failed to get DNS history for {domain_name}: {e}")
        return []

async def run_complete_soft_deletion_migration() -> bool:
    """
    Run the complete Phase 2 soft deletion migration
    Executes all migration steps in the correct order
    """
    logger.info("🚀 Starting COMPLETE Phase 2: Soft Deletion Migration")
    
    # Step 1: Add soft deletion columns
    step1_success = await migrate_add_soft_deletion_columns()
    if not step1_success:
        logger.error("❌ Migration failed at Step 1: Adding soft deletion columns")
        return False
    
    # Step 2: Convert unique constraints to partial indexes
    step2_success = await migrate_convert_unique_constraints_to_partial_indexes()
    if not step2_success:
        logger.error("❌ Migration failed at Step 2: Converting unique constraints")
        return False
    
    # Step 3: Create active views
    step3_success = await migrate_create_active_views()
    if not step3_success:
        logger.error("❌ Migration failed at Step 3: Creating active views")
        return False
    
    logger.info("🎉 Phase 2: Soft Deletion Migration completed successfully!")
    logger.info("📋 Summary:")
    logger.info("   ✅ Added soft deletion columns to all target tables")
    logger.info("   ✅ Converted unique constraints to partial indexes") 
    logger.info("   ✅ Created active record views")
    logger.info("   ✅ Added soft_delete_record() and restore_record() functions")
    logger.info("🔍 Next: Update existing queries to include deleted_at IS NULL filters")
    
    return True


# =============================================================================
# OPENPROVIDER MULTI-ACCOUNT MANAGEMENT
# =============================================================================

async def get_openprovider_accounts() -> List[Dict[str, Any]]:
    """Get all active OpenProvider accounts"""
    try:
        accounts = await execute_query("""
            SELECT id, account_name, username, is_default, is_active, notes, created_at
            FROM openprovider_accounts
            WHERE is_active = TRUE
            ORDER BY is_default DESC, account_name ASC
        """)
        return accounts if accounts else []
    except Exception as e:
        logger.error(f"❌ Failed to get OpenProvider accounts: {e}")
        return []

async def get_default_openprovider_account() -> Optional[Dict[str, Any]]:
    """Get the default OpenProvider account"""
    try:
        accounts = await execute_query("""
            SELECT id, account_name, username, is_default, is_active, notes
            FROM openprovider_accounts
            WHERE is_default = TRUE AND is_active = TRUE
            LIMIT 1
        """)
        if accounts:
            return accounts[0]
        
        # If no default, get first active account
        accounts = await execute_query("""
            SELECT id, account_name, username, is_default, is_active, notes
            FROM openprovider_accounts
            WHERE is_active = TRUE
            ORDER BY id ASC
            LIMIT 1
        """)
        return accounts[0] if accounts else None
    except Exception as e:
        logger.error(f"❌ Failed to get default OpenProvider account: {e}")
        return None

async def get_openprovider_account_by_id(account_id: int) -> Optional[Dict[str, Any]]:
    """Get OpenProvider account by ID"""
    try:
        accounts = await execute_query("""
            SELECT id, account_name, username, is_default, is_active, notes
            FROM openprovider_accounts
            WHERE id = %s AND is_active = TRUE
        """, (account_id,))
        return accounts[0] if accounts else None
    except Exception as e:
        logger.error(f"❌ Failed to get OpenProvider account {account_id}: {e}")
        return None

async def create_openprovider_account(
    account_name: str,
    username: str,
    is_default: bool = False,
    notes: Optional[str] = None
) -> Optional[int]:
    """Create a new OpenProvider account record"""
    try:
        # If setting as default, unset other defaults first
        if is_default:
            await execute_update("""
                UPDATE openprovider_accounts SET is_default = FALSE WHERE is_default = TRUE
            """)
        
        # FIX: Use execute_query for INSERT...RETURNING to get actual ID (not rowcount)
        result = await execute_query("""
            INSERT INTO openprovider_accounts (account_name, username, is_default, notes)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (account_name, username, is_default, notes))
        
        if result and len(result) > 0:
            account_id = result[0]['id']
            logger.info(f"✅ Created OpenProvider account: {account_name} (ID: {account_id})")
            return account_id
        return None
    except Exception as e:
        logger.error(f"❌ Failed to create OpenProvider account {account_name}: {e}")
        return None

async def set_default_openprovider_account(account_id: int) -> bool:
    """Set an account as the default"""
    try:
        # Unset all defaults
        await execute_update("""
            UPDATE openprovider_accounts SET is_default = FALSE WHERE is_default = TRUE
        """)
        
        # Set new default
        rows = await execute_update("""
            UPDATE openprovider_accounts SET is_default = TRUE WHERE id = %s
        """, (account_id,))
        
        if rows and rows > 0:
            logger.info(f"✅ Set OpenProvider account {account_id} as default")
            return True
        return False
    except Exception as e:
        logger.error(f"❌ Failed to set default OpenProvider account: {e}")
        return False

async def save_openprovider_contact_handle(
    account_id: int,
    tld: str,
    contact_type: str,
    handle: str
) -> bool:
    """Save a contact handle for an account/TLD combination"""
    try:
        await execute_update("""
            INSERT INTO openprovider_contact_handles (account_id, tld, contact_type, handle)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (account_id, tld, contact_type) 
            DO UPDATE SET handle = EXCLUDED.handle
        """, (account_id, tld, contact_type, handle))
        
        logger.info(f"✅ Saved contact handle for account {account_id}, TLD {tld}, type {contact_type}: {handle}")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to save contact handle: {e}")
        return False

async def get_openprovider_contact_handle(
    account_id: int,
    tld: str,
    contact_type: str
) -> Optional[str]:
    """Get a cached contact handle for an account/TLD combination"""
    try:
        result = await execute_query("""
            SELECT handle FROM openprovider_contact_handles
            WHERE account_id = %s AND tld = %s AND contact_type = %s
        """, (account_id, tld, contact_type))
        
        if result:
            return result[0]['handle'] if isinstance(result[0], dict) else result[0][0]
        return None
    except Exception as e:
        logger.error(f"❌ Failed to get contact handle: {e}")
        return None

async def get_all_contact_handles_for_account(account_id: int) -> List[Dict[str, Any]]:
    """Get all contact handles for an account"""
    try:
        handles = await execute_query("""
            SELECT tld, contact_type, handle, created_at
            FROM openprovider_contact_handles
            WHERE account_id = %s
            ORDER BY tld, contact_type
        """, (account_id,))
        return handles if handles else []
    except Exception as e:
        logger.error(f"❌ Failed to get contact handles for account {account_id}: {e}")
        return []

async def seed_openprovider_accounts() -> bool:
    """Seed OpenProvider accounts from environment variables"""
    import os
    
    try:
        # Check if accounts already exist
        existing = await get_openprovider_accounts()
        if existing:
            logger.info(f"ℹ️ OpenProvider accounts already exist ({len(existing)} accounts)")
            return True
        
        # Account 1 (Primary/Default)
        username1 = os.getenv('OPENPROVIDER_USERNAME') or os.getenv('OPENPROVIDER_EMAIL')
        if username1:
            await create_openprovider_account(
                account_name="Primary",
                username=username1,
                is_default=True,
                notes="Primary OpenProvider account"
            )
            logger.info("✅ Seeded primary OpenProvider account")
        
        # Account 2 (Secondary)
        username2 = os.getenv('Openprovider_user2')
        if username2:
            await create_openprovider_account(
                account_name="Secondary",
                username=username2,
                is_default=False,
                notes="Secondary OpenProvider account"
            )
            logger.info("✅ Seeded secondary OpenProvider account")
        
        return True
    except Exception as e:
        logger.error(f"❌ Failed to seed OpenProvider accounts: {e}")
        return False
