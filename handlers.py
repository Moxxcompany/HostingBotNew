"""
All command and callback handlers for Telegram Bot
Enhanced DNS flows with progressive disclosure UX patterns
"""

import logging
import os
import hashlib
import time
import secrets
import string
import asyncio
import ipaddress
from datetime import datetime, timedelta
from decimal import Decimal
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from typing import Optional, Dict, List, Any, Tuple, Literal
from database import (
    get_or_create_user, get_user_domains, create_domain_with_uuid, save_cloudflare_zone, 
    execute_update, execute_query, get_user_wallet_balance, get_user_wallet_balance_by_id, debit_wallet_balance,
    credit_user_wallet, get_user_wallet_transactions, reserve_wallet_balance, create_wallet_deposit_with_uuid,
    finalize_wallet_reservation, get_cloudflare_zone, get_domain_provider_id,
    update_domain_nameservers, get_domain_nameservers, get_domain_auto_proxy_enabled,
    set_domain_auto_proxy_enabled, accept_user_terms, has_user_accepted_terms,
    get_or_create_user_with_status, create_hosting_subscription_with_uuid,
    create_cpanel_account, get_hosting_subscription_details, get_domain_by_name,
    log_domain_search, create_registration_intent, update_intent_status,
    finalize_domain_registration, get_active_registration_intent, check_domain_ownership_state,
    create_hosting_intent, update_hosting_intent_status, finalize_hosting_provisioning,
    get_active_hosting_intent, get_hosting_intent_by_id,
    # UUID-based functions for new record creation
    create_payment_intent_with_uuid, create_order_with_uuid, get_order_by_uuid,
    # Domain order functions for single-table consolidation
    create_domain_order_crypto,
    # Hosting order functions for single-table consolidation
    create_hosting_order_crypto,
    # DNS Optimistic Concurrency Control functions
    get_dns_record_version, update_dns_record_version, check_dns_record_conflict,
    force_update_dns_record_version,
    check_zone_creation_lock, create_zone_with_lock, get_zone_by_domain_id
)
from services.cloudflare import CloudflareService
from services.openprovider import OpenProviderService
from services.payment_provider import create_payment_address, check_payment_status, get_current_provider_name
from services.cpanel import CPanelService
from services.vultr import vultr_service
from brand_config import (
    get_welcome_message, get_platform_name, get_dns_management_intro,
    get_service_error_message, get_payment_success_message, 
    get_domain_success_message, format_branded_message, BrandConfig,
    get_support_contact
)
from admin_handlers import (
    handle_admin_broadcast, handle_admin_credit_wallet, handle_cancel_broadcast,
    execute_admin_credit, show_admin_credit_search, handle_admin_credit_user_search,
    handle_admin_credit_amount, is_admin_user
)
from pricing_utils import format_money, calculate_marked_up_price
from crypto_config import crypto_config
from message_utils import (
    escape_html, format_bold, format_code_block, format_inline_code,
    create_success_message, create_error_message, create_info_message,
    create_warning_message, create_contact_support_message, get_platform_name as get_platform_name_html,
    render_crypto_payment, t_fmt
)
from services.registration_orchestrator import start_domain_registration as orchestrator_start_registration
from services.supported_tlds import is_supported_tld, get_unsupported_tld_message
from services.domain_linking_orchestrator import DomainLinkingOrchestrator
from localization import (
    t, t_for_user, resolve_user_language, t_html, t_html_for_user,
    set_user_language_preference, get_supported_languages, is_language_supported,
    get_user_language_preference, btn_t
)
# Import unified ID handling functions
from unified_user_id_handlers import (
    ensure_user_exists_by_telegram_id,
    get_internal_user_id_from_telegram_id,
    get_wallet_balance_by_telegram_id
)

# Region mapping cache
_region_cache = {}

def get_region_name(region_code: str) -> str:
    """Convert region code to readable name (e.g., 'ewr' -> 'Newark, US')"""
    global _region_cache
    
    if not _region_cache:
        try:
            regions = vultr_service.get_regions()
            _region_cache = {r['id']: f"{r['city']}, {r['country']}" for r in regions}
        except:
            pass
    
    return _region_cache.get(region_code, region_code.upper())

# PRODUCTION MONITORING: Enhanced logging and monitoring integration
from monitoring.production_logging import (
    get_production_logger, log_performance_metric,
    log_business_event, log_error_with_context
)
from utils.timezone_utils import ensure_utc
from performance_monitor import PerformanceMonitor
from health_monitor import get_health_monitor, log_error
from admin_alerts import send_error_alert, send_warning_alert, send_info_alert, AlertSeverity, AlertCategory

logger = logging.getLogger(__name__)

# Import shared constants to prevent circular dependencies
from services.constants import HOSTING_SERVICE_TYPES, is_hosting_bundle_service_type, enforce_hosting_context, log_routing_enforcement

# API Management handlers
from api_management_handlers import (  # type: ignore[assignment]
    show_api_management_dashboard, start_api_key_creation, handle_api_key_name_input,  # type: ignore[assignment]
    show_environment_selector, toggle_environment, show_security_settings,  # type: ignore[assignment]
    generate_and_show_api_key, show_api_key_management, show_api_key_stats,  # type: ignore[assignment]
    confirm_api_key_revoke, revoke_api_key, show_api_documentation  # type: ignore[assignment]
)

# PRODUCTION MONITORING: Initialize production logging and performance monitoring
production_logger = get_production_logger()
performance_monitor = PerformanceMonitor(window_size_seconds=60)
health_monitor = get_health_monitor()

import html
import re
from qrcode import QRCode  # type: ignore[attr-defined]
from io import BytesIO

# ====================================================================
# DNS CALLBACK DATA COMPRESSION
# ====================================================================
# Telegram has a 64-byte limit for callback_data. Long domain names + record IDs
# can easily exceed this. We use a short hash-based cache to compress the data.

_dns_callback_cache: Dict[str, Tuple[str, str, float]] = {}  # short_id -> (domain, record_id, timestamp)
_dns_nav_cache: Dict[str, Tuple[str, str, float]] = {}  # short_id -> (domain, path, timestamp)
_dns_callback_cache_ttl = 3600  # 1 hour TTL

def create_short_dns_callback(domain: str, record_id: str, action: str = "record") -> str:
    """
    Create a short callback_data for DNS operations that stays under Telegram's 64-byte limit.
    
    Format: dns_{action}:{short_id} where short_id is a 12-character hash of domain+record_id
    Actions: record (view), edit, delete
    This keeps the total under 25 bytes, well under the 64-byte limit.
    """
    # Clean up expired entries periodically
    current_time = time.time()
    expired = [k for k, v in _dns_callback_cache.items() if current_time - v[2] > _dns_callback_cache_ttl]
    for k in expired:
        del _dns_callback_cache[k]
    
    # Create short hash from domain + record_id
    data = f"{domain}:{record_id}"
    hash_obj = hashlib.sha256(data.encode())
    short_id = hash_obj.hexdigest()[:12]  # Use first 12 chars of hash
    
    # Store mapping
    _dns_callback_cache[short_id] = (domain, record_id, current_time)
    
    return f"dns_{action}:{short_id}"

def resolve_short_dns_callback(short_id: str) -> Optional[Tuple[str, str]]:
    """
    Resolve a short DNS callback ID back to (domain, record_id).
    Returns None if not found or expired.
    """
    current_time = time.time()
    if short_id in _dns_callback_cache:
        domain, record_id, timestamp = _dns_callback_cache[short_id]
        if current_time - timestamp <= _dns_callback_cache_ttl:
            return (domain, record_id)
        else:
            # Expired, remove it
            del _dns_callback_cache[short_id]
    return None

def create_short_dns_nav(domain: str, path: str) -> str:
    """
    Create compressed navigation callback for long domains.
    
    Args:
        domain: The domain name
        path: The navigation path (e.g., "add", "add:A", "nameservers", "list:2")
    
    Returns:
        Compressed callback like "dns_nav:{short_id}" (max 20 bytes)
    
    Examples:
        create_short_dns_nav("example.com", "add") -> "dns_nav:a1b2c3d4e5f6"
        create_short_dns_nav("example.com", "add:A") -> "dns_nav:x9y8z7w6v5u4"
    """
    # Clean up expired entries
    current_time = time.time()
    expired = [k for k, v in _dns_nav_cache.items() if current_time - v[2] > _dns_callback_cache_ttl]
    for k in expired:
        del _dns_nav_cache[k]
    
    # Create hash from domain + path
    data = f"{domain}:{path}"
    hash_obj = hashlib.sha256(data.encode())
    short_id = hash_obj.hexdigest()[:12]
    
    # Store mapping
    _dns_nav_cache[short_id] = (domain, path, current_time)
    
    return f"dns_nav:{short_id}"

def resolve_short_dns_nav(short_id: str) -> Optional[Tuple[str, str]]:
    """
    Resolve a short DNS navigation callback back to (domain, path).
    Returns None if not found or expired.
    """
    current_time = time.time()
    if short_id in _dns_nav_cache:
        domain, path, timestamp = _dns_nav_cache[short_id]
        if current_time - timestamp <= _dns_callback_cache_ttl:
            return (domain, path)
        else:
            del _dns_nav_cache[short_id]
    return None

def smart_dns_callback(domain: str, path: str, force_compress: bool = False) -> str:
    """
    Intelligently choose between regular and compressed DNS callbacks.
    Auto-compresses if the regular callback would exceed safe limits.
    
    Args:
        domain: The domain name
        path: The path (e.g., "add", "list", "nameservers")
        force_compress: Always use compression
    
    Returns:
        Either "dns:{domain}:{path}" or compressed "dns_nav:{short_id}"
    """
    regular_callback = f"dns:{domain}:{path}"
    
    # Use compression if forced or if callback is close to/over limit
    # We use 50 bytes as threshold to be safe (64 - 14 byte safety margin)
    if force_compress or len(regular_callback) >= 50:
        return create_short_dns_nav(domain, path)
    
    return regular_callback

# ====================================================================
# SMART AUTO-APPLY DNS RECORD MANAGEMENT SYSTEM
# ====================================================================

class AutoApplySession:
    """
    AutoApplySession Manager for DNS records with debounced auto-apply logic.
    Provides real-time validation and automatic change application after validation.
    """
    
    def __init__(self, user_id: int, domain: str, record_id: str, record_type: str, user_lang: str = 'en'):
        self.user_id = user_id
        self.domain = domain
        self.record_id = record_id
        self.record_type = record_type.upper()
        self.user_lang = user_lang
        self.original_state = {}
        self.draft_state = {}
        self.dirty_fields = set()
        self.last_change_time = 0
        self.apply_delay = 1.0  # 1 second delay
        self.is_applying = False
        self.apply_task = None
        self.validation_errors = {}
        # DNS Version Control for Optimistic Concurrency
        self.original_etag = None
        self.last_known_modified = None
        self.has_version_conflict = False
        self.conflict_resolution_needed = False
        
    async def set_original_state(self, record_data: Dict):
        """Initialize with current record state from API and version tracking"""
        # Normalize types to ensure consistent state management
        normalized_data = self._normalize_record_data(record_data)
        self.original_state = normalized_data.copy()
        self.draft_state = normalized_data.copy()
        self.dirty_fields.clear()
        
        # Initialize version control - get existing version data
        try:
            version_data = await get_dns_record_version(self.record_id)
            if version_data:
                self.original_etag = version_data.get('version_etag')
                self.last_known_modified = version_data.get('last_modified_at')
                logger.debug(f"📝 Loaded DNS version: {self.record_id} etag:{self.original_etag[:8] if self.original_etag else 'None'}...")
            else:
                # First time tracking this record - generate initial etag from content
                import hashlib
                content_str = str(sorted(normalized_data.items()))
                self.original_etag = hashlib.md5(content_str.encode()).hexdigest()
                logger.debug(f"📝 New DNS version tracking: {self.record_id} etag:{self.original_etag[:8]}...")
        except Exception as e:
            logger.warning(f"Failed to load DNS version for {self.record_id}: {e}")
            # Fall back to content-based etag
            import hashlib
            content_str = str(sorted(normalized_data.items()))
            self.original_etag = hashlib.md5(content_str.encode()).hexdigest()
        
        # Reset conflict flags
        self.has_version_conflict = False
        self.conflict_resolution_needed = False
        
    def update_field(self, field: str, value: str) -> Dict[str, Any]:
        """Update a field and trigger debounced validation/apply"""
        # Normalize the value to proper type
        normalized_value = self._normalize_field_value(field, value)
        
        # Update draft state
        old_value = self.draft_state.get(field)
        self.draft_state[field] = normalized_value
        
        # Track dirty fields by comparing with original state
        if normalized_value != self.original_state.get(field):
            self.dirty_fields.add(field)
        else:
            self.dirty_fields.discard(field)
            
        # Update change time for debouncing
        self.last_change_time = time.time()
        
        # Cancel any existing apply task
        if self.apply_task and not self.apply_task.done():
            self.apply_task.cancel()
        
        # Schedule new auto-apply task if there are changes
        if self.dirty_fields:
            self.apply_task = asyncio.create_task(self._schedule_auto_apply())
        
        # Return immediate validation results
        return self.validate_current_state()
    
    def validate_current_state(self) -> Dict[str, Any]:
        """Validate current draft state and return validation results"""
        self.validation_errors.clear()
        
        # Record type specific validation
        if self.record_type == "A":
            self._validate_a_record()
        elif self.record_type == "CNAME":
            self._validate_cname_record()
        elif self.record_type == "MX":
            self._validate_mx_record()
        elif self.record_type == "TXT":
            self._validate_txt_record()
        elif self.record_type == "AAAA":
            self._validate_aaaa_record()
            
        return {
            'valid': len(self.validation_errors) == 0,
            'errors': self.validation_errors,
            'dirty_fields': list(self.dirty_fields),
            'has_changes': len(self.dirty_fields) > 0
        }
    
    def _validate_a_record(self):
        """Validate A record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        proxied = self.draft_state.get('proxied', False)  # Now normalized to bool
        
        # IP address validation
        if not content:
            self.validation_errors['content'] = "IP address is required"
        else:
            try:
                ip = ipaddress.ip_address(content)
                if ip.version != 4:
                    self.validation_errors['content'] = t('dns.validation.ipv4_required_for_a_record', self.user_lang)
                elif proxied and not is_ip_proxyable(content):
                    self.validation_errors['content'] = get_proxy_restriction_message(content, self.user_lang)
            except (ipaddress.AddressValueError, ValueError):
                self.validation_errors['content'] = t('dns.validation.invalid_ip_address_format', self.user_lang)
                
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
        elif ttl > 86400:
            self.validation_errors['ttl'] = "TTL cannot exceed 86400 seconds (24 hours)"
    
    def _validate_aaaa_record(self):
        """Validate AAAA record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        
        # IPv6 address validation
        if not content:
            self.validation_errors['content'] = "IPv6 address is required"
        else:
            try:
                ip = ipaddress.ip_address(content)
                if ip.version != 6:
                    self.validation_errors['content'] = "IPv6 address required for AAAA records"
            except (ipaddress.AddressValueError, ValueError):
                self.validation_errors['content'] = "Invalid IPv6 address format"
                
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
    
    def _validate_cname_record(self):
        """Validate CNAME record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        
        # Target domain validation
        if not content:
            self.validation_errors['content'] = "Target domain is required"
        elif not is_valid_domain(content):
            self.validation_errors['content'] = "Target must be a valid domain name"
            
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
    
    def _validate_mx_record(self):
        """Validate MX record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        priority = self.draft_state.get('priority', 10)  # Now normalized to int
        
        # Mail server validation
        if not content:
            self.validation_errors['content'] = "Mail server is required"
        elif not is_valid_domain(content):
            self.validation_errors['content'] = "Mail server must be a valid domain name"
            
        # Priority validation (priority is now already an int)
        if priority < 0 or priority > 65535:
            self.validation_errors['priority'] = "Priority must be between 0 and 65535"
            
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
    
    def _validate_txt_record(self):
        """Validate TXT record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        
        # Content validation
        if not content:
            self.validation_errors['content'] = "TXT content is required"
        elif len(content) > 4096:
            self.validation_errors['content'] = "TXT content cannot exceed 4096 characters"
            
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
    
    async def should_auto_apply(self) -> bool:
        """Check if auto-apply should be triggered (debounced)"""
        if not self.dirty_fields or self.is_applying:
            return False
            
        # Check if enough time has passed since last change
        time_since_change = time.time() - self.last_change_time
        if time_since_change < self.apply_delay:
            return False
            
        # Validate before applying
        validation = self.validate_current_state()
        return validation['valid'] and validation['has_changes']
    
    async def auto_apply_changes(self, context) -> Dict[str, Any]:
        """Apply changes automatically with optimistic concurrency control"""
        if self.is_applying:
            return {'success': False, 'error': 'Already applying changes'}
            
        self.is_applying = True
        
        try:
            # STEP 1: Check for version conflicts before applying changes
            if self.original_etag:
                has_conflict, current_etag = await check_dns_record_conflict(self.record_id, self.original_etag)
                if has_conflict:
                    self.has_version_conflict = True
                    self.conflict_resolution_needed = True
                    logger.warning(f"🔄 DNS conflict detected: {self.record_id}, expected {self.original_etag[:8]}..., current {current_etag[:8] if current_etag else 'None'}...")
                    return {
                        'success': False,
                        'error': 'Version conflict detected',
                        'conflict': True,
                        'current_etag': current_etag,
                        'expected_etag': self.original_etag,
                        'message': 'Another user has modified this DNS record. Please refresh and try again.'
                    }
            
            # STEP 2: Get zone information
            cf_zone = await get_cloudflare_zone(self.domain)
            if not cf_zone:
                return {'success': False, 'error': 'DNS zone not found'}
            
            # STEP 3: Apply changes via CloudflareService
            cloudflare = CloudflareService()
            zone_id = cf_zone['cf_zone_id']
            
            # Prepare record data based on type
            record_data = self._prepare_record_data()
            
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=self.record_id,
                **record_data
            )
            
            if result and result.get('success'):
                # STEP 4: Success - update version tracking and clear state
                changes_applied = list(self.dirty_fields)
                
                # Generate new etag for the updated record
                import hashlib
                content_str = str(sorted(self.draft_state.items()))
                new_etag = hashlib.md5(content_str.encode()).hexdigest()
                content_hash = hashlib.sha256(content_str.encode()).hexdigest()
                
                # STEP 5: Update DNS record version tracking with CAS semantics
                try:
                    # Use Compare-And-Set to prevent race conditions
                    cas_result = await update_dns_record_version(
                        record_id=self.record_id,
                        zone_id=zone_id,
                        record_type=self.record_type,
                        version_etag=new_etag,
                        content_hash=content_hash,
                        record_data=self.draft_state,
                        expected_etag=self.original_etag  # CAS: ensure version hasn't changed
                    )
                    
                    # STEP 6: Update database with the specific record that changed (no race conditions)
                    try:
                        # Get the updated record from Cloudflare to save to database
                        updated_record = await cloudflare.get_dns_record(zone_id, self.record_id)
                        if updated_record:
                            from database import update_single_dns_record_in_db
                            await update_single_dns_record_in_db(self.domain, updated_record)
                            logger.debug(f"✅ DNS record updated in database: {self.record_id}")
                        else:
                            logger.warning(f"Could not fetch updated DNS record {self.record_id} for database sync")
                    except Exception as db_err:
                        logger.warning(f"Failed to sync updated DNS record to database: {db_err}")
                        # Don't fail the operation - Cloudflare update succeeded
                    
                    if cas_result.get('success'):
                        logger.debug(f"✅ DNS version CAS SUCCESS: {self.record_id} -> {new_etag[:8]}...")
                    elif cas_result.get('conflict'):
                        # CRITICAL: CAS CONFLICT after Cloudflare update!
                        # Cloudflare succeeded but version tracking conflicted.
                        # Since we KNOW Cloudflare has the correct state, force reconcile the database.
                        current_etag = cas_result.get('current_etag')
                        logger.warning(f"🔄 POST-APPLY CAS CONFLICT: {self.record_id}")
                        logger.warning(f"   Expected: {self.original_etag[:8] if self.original_etag else 'None'}...")
                        logger.warning(f"   Current:  {current_etag[:8] if current_etag else 'None'}...")
                        logger.warning(f"   New:      {new_etag[:8]}...")
                        logger.warning(f"   🔧 Forcing reconciliation since Cloudflare update succeeded")
                        
                        # Force reconciliation: override version tracking to match Cloudflare state
                        try:
                            force_result = await force_update_dns_record_version(
                                record_id=self.record_id,
                                zone_id=zone_id,
                                record_type=self.record_type,
                                version_etag=new_etag,
                                content_hash=content_hash,
                                record_data=self.draft_state
                            )
                            
                            if force_result.get('success'):
                                # Forced reconciliation succeeded - update session state
                                logger.info(f"✅ RECONCILIATION SUCCESS: {self.record_id} - database now matches Cloudflare state")
                                self.original_state.update(self.draft_state)
                                self.original_etag = new_etag
                                self.dirty_fields.clear()
                                self.has_version_conflict = False
                                self.conflict_resolution_needed = False
                                
                                return {
                                    'success': True,
                                    'result': result.get('result', {}),
                                    'changes_applied': changes_applied,
                                    'new_etag': new_etag,
                                    'reconciled': True
                                }
                            else:
                                # Force reconciliation failed - this is serious
                                force_error = force_result.get('error', 'Unknown error')
                                logger.error(f"🚨 RECONCILIATION FAILED: {self.record_id}: {force_error}")
                                logger.error(f"   ⚠️ CRITICAL: Cloudflare and database are now out of sync!")
                                
                                self.has_version_conflict = True
                                self.conflict_resolution_needed = True
                                
                                return {
                                    'success': True,  # Cloudflare still succeeded
                                    'result': result.get('result', {}),
                                    'changes_applied': changes_applied,
                                    'new_etag': new_etag,
                                    'warning': 'DNS updated but failed to reconcile version tracking - please contact support',
                                    'version_conflict': True,
                                    'reconciliation_failed': True,
                                    'version_conflict_details': {
                                        'expected_etag': self.original_etag,
                                        'current_etag': current_etag,
                                        'force_error': force_error,
                                        'message': 'Version reconciliation failed. DNS is updated but tracking is inconsistent.'
                                    }
                                }
                        except Exception as force_error:
                            logger.error(f"🚨 RECONCILIATION EXCEPTION: {self.record_id}: {force_error}")
                            logger.error(f"   ⚠️ CRITICAL: Cloudflare and database are now out of sync!")
                            
                            self.has_version_conflict = True
                            self.conflict_resolution_needed = True
                            
                            return {
                                'success': True,  # Cloudflare still succeeded
                                'result': result.get('result', {}),
                                'changes_applied': changes_applied,
                                'new_etag': new_etag,
                                'warning': 'DNS updated but reconciliation failed - please contact support',
                                'version_conflict': True,
                                'reconciliation_failed': True
                            }
                    else:
                        # CAS failed for other reasons
                        error_msg = cas_result.get('error', 'Unknown CAS error')
                        logger.error(f"🚫 DNS version CAS ERROR: {self.record_id}: {error_msg}")
                        # Continue - don't fail the entire operation for version tracking issues
                        
                except Exception as version_error:
                    logger.error(f"🚫 DNS version tracking exception: {self.record_id}: {version_error}")
                    # Continue - don't fail the entire operation for version tracking issues
                
                # ONLY update original state if CAS was successful (no conflicts)
                if not self.has_version_conflict:
                    # Update original state to match applied state
                    self.original_state.update(self.draft_state)
                    self.original_etag = new_etag
                    self.dirty_fields.clear()
                    self.has_version_conflict = False
                    self.conflict_resolution_needed = False
                    
                    return {
                        'success': True,
                        'result': result.get('result', {}),
                        'changes_applied': changes_applied,
                        'new_etag': new_etag
                    }
                else:
                    # CAS conflict was already handled above - session remains in conflict state
                    # Return success since Cloudflare update succeeded, just with conflict warning
                    return {
                        'success': True,
                        'result': result.get('result', {}),
                        'changes_applied': changes_applied,
                        'version_conflict': True,
                        'warning': 'Changes applied but version conflict detected'
                    }
            else:
                # API failed - keep draft state for retry
                errors = result.get('errors', [{'message': 'Unknown error'}]) if result else [{'message': 'API call failed'}]
                return {
                    'success': False,
                    'error': errors[0].get('message', 'Update failed'),
                    'api_errors': errors
                }
                
        except Exception as e:
            logger.error(f"Auto-apply error for {self.record_type} record {self.record_id}: {e}")
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }
        finally:
            self.is_applying = False
    
    def _normalize_record_data(self, record_data: Dict) -> Dict:
        """Normalize record data to consistent types"""
        normalized = record_data.copy()
        
        # Normalize TTL to integer
        if 'ttl' in normalized:
            try:
                normalized['ttl'] = int(normalized['ttl'])
            except (ValueError, TypeError):
                normalized['ttl'] = 300  # Default TTL
        
        # Normalize proxied to boolean
        if 'proxied' in normalized:
            if isinstance(normalized['proxied'], str):
                normalized['proxied'] = normalized['proxied'].lower() == 'true'
            elif not isinstance(normalized['proxied'], bool):
                normalized['proxied'] = bool(normalized['proxied'])
        
        # Normalize priority to integer for MX records
        if 'priority' in normalized:
            try:
                normalized['priority'] = int(normalized['priority'])
            except (ValueError, TypeError):
                normalized['priority'] = 10  # Default priority
        
        # Ensure content is always a string
        if 'content' in normalized:
            normalized['content'] = str(normalized['content'])
        
        # Ensure name is always a string
        if 'name' in normalized:
            normalized['name'] = str(normalized['name'])
            
        return normalized
    
    def _normalize_field_value(self, field: str, value: str):
        """Normalize a single field value to the appropriate type"""
        if field == 'ttl':
            try:
                return int(value)
            except (ValueError, TypeError):
                return 300  # Default TTL
        elif field == 'proxied':
            if isinstance(value, str):
                return value.lower() == 'true'
            return bool(value)
        elif field == 'priority':
            try:
                return int(value)
            except (ValueError, TypeError):
                return 10  # Default priority
        else:
            # All other fields remain as strings
            return str(value)
    
    async def _schedule_auto_apply(self):
        """Schedule auto-apply after debounce delay"""
        try:
            # Wait for debounce delay
            await asyncio.sleep(self.apply_delay)
            
            # Validate before applying
            validation = self.validate_current_state()
            if validation['valid'] and validation['has_changes']:
                logger.info(f"Auto-applying changes for {self.record_type} record {self.record_id}")
                result = await self.auto_apply_changes(None)
                
                if result and result.get('success'):
                    logger.info(f"Auto-apply successful for {self.record_type} record {self.record_id}")
                else:
                    error_msg = result.get('error', 'Unknown error') if result else 'No result returned'
                    logger.warning(f"Auto-apply failed for {self.record_type} record {self.record_id}: {error_msg}")
            else:
                logger.debug(f"Skipping auto-apply for {self.record_type} record {self.record_id}: validation failed or no changes")
                
        except asyncio.CancelledError:
            logger.debug(f"Auto-apply cancelled for {self.record_type} record {self.record_id}")
        except Exception as e:
            logger.error(f"Error in auto-apply scheduling for {self.record_type} record {self.record_id}: {e}")
    
    def _prepare_record_data(self) -> Dict:
        """Prepare record data for API call based on record type"""
        base_data = {
            'record_type': self.record_type,
            'name': self.draft_state.get('name', ''),
            'content': self.draft_state.get('content', ''),
            'ttl': int(self.draft_state.get('ttl', 300))
        }
        
        # Add type-specific fields
        if self.record_type == 'A':
            base_data['proxied'] = self.draft_state.get('proxied', 'false') == 'true'
        elif self.record_type == 'MX':
            base_data['priority'] = int(self.draft_state.get('priority', 10))
            
        return base_data
    
    def revert_to_original(self):
        """Revert draft state back to original state"""
        self.draft_state = self.original_state.copy()
        self.dirty_fields.clear()
        self.validation_errors.clear()
    
    def get_changes_summary(self) -> List[str]:
        """Get human-readable summary of changes"""
        changes = []
        for field in self.dirty_fields:
            old_value = self.original_state.get(field, '')
            new_value = self.draft_state.get(field, '')
            
            # Format values for display
            if field == 'ttl':
                old_display = "Auto" if old_value == '1' else f"{old_value}s"
                new_display = "Auto" if new_value == '1' else f"{new_value}s"
                changes.append(f"TTL: {old_display} → {new_display}")
            elif field == 'proxied':
                old_display = "🟠 Proxied" if old_value == 'true' else "⚪ Direct"
                new_display = "🟠 Proxied" if new_value == 'true' else "⚪ Direct"
                changes.append(f"Proxy: {old_display} → {new_display}")
            elif field == 'content':
                if self.record_type == 'A':
                    changes.append(f"IP: {old_value} → {new_value}")
                elif self.record_type == 'CNAME':
                    changes.append(f"Target: {old_value} → {new_value}")
                elif self.record_type == 'MX':
                    changes.append(f"Server: {old_value} → {new_value}")
                else:
                    changes.append(f"Content: {old_value} → {new_value}")
            elif field == 'priority':
                changes.append(f"Priority: {old_value} → {new_value}")
            else:
                changes.append(f"{field.title()}: {old_value} → {new_value}")
                
        return changes


class DNSAutoApplyManager:
    """Global manager for DNS auto-apply sessions"""
    
    def __init__(self):
        self.sessions = {}  # user_id:record_id -> AutoApplySession
        
    def get_session(self, user_id: int, domain: str, record_id: str, record_type: str, user_lang: str = 'en') -> AutoApplySession:
        """Get or create auto-apply session for a DNS record"""
        session_key = f"{user_id}:{record_id}"
        
        if session_key not in self.sessions:
            self.sessions[session_key] = AutoApplySession(user_id, domain, record_id, record_type, user_lang)
        else:
            # Update language for existing session
            self.sessions[session_key].user_lang = user_lang
            
        return self.sessions[session_key]
    
    def cleanup_session(self, user_id: int, record_id: str):
        """Clean up session when editing is complete"""
        session_key = f"{user_id}:{record_id}"
        if session_key in self.sessions:
            del self.sessions[session_key]
    
    async def process_pending_applies(self, context):
        """Process any pending auto-applies across all sessions"""
        for session in list(self.sessions.values()):
            if await session.should_auto_apply():
                await session.auto_apply_changes(context)

# Global DNS auto-apply manager instance
dns_auto_apply_manager = DNSAutoApplyManager()


# Enhanced validation functions
def validate_dns_record_field(record_type: str, field: str, value: str, user_lang: str = 'en') -> Dict[str, Any]:
    """Enhanced field-level validation for DNS records"""
    errors = {}
    
    if record_type.upper() == 'A' and field == 'content':
        # A record IP validation
        try:
            ip = ipaddress.ip_address(value)
            if ip.version != 4:
                errors[field] = t('dns.validation.ipv4_required_for_a_record', user_lang)
        except (ipaddress.AddressValueError, ValueError):
            errors[field] = t('dns.validation.invalid_ip_address_format', user_lang)
    
    elif record_type.upper() == 'AAAA' and field == 'content':
        # AAAA record IPv6 validation
        try:
            ip = ipaddress.ip_address(value)
            if ip.version != 6:
                errors[field] = "IPv6 address required for AAAA records"
        except (ipaddress.AddressValueError, ValueError):
            errors[field] = "Invalid IPv6 address format"
    
    elif record_type.upper() == 'CNAME' and field == 'content':
        # CNAME target validation
        if not is_valid_domain(value):
            errors[field] = "Target must be a valid domain name"
    
    elif record_type.upper() == 'MX' and field == 'content':
        # MX server validation
        if not is_valid_domain(value):
            errors[field] = "Mail server must be a valid domain name"
    
    elif field == 'ttl':
        # TTL validation for all record types
        try:
            ttl_int = int(value)
            if ttl_int < 1:
                errors[field] = "TTL must be 1 (Auto) or higher"
            elif ttl_int > 86400:
                errors[field] = "TTL cannot exceed 86400 seconds"
        except (ValueError, TypeError):
            errors[field] = "TTL must be a valid number"
    
    elif field == 'priority' and record_type.upper() == 'MX':
        # MX priority validation
        try:
            priority_int = int(value)
            if priority_int < 0 or priority_int > 65535:
                errors[field] = "Priority must be between 0 and 65535"
        except (ValueError, TypeError):
            errors[field] = "Priority must be a valid number"
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }

# Auto-apply feedback function
async def auto_apply_with_feedback(query, context, session: AutoApplySession):
    """Apply changes with real-time feedback updates"""
    try:
        # Brief delay to allow debouncing
        await asyncio.sleep(0.5)
        
        # Re-check if we should still apply (user might have made more changes)
        if not await session.should_auto_apply():
            return
            
        # Apply changes
        result = await session.auto_apply_changes(context)
        
        if result['success']:
            logger.info(f"Auto-applied DNS changes for {session.record_type} record {session.record_id}")
            
            # Get current wizard state to refresh the UI
            wizard_state = context.user_data.get('dns_wizard')
            if wizard_state and wizard_state.get('record_id') == session.record_id:
                # Refresh the editing interface to show success state
                if session.record_type == 'A':
                    await continue_a_record_edit_wizard(query, context, wizard_state)
                elif session.record_type == 'CNAME':
                    await continue_cname_record_edit_wizard(query, wizard_state)
                elif session.record_type == 'TXT':
                    await continue_txt_record_edit_wizard(query, wizard_state)
                elif session.record_type == 'MX':
                    await continue_mx_record_edit_wizard(query, wizard_state)
                    
        else:
            logger.error(f"Auto-apply failed for {session.record_type} record {session.record_id}: {result['error']}")
            
            # Get user language for localized buttons
            user = query.from_user
            user_lang = await resolve_user_language(user.id, user.language_code) if user else 'en'
            
            # Show error message with retry option
            error_message = f"""
❌ Auto-Apply Failed

{result['error']}

Changes have been reverted. You can modify the record and it will auto-apply when valid.
"""
            
            keyboard = [
                [InlineKeyboardButton(btn_t('try_again', user_lang), callback_data=f"dns:{session.domain}:edit:{session.record_id}")],
                [InlineKeyboardButton(btn_t('back_to_record', user_lang), callback_data=f"dns:{session.domain}:record:{session.record_id}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            try:
                await safe_edit_message(query, error_message, reply_markup=reply_markup)
            except Exception as e:
                logger.error(f"Error showing auto-apply feedback: {e}")
                
    except Exception as e:
        logger.error(f"Error in auto_apply_with_feedback: {e}")

# ====================================================================
# END AUTO-APPLY SYSTEM
# ====================================================================

def is_ip_proxyable(ip_str):
    """Check if an IP address can be proxied by Cloudflare (must be public)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # IPv4 checks
        if ip.version == 4:
            # Private networks (RFC 1918)
            if ip.is_private:
                return False
            # Loopback (127.x.x.x)
            if ip.is_loopback:
                return False
            # Link-local (169.254.x.x)
            if ip.is_link_local:
                return False
            # Multicast
            if ip.is_multicast:
                return False
            # Reserved/unspecified
            if ip.is_reserved or ip.is_unspecified:
                return False
            # Test networks (RFC 3927, RFC 5737)
            test_networks = [
                ipaddress.IPv4Network('192.0.2.0/24'),    # TEST-NET-1
                ipaddress.IPv4Network('198.51.100.0/24'), # TEST-NET-2
                ipaddress.IPv4Network('203.0.113.0/24'),  # TEST-NET-3
            ]
            for test_net in test_networks:
                if ip in test_net:
                    return False
                    
        # IPv6 checks
        elif ip.version == 6:
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False
            if ip.is_reserved or ip.is_unspecified:
                return False
                
        # If we get here, it's a public IP
        return True
        
    except (ipaddress.AddressValueError, ValueError):
        # Invalid IP format
        return False

def get_proxy_restriction_message(ip_str, user_lang='en'):
    """Get user-friendly message explaining why an IP cannot be proxied"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        if ip.is_private:
            return t('proxy.private_ip_restriction', user_lang, ip_str=ip_str)
        elif ip.is_loopback:
            return t('proxy.localhost_restriction', user_lang, ip_str=ip_str)
        elif ip.is_link_local:
            return t('proxy.link_local_restriction', user_lang, ip_str=ip_str)
        else:
            return t('proxy.reserved_ip_restriction', user_lang, ip_str=ip_str)
            
    except (ipaddress.AddressValueError, ValueError):
        return t('proxy.invalid_ip_format', user_lang, ip_str=ip_str)

async def get_available_names_for_record_type(domain, record_type, zone_id):
    """Get available DNS names for a specific record type based on existing records"""
    try:
        cloudflare = CloudflareService()
        existing_records = await cloudflare.list_dns_records(zone_id)
        
        if not existing_records:
            # No existing records, all names available
            common_names = ['@', 'www', 'mail', 'blog', 'app', 'api', 'ftp']
            return [{'name': name, 'display': name if name != '@' else f'@ (root)', 'description': _get_name_description(name, domain)} for name in common_names]
        
        # Group existing records by name
        records_by_name = {}
        for record in existing_records:
            name = record.get('name', '')
            # Normalize root domain name to @
            if name == domain:
                name = '@'
            elif name.endswith(f'.{domain}'):
                name = name[:-len(f'.{domain}')]
            
            if name not in records_by_name:
                records_by_name[name] = []
            records_by_name[name].append(record.get('type', ''))
        
        # Determine available names based on record type
        available_names = []
        common_names = ['@', 'www', 'mail', 'blog', 'app', 'api', 'ftp', 'shop']
        
        for name in common_names:
            existing_types = records_by_name.get(name, [])
            
            if record_type == 'CNAME':
                # CNAME can only exist if NO other records exist at this name
                if not existing_types:
                    available_names.append({
                        'name': name,
                        'display': name if name != '@' else f'@ (root)',
                        'description': _get_name_description(name, domain)
                    })
            else:
                # A, TXT, MX can coexist with each other but not with CNAME
                if 'CNAME' not in existing_types:
                    available_names.append({
                        'name': name,
                        'display': name if name != '@' else f'@ (root)',
                        'description': _get_name_description(name, domain)
                    })
        
        return available_names
        
    except Exception as e:
        logger.error(f"Error getting available names: {e}")
        # Fallback to basic options
        return [{'name': 'www', 'display': 'www', 'description': f'www.{domain}'}]

def _get_name_description(name, domain):
    """Get user-friendly description for DNS name"""
    if name == '@':
        return f'{domain} (root domain)'
    elif name == 'www':
        return f'www.{domain} (website)'
    elif name == 'mail':
        return f'mail.{domain} (email server)'
    elif name == 'blog':
        return f'blog.{domain} (blog subdomain)'
    elif name == 'app':
        return f'app.{domain} (application)'
    elif name == 'api':
        return f'api.{domain} (API endpoint)'
    elif name == 'ftp':
        return f'ftp.{domain} (file transfer)'
    elif name == 'shop':
        return f'shop.{domain} (online store)'
    else:
        return f'{name}.{domain}'

def is_valid_domain(domain_name):
    """Validate if string is a proper domain name with comprehensive RFC compliance"""
    import idna
    
    if not domain_name or not isinstance(domain_name, str):
        return False
    
    # Clean and normalize input
    domain_name = domain_name.strip()
    if not domain_name:
        return False
    
    # Handle IDN (Internationalized Domain Names) conversion
    try:
        # Convert Unicode domain to ASCII (punycode)
        ascii_domain = idna.encode(domain_name, uts46=True).decode('ascii')
    except (idna.core.IDNAError, UnicodeError, UnicodeDecodeError):
        return False
    
    # Use ASCII version for validation
    domain_to_validate = ascii_domain.lower()
    
    # RFC 1035/1123 total length limit (253 characters)
    if len(domain_to_validate) > 253 or len(domain_to_validate) < 3:
        return False
    
    # Check for invalid patterns
    if '..' in domain_to_validate or domain_to_validate.startswith('.') or domain_to_validate.endswith('.'):
        return False
    
    # Split into labels and validate each
    labels = domain_to_validate.split('.')
    if len(labels) < 2:
        return False
    
    # Validate each label
    for label in labels:
        # RFC 1123 label length limit (63 characters per label)
        if len(label) > 63 or len(label) == 0:
            return False
        
        # Labels cannot start or end with hyphens
        if label.startswith('-') or label.endswith('-'):
            return False
        
        # Check for valid characters only (a-z, 0-9, hyphens)
        if not re.match(r'^[a-z0-9-]+$', label):
            return False
    
    # TLD cannot be all numeric and must be at least 2 characters (standard practice)
    tld = labels[-1]
    if tld.isdigit():
        return False
    
    # TLD must be at least 2 characters (no single character TLDs allowed)
    if len(tld) < 2:
        return False
    
    # Check subdomain level limit (max 10 levels as per OpenProvider)
    if len(labels) > 11:  # 10 subdomains + 1 TLD = 11 total parts
        return False
    
    return True

def validate_domain_name(domain: str) -> bool:
    """Wrapper function for domain validation - expected by tests"""
    return is_valid_domain(domain)

def validate_email_format(email: str) -> bool:
    """Validate email address format - expected by tests"""
    if not email or not isinstance(email, str):
        return False
    
    email = email.strip()
    if not email or '@' not in email:
        return False
    
    parts = email.split('@')
    if len(parts) != 2:
        return False
    
    local, domain = parts
    if not local or not domain:
        return False
    
    # Check local part (before @)
    if len(local) > 64 or len(local) == 0:
        return False
    
    # Check domain part (after @)
    if not is_valid_domain(domain):
        return False
    
    return True

def get_domain_validation_error(domain_name, user_lang=None) -> str:
    """Get specific error message for domain validation failure"""
    # Ensure user_lang has a value
    if user_lang is None:
        user_lang = 'en'
    
    # For detailed validation errors, use OpenProvider's validation function
    try:
        from services.openprovider import OpenProviderService
        service = OpenProviderService()
        validation_result = service.validate_domain_rfc_compliant(domain_name)
        
        if not validation_result['valid']:
            return validation_result['error']
        else:
            return t('domain.validation.valid', user_lang)
            
    except Exception as e:
        # Fallback to basic error messages if OpenProvider service fails
        if not domain_name or not isinstance(domain_name, str):
            return t('domain.validation.required', user_lang)
        
        domain_name = domain_name.strip()
        if not domain_name:
            return t('domain.validation.cannot_be_empty', user_lang)
        
        if len(domain_name) > 253:
            return t('domain.validation.too_long', user_lang, length=len(domain_name))
        
        if len(domain_name) < 3:
            return t('domain.validation.too_short', user_lang)
        
        if '..' in domain_name:
            return t('domain.validation.consecutive_dots', user_lang)
        
        if domain_name.startswith('.') or domain_name.endswith('.'):
            return t('domain.validation.dot_edges', user_lang)
        
        if '.' not in domain_name:
            return t('domain.validation.needs_dot', user_lang)
        
        return t('domain.validation.invalid_format', user_lang)

def is_valid_nameserver(nameserver):
    """Validate if a string is a valid nameserver"""
    if not nameserver or len(nameserver) > 253:
        return False
    
    # Nameserver must be a valid domain name (FQDN)
    nameserver_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(nameserver_pattern, nameserver.strip().lower()))

# DNS resolution logic moved to services/dns_resolver.py

def detect_nameserver_provider(nameservers):
    """Detect if nameservers are from Cloudflare or external provider"""
    if not nameservers:
        return "unknown", "No nameservers found"
    
    cloudflare_ns_patterns = [
        'cloudflare.com',
        'ns.cloudflare.com',
        '.cloudflare.com'
    ]
    
    # Check if any nameserver contains cloudflare patterns
    for ns in nameservers:
        ns_lower = ns.lower()
        for pattern in cloudflare_ns_patterns:
            if pattern in ns_lower:
                return "cloudflare", "Cloudflare DNS"
    
    # Check for common providers
    common_providers = {
        'google': ['ns-cloud'],
        'namecheap': ['registrar-servers.com'],
        'godaddy': ['domaincontrol.com'],
        'amazon': ['awsdns'],
        'digitalocean': ['digitalocean.com']
    }
    
    for provider, patterns in common_providers.items():
        for ns in nameservers:
            ns_lower = ns.lower()
            for pattern in patterns:
                if pattern in ns_lower:
                    return "external", f"{provider.title()} DNS"
    
    return "external", "Custom DNS"

def extract_provider_key(provider_name: str) -> str:
    """Extract provider key from detected provider name for consistent matching"""
    if not provider_name:
        return ""
    
    provider_lower = provider_name.lower()
    
    # Map provider names to consistent keys
    if 'godaddy' in provider_lower:
        return 'godaddy'
    elif 'namecheap' in provider_lower:
        return 'namecheap'
    elif 'google' in provider_lower:
        return 'google domains'
    elif 'cloudflare' in provider_lower:
        return 'cloudflare'
    elif 'amazon' in provider_lower or 'aws' in provider_lower:
        return 'amazon'
    elif 'digitalocean' in provider_lower:
        return 'digitalocean'
    else:
        return provider_lower.replace(' dns', '').replace(' nameservers', '').strip()

async def analyze_domain_nameservers(domain_name: str) -> dict:
    """Analyze domain nameservers for hosting setup automation"""
    try:
        import socket
        import asyncio
        import shutil
        
        # Get current nameservers using async dig or fallback to Python DNS
        nameservers = []
        
        # Check if dig command is available
        if shutil.which('dig'):
            try:
                # Use async subprocess to prevent blocking
                process = await asyncio.create_subprocess_exec(
                    'dig', '+short', 'NS', domain_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Wait for completion with timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=8.0
                )
                
                if process.returncode == 0 and stdout:
                    stdout_text = stdout.decode('utf-8').strip()
                    if stdout_text:
                        nameservers = [ns.strip().rstrip('.') for ns in stdout_text.split('\n') if ns.strip()]
                        
            except (asyncio.TimeoutError, OSError, UnicodeDecodeError) as e:
                logger.warning(f"dig command failed for {domain_name}: {e}")
                nameservers = []
        else:
            # Fallback: dig not available, use dedicated DNS resolver service
            try:
                from services.dns_resolver import dns_resolver
                nameservers = await dns_resolver.get_nameservers(domain_name)
                if nameservers:
                    logger.debug(f"✅ DNS resolver found {len(nameservers)} nameservers for {domain_name}")
            except Exception as e:
                logger.warning(f"DNS resolver service failed for {domain_name}: {e}")
                nameservers = []
        
        # Final fallback to stored nameservers if all methods fail
        if not nameservers:
            try:
                nameservers = await get_domain_nameservers(domain_name) or []
            except Exception as e:
                logger.warning(f"Database nameserver lookup failed for {domain_name}: {e}")
                nameservers = []
        
        # Detect provider and get analysis
        provider_type, provider_name = detect_nameserver_provider(nameservers)
        
        # Get hosting nameservers (this would be your hosting provider's nameservers)
        hosting_nameservers = get_hosting_nameservers()
        
        # Check if domain is already using hosting nameservers
        is_hosting_configured = False
        if nameservers and hosting_nameservers:
            hosting_ns_set = set(ns.lower() for ns in hosting_nameservers)
            current_ns_set = set(ns.lower() for ns in nameservers)
            is_hosting_configured = hosting_ns_set <= current_ns_set
        
        return {
            'domain': domain_name,
            'current_nameservers': nameservers,
            'provider_type': provider_type,
            'provider_name': provider_name,
            'hosting_nameservers': hosting_nameservers,
            'is_hosting_configured': is_hosting_configured,
            'needs_nameserver_change': not is_hosting_configured
        }
        
    except Exception as e:
        logger.error(f"Error analyzing nameservers for {domain_name}: {e}")
        return {
            'domain': domain_name,
            'current_nameservers': [],
            'provider_type': 'unknown',
            'provider_name': 'Unknown',
            'hosting_nameservers': get_hosting_nameservers(),
            'is_hosting_configured': False,
            'needs_nameserver_change': True,
            'error': str(e)
        }

def get_hosting_nameservers() -> list:
    """Get the nameservers that should be used for hosting"""
    # Use centralized configuration
    from config import get_config
    
    try:
        config = get_config()
        nameservers = config.services.hosting_nameservers
        logger.info(f"Using configured nameservers: {nameservers}")
        return nameservers
    except Exception as e:
        logger.warning(f"Failed to get nameservers from config, using fallback: {e}")
        
        # Emergency fallback
        return [
            'ava.ns.cloudflare.com',
            'kai.ns.cloudflare.com'
        ]

async def generate_hosting_nameserver_guidance(domain_name: str, analysis: dict, plan_name: str, user_lang: str = 'en') -> str:
    """Generate comprehensive nameserver setup guidance for hosting"""
    try:
        current_ns = analysis.get('current_nameservers', [])
        provider_name = analysis.get('provider_name', 'Unknown Provider')
        hosting_ns = analysis.get('hosting_nameservers', [])
        is_configured = analysis.get('is_hosting_configured', False)
        
        # Format nameserver lists for display
        ns_list = chr(10).join(f"• {escape_html(ns)}" for ns in hosting_ns)
        
        if is_configured:
            return t('hosting.nameserver.already_configured', user_lang, nameservers=ns_list)
        
        if not current_ns:
            ns_list_indented = chr(10).join(f"   • {escape_html(ns)}" for ns in hosting_ns)
            return t('hosting.nameserver.setup_instructions', user_lang, nameservers=ns_list_indented)
        
        # Generate provider-specific instructions
        # Extract provider name from detected provider (e.g., "GoDaddy DNS" -> "godaddy")
        provider_key = extract_provider_key(provider_name)
        if provider_key in ['godaddy', 'namecheap', 'google domains']:
            provider_instructions = get_provider_specific_instructions(provider_key, hosting_ns, user_lang)
        else:
            provider_instructions = get_generic_nameserver_instructions(hosting_ns, user_lang)
        
        # Format current nameservers
        current_ns_list = chr(10).join(f"• {escape_html(ns)}" for ns in current_ns[:3])
        
        return t('hosting.nameserver.required_nameservers', user_lang, 
                provider_name=escape_html(provider_name),
                current_nameservers=current_ns_list,
                hosting_nameservers=ns_list,
                provider_instructions=provider_instructions)
        
    except Exception as e:
        logger.error(f"Error generating nameserver guidance: {e}")
        ns_list = chr(10).join(f"• {escape_html(ns)}" for ns in get_hosting_nameservers())
        return t('hosting.nameserver.error_fallback', user_lang, nameservers=ns_list)

def get_provider_specific_instructions(provider: str, hosting_ns: list, user_lang: str = 'en') -> str:
    """Get provider-specific nameserver change instructions"""
    escaped_nameservers = ', '.join(escape_html(ns) for ns in hosting_ns)
    
    instructions = {
        'godaddy': t('hosting.nameserver.godaddy_instructions', user_lang, nameservers=escaped_nameservers),
        'namecheap': t('hosting.nameserver.namecheap_instructions', user_lang, nameservers=escaped_nameservers),
        'google domains': t('hosting.nameserver.google_instructions', user_lang, nameservers=escaped_nameservers)
    }
    
    return instructions.get(provider, get_generic_nameserver_instructions(hosting_ns, user_lang))

def get_generic_nameserver_instructions(hosting_ns: list, user_lang: str = 'en') -> str:
    """Get generic nameserver change instructions"""
    ns_list = chr(10).join(f"   • {escape_html(ns)}" for ns in hosting_ns)
    return t('hosting.nameserver.generic_instructions', user_lang, nameservers=ns_list)

async def show_hosting_management(query, subscription_id: str):
    """Show individual hosting account management interface"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user language early for translations
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.unknown", user_lang)
        plan_name = subscription.get('plan_name') or t("common_labels.unknown", user_lang)
        status = subscription.get('status', 'unknown')
        cpanel_username = subscription.get('cpanel_username') or t("common_labels.not_assigned", user_lang)
        created_date = subscription.get('created_at', '')
        
        # Format creation date
        if created_date:
            try:
                from datetime import datetime
                if isinstance(created_date, str):
                    created_date = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                formatted_date = created_date.strftime('%B %d, %Y')
            except:
                formatted_date = str(created_date)[:10]
        else:
            formatted_date = t("common_labels.unknown", user_lang)
        
        # Status indicator and available actions
        if status == 'active':
            status_icon = "🟢"
            status_text = t("common_labels.active", user_lang)
            action_buttons = [
                [InlineKeyboardButton(btn_t('suspend_account', user_lang), callback_data=f"suspend_hosting_{subscription_id}")],
                [InlineKeyboardButton(btn_t('restart_services', user_lang), callback_data=f"restart_hosting_{subscription_id}")]
            ]
        elif status == 'suspended':
            status_icon = "🔴"
            status_text = t("common_labels.suspended", user_lang)
            
            # Show days until deletion if deletion is scheduled
            deletion_scheduled = subscription.get('deletion_scheduled_for')
            days_until_deletion = "?"
            if deletion_scheduled:
                from datetime import datetime, timezone
                days_left = (deletion_scheduled - datetime.now(timezone.utc)).days
                days_until_deletion = max(0, days_left)
            
            action_buttons = [
                [InlineKeyboardButton(btn_t("renew_hosting", user_lang, days=days_until_deletion), callback_data=f"renew_suspended_{subscription_id}")]
            ]
        elif status == 'pending':
            status_icon = "🟡"
            status_text = t("common_labels.pending_setup", user_lang)
            action_buttons = []
        else:
            status_icon = "⚪"
            status_text = t(f"common_labels.{status.lower()}", user_lang) if status and status.lower() in ["active", "suspended", "pending", "expired", "failed"] else t("common_labels.unknown", user_lang)
            action_buttons = []
        
        message = f"""
🏠 <b>{t("hosting.management_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.plan", user_lang)}</b> {plan_name}
<b>{t("common_labels.status", user_lang)}</b> {status_icon} {status_text}
<b>{t("hosting.cpanel_username_label", user_lang)}</b> <code>{cpanel_username}</code>
<b>{t("common_labels.created", user_lang)}</b> {formatted_date}

{get_hosting_status_description(status, user_lang)}
"""
        
        keyboard = []
        
        # Add management actions
        keyboard.extend(action_buttons)
        
        # Add information buttons
        keyboard.extend([
            [InlineKeyboardButton(btn_t('account_details', user_lang), callback_data=f"hosting_details_{subscription_id}")],
            [InlineKeyboardButton(btn_t('cpanel_login', user_lang), callback_data=f"cpanel_login_{subscription_id}")],
            [InlineKeyboardButton(btn_t('usage_stats', user_lang), callback_data=f"hosting_usage_{subscription_id}")]
        ])
        
        # Navigation
        keyboard.extend([
            [InlineKeyboardButton(btn_t('back_to_my_hosting', user_lang), callback_data="my_hosting")],
            [InlineKeyboardButton(btn_t('main_menu', user_lang), callback_data="main_menu")]
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing hosting management: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code)
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def show_hosting_details(query, subscription_id: str):
    """Show detailed hosting account information"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user language early for translations
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.not_assigned", user_lang)
        plan_name = subscription.get('plan_name') or t("common_labels.unknown", user_lang)
        status = subscription.get('status', 'unknown')
        server_ip = subscription.get('server_ip') or t("common_labels.not_assigned", user_lang)
        created_at = subscription.get('created_at')
        next_billing = subscription.get('next_billing_date')
        
        # Format dates
        formatted_created = created_at.strftime("%B %d, %Y") if created_at else t("common_labels.unknown", user_lang)
        formatted_billing = next_billing.strftime("%B %d, %Y") if next_billing else t("common_labels.unknown", user_lang)
        
        # Format status text
        if status and status.lower() in ["active", "suspended", "pending", "pending_setup", "expired", "failed"]:
            status_display = t(f"common_labels.{status.lower()}", user_lang)
        else:
            status_display = t("common_labels.unknown", user_lang)
        
        message = f"""
📊 <b>{t("hosting.account_details_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.plan", user_lang)}</b> {plan_name}
<b>{t("common_labels.server_ip", user_lang)}</b> <code>{server_ip}</code>
<b>{t("common_labels.status", user_lang)}</b> {status_display}
<b>{t("common_labels.created", user_lang)}</b> {formatted_created}
<b>{t("common_labels.next_billing", user_lang)}</b> {formatted_billing}

💡 {t("hosting.account_details_info", user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(btn_t('back_to_management', user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing hosting details: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code)
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def show_cpanel_login(query, subscription_id: str):
    """Show cPanel login credentials with copy functionality"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user language early for translations
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        not_assigned = t("common_labels.not_assigned", user_lang)
        domain_name = subscription.get('domain_name', 'hostingbay.sbs')
        cpanel_username = subscription.get('cpanel_username') or not_assigned
        cpanel_password = subscription.get('cpanel_password') or not_assigned
        server_ip = subscription.get('server_ip') or not_assigned
        
        # Construct cPanel URL
        cpanel_url = f"https://{domain_name}:2083" if domain_name != not_assigned else f"https://{server_ip}:2083"
        
        message = f"""
🔧 <b>{t("hosting.cpanel_login_title", user_lang)}</b>

<b>🌐 {t("common_labels.url", user_lang)}</b> <code>{cpanel_url}</code>
<b>👤 {t("common_labels.username", user_lang)}</b> <code>{cpanel_username}</code>
<b>🔑 {t("common_labels.password", user_lang)}</b> <code>{cpanel_password}</code>
<b>🖥️ {t("common_labels.server", user_lang)}</b> <code>{server_ip}</code>

💡 {t("hosting.tap_to_copy", user_lang)}
💾 {t("hosting.save_credentials", user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(btn_t('back_to_management', user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing cPanel login: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code)
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def show_hosting_usage(query, subscription_id: str):
    """Show hosting usage statistics"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user language early for translations
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.not_assigned", user_lang)
        plan_name = subscription.get('plan_name') or t("common_labels.unknown", user_lang)
        unlimited_text = t("hosting.unlimited", user_lang)
        
        # For now, show placeholder usage stats (can be enhanced with real cPanel API integration)
        message = f"""
📈 <b>{t("hosting.usage_statistics_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.plan", user_lang)}</b> {plan_name}

<b>📦 {t("hosting.disk_usage_label", user_lang)}</b> 0.1 GB / 5.0 GB (2%)
<b>📊 {t("hosting.bandwidth_label", user_lang)}</b> 0.5 GB / 50 GB (1%)
<b>📁 {t("hosting.files_label", user_lang)}</b> 12 / {unlimited_text}
<b>📧 {t("hosting.email_accounts_label", user_lang)}</b> 1 / {unlimited_text}
<b>🗂️ {t("hosting.databases_label", user_lang)}</b> 0 / 10

<b>⏱️ {t("hosting.uptime_label", user_lang)}</b> 99.9%
<b>🔄 {t("hosting.last_updated_label", user_lang)}</b> {t("hosting.just_now", user_lang)}

💡 {t("hosting.usage_update_hourly", user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(btn_t('back_to_management', user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing hosting usage: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code)
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def handle_renew_suspended_hosting(query, subscription_id: str):
    """Show payment options for manually renewing suspended hosting account"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details, get_user_wallet_balance
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        # Get user language early for translations
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        if not subscription:
            await safe_edit_message(query, f"❌ {t('hosting.not_found_or_denied', user_lang)}")
            return
        
        if subscription['status'] != 'suspended':
            await safe_edit_message(query, f"⚠️ This account is not suspended.")
            return
        
        domain_name = subscription.get('domain_name', 'unknown')
        plan_name = subscription.get('plan_name') or t("common_labels.unknown", user_lang)
        
        # Calculate renewal cost based on plan
        from database import get_hosting_plan
        plan_id = subscription.get('plan_id')
        if not plan_id:
            await safe_edit_message(query, f"❌ {t('hosting.invalid_plan_contact_support', user_lang)}")
            return
        plan = await get_hosting_plan(int(plan_id))
        renewal_cost = plan['monthly_price'] if plan else 0.0
        
        # Get current wallet balance (use telegram_id, not internal user_id)
        wallet_balance = await get_user_wallet_balance(user.id)
        
        # Create message
        message = f"""
💳 <b>{t("renewal.title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.plan", user_lang)}</b> {plan_name}
<b>{t("renewal.renewal_cost", user_lang)}</b> ${renewal_cost:.2f}

<b>{t("renewal.your_wallet_balance", user_lang)}</b> ${float(wallet_balance):.2f}

{t("renewal.choose_payment_method", user_lang)}
"""
        
        # Create payment buttons
        keyboard = []
        
        # Wallet payment button (with balance check)
        if wallet_balance >= renewal_cost:
            keyboard.append([InlineKeyboardButton(
                f"💰 {t('renewal.pay_from_wallet', user_lang)} (${float(wallet_balance):.2f})",
                callback_data=f"renew_wallet_{subscription_id}"
            )])
        else:
            # Show insufficient funds with add funds option
            keyboard.append([InlineKeyboardButton(
                f"💰 {t('renewal.wallet_insufficient', user_lang)} (${float(wallet_balance):.2f} / ${renewal_cost:.2f})",
                callback_data=f"insufficient_funds_{subscription_id}"
            )])
        
        # Crypto payment button
        keyboard.append([InlineKeyboardButton(
            f"₿ {t('payment.hosting.crypto_button', user_lang)}",
            callback_data=f"renew_crypto_{subscription_id}"
        )])
        
        # Back button
        keyboard.append([InlineKeyboardButton(
            t("buttons.back_to_management", user_lang),
            callback_data=f"manage_hosting_{subscription_id}"
        )])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing renewal options: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        await safe_edit_message(query, f"❌ {t('errors.general', user_lang)}")

async def process_manual_renewal_wallet(query, subscription_id: str):
    """Process manual renewal payment from wallet"""
    user = query.from_user
    
    # Get user language early for translations
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        from database import (get_or_create_user, get_hosting_subscription_details,
                            get_user_wallet_balance, get_hosting_plan)
        from services.renewal_processor import HostingRenewalProcessor
        
        db_user = await get_or_create_user(telegram_id=user.id)
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription or subscription['status'] != 'suspended':
            await safe_edit_message(query, t("renewal.invalid_subscription_or_not_suspended", user_lang))
            return
        
        # Use the renewal processor to handle the payment
        processor = HostingRenewalProcessor()
        result = await processor.process_subscription_renewal(subscription)
        
        if result['status'] == 'success':
            next_billing_date = result.get('next_billing_date', 'N/A')
            message = f"""
✅ <b>{t("renewal.renewal_successful_title", user_lang)}</b>

{t("renewal.your_hosting_for", user_lang)} <code>{subscription['domain_name']}</code> {t("renewal.has_been_renewed", user_lang)}

• {t("renewal.new_expiry_date", user_lang)} {next_billing_date}
• cPanel access restored

🎉 Your hosting is now active!
"""
            await safe_edit_message(query, message, parse_mode='HTML')
        else:
            reason = result.get('reason', 'Payment failed')
            await safe_edit_message(query, f"❌ {t('renewal.renewal_error_title', user_lang)}: {reason}")
            
    except Exception as e:
        logger.error(f"Error processing manual renewal: {e}")
        await safe_edit_message(query, f"❌ {t('errors.general', user_lang)}")


async def process_manual_renewal_crypto(query, subscription_id: str):
    """Process manual renewal payment via cryptocurrency"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    # Reuse existing hosting payment flow
    await safe_edit_message(query, f"🔧 {t('renewal.crypto_coming_soon', user_lang)}")


async def handle_manual_renewal(query, subscription_id: str):
    """Handle manual renewal from /renew command with concurrency protection"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        from services.renewal_processor import HostingRenewalProcessor
        from pricing_utils import format_money
        from telegram import InlineKeyboardMarkup
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        # Get user language early for translations
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        if not subscription:
            await safe_edit_message(query, f"❌ {t('hosting.not_found_or_denied', user_lang)}")
            return
        
        # Check subscription is renewable
        status = subscription.get('status')
        if status not in ('active', 'pending_renewal', 'grace_period'):
            status_display = t(f"common_labels.{status.lower()}", user_lang) if status and status.lower() in ["active", "suspended", "pending", "expired", "failed"] else t("common_labels.unknown", user_lang)
            await safe_edit_message(query, t("renewal.cannot_be_renewed", user_lang, status=status_display))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.unknown", user_lang)
        
        # Concurrency Protection:
        # - Client-side: Buttons removed to prevent accidental double-click
        # - Database: Row-level FOR UPDATE lock in _process_renewal_atomically prevents concurrent processing
        # - Idempotency: Transaction hash checked within atomic transaction prevents duplicate charges
        await safe_edit_message(
            query, 
            f"⏳ <b>{t('renewal.processing_renewal', user_lang)}</b>\n\n{t('renewal.renewing_hosting', user_lang)} <code>{domain_name}</code>\n{t('renewal.please_wait', user_lang)}",
            reply_markup=InlineKeyboardMarkup([]),  # Empty keyboard to remove buttons
            parse_mode='HTML'
        )
        
        # Use the renewal processor to handle the payment
        processor = HostingRenewalProcessor()
        result = await processor.process_subscription_renewal(subscription)
        
        # Handle all possible renewal statuses with appropriate messages
        if result['status'] == 'success':
            next_billing_date = result.get('next_billing_date')
            amount_charged = result.get('amount_charged', 0)
            new_balance = result.get('new_balance', 0)
            
            if next_billing_date is not None:
                next_billing_str = next_billing_date.strftime('%Y-%m-%d')
            else:
                next_billing_str = 'N/A'
            
            message = f"""
✅ <b>{t("renewal.renewal_successful_title", user_lang)}</b>

{t("renewal.your_hosting_for", user_lang)} <code>{domain_name}</code> {t("renewal.has_been_renewed", user_lang)}

• <b>{t("common_labels.amount", user_lang)}</b> {format_money(amount_charged)}
• <b>{t("wallet.new_balance", user_lang)}</b> {format_money(new_balance)}
• <b>{t("common_labels.next_billing", user_lang)}</b> {next_billing_str}

🎉 Your hosting subscription is active and renewed!
"""
            await safe_edit_message(query, message, parse_mode='HTML')
            
        elif result['status'] == 'payment_failed':
            current_balance = result.get('current_balance', 0)
            amount_needed = result.get('amount_needed', 0)
            shortfall = result.get('shortfall', 0)
            
            message = f"""
❌ <b>{t("renewal.renewal_failed_title", user_lang)}</b>

{t("renewal.your_hosting_for", user_lang)} <code>{domain_name}</code> {t("renewal.could_not_be_renewed", user_lang)}

• <b>{t("renewal.current_balance", user_lang)}</b> {format_money(current_balance)}
• <b>{t("common_labels.amount", user_lang)}</b> {format_money(amount_needed)}
• <b>{t("renewal.shortfall", user_lang)}</b> {format_money(shortfall)}

⚠️ {t("renewal.moved_to_grace_period", user_lang)}
{t("renewal.add_funds_via_wallet", user_lang)}
"""
            await safe_edit_message(query, message, parse_mode='HTML')
            
        elif result['status'] == 'duplicate':
            message = f"""
ℹ️ <b>{t("renewal.already_renewed_title", user_lang)}</b>

{t("renewal.already_renewed_message", user_lang)}

{t("renewal.your_hosting_for", user_lang)} <code>{domain_name}</code> {t("renewal.is_active_up_to_date", user_lang)}
"""
            await safe_edit_message(query, message, parse_mode='HTML')
            
        elif result['status'] == 'blocked':
            reason = result.get('reason', 'Financial operations blocked')
            message = f"""
🚫 <b>{t("renewal.renewal_blocked_title", user_lang)}</b>

{t("renewal.renewing_hosting", user_lang)} <code>{domain_name}</code> {t("renewal.could_not_be_processed", user_lang)}

<b>{t("renewal.reason_label", user_lang)}</b> {reason}

{t("renewal.contact_support_message", user_lang)}
"""
            await safe_edit_message(query, message, parse_mode='HTML')
            
        elif result['status'] == 'error':
            error_msg = result.get('error', result.get('reason', 'Unknown error'))
            message = f"""
❌ <b>{t("renewal.renewal_error_title", user_lang)}</b>

{t("renewal.error_occurred_renewing", user_lang)} <code>{domain_name}</code>.

<b>{t("renewal.error_label", user_lang)}</b> {error_msg}

{t("renewal.try_again_or_contact_support", user_lang)}
"""
            await safe_edit_message(query, message, parse_mode='HTML')
            
        else:
            # Catch-all for any unexpected status
            status_type = result.get('status', t('common_labels.unknown', user_lang))
            message = f"""
⚠️ <b>{t("renewal.unexpected_status_title", user_lang)}</b>

{t("renewal.completed_with_status", user_lang)} {status_type}

{t("renewal.check_status_or_contact", user_lang)}
"""
            await safe_edit_message(query, message, parse_mode='HTML')
            
    except Exception as e:
        logger.error(f"Error in handle_manual_renewal: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        await safe_edit_message(query, f"❌ <b>{t('renewal.error_processing', user_lang)}</b>\n\n{t('renewal.unexpected_error', user_lang)}", parse_mode='HTML')


async def show_insufficient_funds_message(query, subscription_id: str):
    """Show message about insufficient wallet funds with add funds option"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details, get_user_wallet_balance, get_hosting_plan
        
        db_user = await get_or_create_user(telegram_id=user.id)
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, f"❌ {t('hosting.not_found_or_denied', user_lang)}")
            return
            
        plan_id = subscription.get('plan_id')
        if not plan_id:
            await safe_edit_message(query, f"❌ {t('hosting.invalid_plan_contact_support', user_lang)}")
            return
        
        plan = await get_hosting_plan(int(plan_id))
        renewal_cost = plan['monthly_price'] if plan else 0.0
        # Get wallet balance (use telegram_id, not internal user_id)
        wallet_balance = await get_user_wallet_balance(user.id)
        shortfall = renewal_cost - float(wallet_balance)
        
        message = f"""
⚠️ <b>{t("renewal.insufficient_balance_title", user_lang)}</b>

<b>{t("renewal.current_balance", user_lang)}</b> ${float(wallet_balance):.2f}
<b>{t("renewal.renewal_cost", user_lang)}</b> ${renewal_cost:.2f}
<b>{t("renewal.shortfall", user_lang)}</b> ${shortfall:.2f}

{t("renewal.add_funds_message", user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.add_funds_to_wallet", user_lang), callback_data="add_funds")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"renew_suspended_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing insufficient funds message: {e}")
        await safe_edit_message(query, f"❌ {t('errors.general', user_lang)}")

def get_hosting_status_description(status: str, user_lang: str) -> str:
    """Get description for hosting status"""
    descriptions = {
        'active': t("hosting.status_desc_active", user_lang),
        'suspended': t("hosting.status_desc_suspended", user_lang),
        'pending': t("hosting.status_desc_pending", user_lang),
        'expired': t("hosting.status_desc_expired", user_lang),
        'cancelled': t("hosting.status_desc_cancelled", user_lang)
    }
    return descriptions.get(status, t("hosting.status_desc_unavailable", user_lang))

async def suspend_hosting_account(query, subscription_id: str):
    """Show confirmation for hosting account suspension"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user language early for translations
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.unknown", user_lang)
        plan_name = subscription.get('plan_name') or t("common_labels.unknown", user_lang)
        
        message = f"""
⚠️ <b>{t("hosting.suspend_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.plan", user_lang)}</b> {plan_name}

<b>⚠️ {t("hosting.warning_label", user_lang)}</b> {t("hosting.suspend_warning_intro", user_lang)}:
• {t("hosting.suspend_warning_1", user_lang)}
• {t("hosting.suspend_warning_2", user_lang)}
• {t("hosting.suspend_warning_3", user_lang)}
• {t("hosting.suspend_warning_4", user_lang)}

{t("hosting.suspend_preservation", user_lang)}

{t("hosting.suspend_confirmation", user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(btn_t('yes_suspend', user_lang), callback_data=f"confirm_suspend_{subscription_id}")],
            [InlineKeyboardButton(btn_t('cancel', user_lang), callback_data=f"cancel_suspend_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing suspension confirmation: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code)
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def confirm_hosting_suspension(query, subscription_id: str):
    """Execute hosting account suspension"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details, update_hosting_subscription_status
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.unknown", user_lang)
        cpanel_username = subscription.get('cpanel_username')
        
        # Show processing message
        message_text, parse_mode = t_html('hosting_management.suspending_account', user_lang, domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        
        # Attempt to suspend via cPanel API
        suspension_success = False
        if cpanel_username:
            try:
                suspension_success = await cpanel.suspend_account(cpanel_username)
            except Exception as e:
                logger.error(f"Error suspending cPanel account {cpanel_username}: {e}")
        
        # Update database status regardless of cPanel API result
        await update_hosting_subscription_status(int(subscription_id), 'suspended')
        
        # Show result message
        if suspension_success:
            message = f"""
✅ <b>{t("hosting.suspend_success_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.status", user_lang)}</b> 🔴 {t("common_labels.suspended", user_lang)}

{t("hosting.suspend_success_message", user_lang)}

{t("hosting.suspend_restore_note", user_lang)}
"""
        else:
            message = f"""
⚠️ <b>{t("hosting.suspend_marked_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.status", user_lang)}</b> 🔴 {t("common_labels.suspended", user_lang)}

{t("hosting.suspend_marked_message", user_lang)}

{t("hosting.suspend_manual_note", user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.unsuspend_account", user_lang), callback_data=f"unsuspend_hosting_{subscription_id}")],
            [InlineKeyboardButton(t("buttons.back_to_management", user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error confirming hosting suspension: {e}")
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def unsuspend_hosting_account(query, subscription_id: str):
    """Execute hosting account unsuspension"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details, update_hosting_subscription_status
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.unknown", user_lang)
        cpanel_username = subscription.get('cpanel_username')
        
        # Show processing message
        message_text, parse_mode = t_html('hosting_management.unsuspending_account', user_lang, domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        
        # Attempt to unsuspend via cPanel API
        unsuspension_success = False
        if cpanel_username:
            try:
                unsuspension_success = await cpanel.unsuspend_account(cpanel_username)
            except Exception as e:
                logger.error(f"Error unsuspending cPanel account {cpanel_username}: {e}")
        
        # Update database status regardless of cPanel API result
        await update_hosting_subscription_status(int(subscription_id), 'active')
        
        # Show result message
        if unsuspension_success:
            message = f"""
✅ <b>{t("hosting.unsuspend_success_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.status", user_lang)}</b> 🟢 {t("common_labels.active", user_lang)}

{t("hosting.unsuspend_success_message", user_lang)}

{t("hosting.unsuspend_restore_note", user_lang)}
"""
        else:
            message = f"""
⚠️ <b>{t("hosting.unsuspend_marked_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.status", user_lang)}</b> 🟢 {t("common_labels.active", user_lang)}

{t("hosting.unsuspend_marked_message", user_lang)}

{t("hosting.unsuspend_manual_note", user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.suspend_account", user_lang), callback_data=f"suspend_hosting_{subscription_id}")],
            [InlineKeyboardButton(t("buttons.back_to_management", user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error unsuspending hosting account: {e}")
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def restart_hosting_services(query, subscription_id: str):
    """Restart hosting services for an account"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.unknown", user_lang)
        cpanel_username = subscription.get('cpanel_username')
        
        # Show processing message
        message_text, parse_mode = t_html('hosting_management.restarting_services', user_lang, domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        
        # Attempt to restart services via cPanel API
        restart_success = False
        if cpanel_username:
            try:
                restart_success = await cpanel.restart_services(cpanel_username)
            except Exception as e:
                logger.error(f"Error restarting services for cPanel account {cpanel_username}: {e}")
        
        # Show result message
        if restart_success:
            message = f"""
✅ <b>{t("hosting.restart_success_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.status", user_lang)}</b> 🔄 {t("hosting.services_restarted", user_lang)}

{t("hosting.restart_services_list_intro", user_lang)}:
• {t("hosting.restart_service_web", user_lang)}
• {t("hosting.restart_service_email", user_lang)}
• {t("hosting.restart_service_database", user_lang)}
• {t("hosting.restart_service_ftp", user_lang)}

{t("hosting.restart_success_note", user_lang)}
"""
        else:
            message = f"""
⚠️ <b>{t("hosting.restart_processed_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.status", user_lang)}</b> 🔄 {t("hosting.restart_requested", user_lang)}

{t("hosting.restart_processed_message", user_lang)}

{t("hosting.restart_manual_note", user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.back_to_management", user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error restarting hosting services: {e}")
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def check_hosting_status(query, subscription_id: str):
    """Check current hosting account status"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        domain_name = subscription.get('domain_name') or t("common_labels.unknown", user_lang)
        cpanel_username = subscription.get('cpanel_username')
        current_status = subscription.get('status', 'unknown')
        
        # Show checking message
        message_text, parse_mode = t_html('hosting_management.checking_domain_status', user_lang, domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        
        # Get real-time status from cPanel API
        live_status = None
        status_details = {}
        
        if cpanel_username:
            try:
                status_result = await cpanel.check_account_status(cpanel_username)
                if status_result:
                    live_status = status_result.get('status')
                    status_details = status_result.get('details', {})
            except Exception as e:
                logger.error(f"Error checking cPanel account status {cpanel_username}: {e}")
        
        # Format status display
        if live_status == 'active':
            status_icon = "🟢"
            status_text = t("common_labels.active", user_lang)
            status_desc = t("hosting.status_check_active", user_lang)
        elif live_status == 'suspended':
            status_icon = "🔴"
            status_text = t("common_labels.suspended", user_lang)
            status_desc = t("hosting.status_check_suspended", user_lang)
        elif live_status == 'pending':
            status_icon = "🟡"
            status_text = t("common_labels.pending", user_lang)
            status_desc = t("hosting.status_check_pending", user_lang)
        else:
            status_icon = "⚪"
            status_text = t(f"common_labels.{current_status.lower()}", user_lang) if current_status and current_status.lower() in ["active", "suspended", "pending", "expired", "failed"] else t("common_labels.unknown", user_lang)
            status_desc = t("hosting.status_check_unavailable", user_lang)
        
        # Build status details
        details_text = ""
        if status_details:
            details_text = f"\n\n<b>{t('hosting.service_details_label', user_lang)}</b>\n"
            for service, status in status_details.items():
                service_icon = "🟢" if status == "running" else "🔴" if status == "stopped" else "🟡"
                # Translate service and status if available, otherwise use capitalized version
                service_label = service.replace('_', ' ').title()
                status_label = t(f"common_labels.{status.lower()}", user_lang) if status and status.lower() in ["active", "running", "stopped", "pending"] else status.title()
                details_text += f"• {service_icon} {service_label}: {status_label}\n"
        
        message = f"""
🔍 <b>{t("hosting.status_check_title", user_lang)}</b>

<b>{t("common_labels.domain", user_lang)}</b> <code>{domain_name}</code>
<b>{t("common_labels.status", user_lang)}</b> {status_icon} {status_text}

{status_desc}{details_text}

<i>{t("hosting.last_checked_label", user_lang)}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</i>
"""
        
        # Status-specific action buttons
        if live_status == 'active':
            action_buttons = [
                [InlineKeyboardButton(t("buttons.suspend_account", user_lang), callback_data=f"suspend_hosting_{subscription_id}")],
                [InlineKeyboardButton(t("buttons.restart_services", user_lang), callback_data=f"restart_hosting_{subscription_id}")]
            ]
        elif live_status == 'suspended':
            action_buttons = [
                [InlineKeyboardButton(t("buttons.unsuspend_account", user_lang), callback_data=f"unsuspend_hosting_{subscription_id}")]
            ]
        else:
            action_buttons = []
        
        action_buttons.append([InlineKeyboardButton(t("buttons.back_to_management", user_lang), callback_data=f"manage_hosting_{subscription_id}")])
        
        reply_markup = InlineKeyboardMarkup(action_buttons)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error checking hosting status: {e}")
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

async def recheck_hosting_nameservers(query, plan_id: str, domain_name: str):
    """Recheck nameserver configuration for hosting domain"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t("hosting.not_found_or_denied", user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        plan_price = plan.get('monthly_price', 0)
        
        # Show checking message
        await safe_edit_message(query, f"🔄 Re-analyzing nameserver configuration for {domain_name}...")
        
        # Re-analyze nameserver configuration
        nameserver_analysis = await analyze_domain_nameservers(domain_name)
        
        # Generate updated nameserver setup guidance
        setup_guidance = await generate_hosting_nameserver_guidance(domain_name, nameserver_analysis, plan_name)
        
        message_text = t('hosting.connect_existing_domain_message', user_lang,
                        domain=domain_name,
                        plan_name=plan_name,
                        price=plan_price,
                        setup_guidance=setup_guidance)
        
        keyboard = [
            [InlineKeyboardButton(btn_t("purchase_hosting", user_lang, price=plan_price), callback_data=f"confirm_hosting_existing_{plan_id}:{domain_name}")],
            [InlineKeyboardButton(t("buttons.check_nameservers_again", user_lang), callback_data=f"recheck_ns_{plan_id}:{domain_name}")],
            [InlineKeyboardButton(t("buttons.back_to_domain_options", user_lang), callback_data=f"collect_domain_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message_text, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error rechecking hosting nameservers: {e}")
        await safe_edit_message(query, t("errors.generic_try_again", user_lang))

def format_nameserver_display(nameservers, max_display=2):
    """Format nameservers for display in UI"""
    if not nameservers:
        return "None configured"
    
    if len(nameservers) <= max_display:
        return "\n".join([f"• <code>{ns}</code>" for ns in nameservers])
    else:
        displayed = nameservers[:max_display]
        remaining = len(nameservers) - max_display
        result = "\n".join([f"• <code>{ns}</code>" for ns in displayed])
        result += f"\n• ... and {remaining} more"
        return result

class WizardQueryAdapter:
    """Adapter for DNS wizard to interface with safe_edit_message"""
    def __init__(self, bot, chat_id, message_id, user_id):
        self.bot = bot
        self.chat_id = chat_id
        self.message_id = message_id
        self.user_id = user_id
        
        # Create from_user object
        class User:
            def __init__(self, user_id):
                self.id = user_id
        
        self.from_user = User(user_id)
        
        # Create message object
        class Message:
            def __init__(self, chat_id, message_id):
                self.chat = type('Chat', (), {'id': chat_id})()
                self.message_id = message_id
        
        self.message = Message(chat_id, message_id)
        self.inline_message_id = None
    
    async def edit_message_text(self, text, reply_markup=None, parse_mode=None):
        """Edit message text through bot"""
        return await self.bot.edit_message_text(
            chat_id=self.chat_id,
            message_id=self.message_id,
            text=text,
            reply_markup=reply_markup,
            parse_mode=parse_mode
        )

def escape_content_for_display(content: str, mode: str = "full") -> Tuple[str, Literal["HTML", "Markdown"]]:
    """Safely escape content for display in messages
    
    Args:
        content: The content to escape
        mode: "full" for confirmation/edit screens (preserves exact content, returns HTML)
              "summary" for lists/previews (safe truncation for Markdown)
    """
    if not content:
        return "(empty)", "Markdown"
    
    if mode == "full":
        # For confirmations - HTML mode with exact content preservation
        escaped_content = html.escape(content)
        return f"<pre><code>{escaped_content}</code></pre>", "HTML"
    else:
        # For summaries - safe truncation preserving critical DNS characters
        # Keep underscores and brackets but escape problematic Markdown chars
        safe_content = content.replace('`', "'").replace('*', '∗').replace('[', '(').replace(']', ')')
        if len(safe_content) > 80:
            return f"{safe_content[:80]}...(truncated)", "Markdown"
        return safe_content, "Markdown"

async def store_callback_token(user_id: int, callback_data: str) -> str:
    """Store callback data in database and return secure token"""
    from datetime import timezone
    
    # Generate cryptographically secure random token
    token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    
    # Set expiration time (1 hour from now) - use UTC to match retrieval
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    
    # Store in database
    await execute_update(
        "INSERT INTO callback_tokens (token, user_id, callback_data, expires_at) VALUES (%s, %s, %s, %s)",
        (token, user_id, callback_data, expires_at)
    )
    
    logger.info(f"Stored callback token: {len(callback_data)} chars -> c:{token}")
    return f"c:{token}"

async def compress_callback(callback_data: str, context) -> str:
    """Compress long callback data to stay under Telegram's 64-byte limit using database storage"""
    if len(callback_data) <= 60:  # Safe margin
        return callback_data
    
    # Get user_id from context
    user_id = context._user_id if hasattr(context, '_user_id') else None
    if not user_id and hasattr(context, 'user_data') and 'user_id' in context.user_data:
        user_id = context.user_data['user_id']
    
    if not user_id:
        logger.warning("No user_id available for callback compression, using fallback")
        return callback_data[:60]  # Truncate as fallback
    
    # Always use database storage for reliability
    try:
        token = await store_callback_token(user_id, callback_data)
        logger.info(f"Compressed callback: {len(callback_data)} chars -> {token}")
        return token
    except Exception as e:
        logger.error(f"Error storing callback token: {e}")
        # Fallback to truncation
        return callback_data[:60]

async def cleanup_expired_tokens():
    """Clean up expired callback tokens from database"""
    try:
        # Use UTC time to avoid timezone issues
        from datetime import datetime, timezone
        current_time = datetime.now(timezone.utc)
        
        result = await execute_update(
            "DELETE FROM callback_tokens WHERE expires_at < %s",
            (current_time,)
        )
        if result > 0:
            logger.info(f"Cleaned up {result} expired callback tokens")
    except Exception as e:
        logger.error(f"Error cleaning up expired tokens: {e}")

async def retrieve_callback_token(user_id: int, token: str) -> Optional[str]:
    """Retrieve callback data from database by token"""
    from datetime import datetime, timezone
    current_time = datetime.now(timezone.utc)
    
    result = await execute_query(
        "SELECT callback_data FROM callback_tokens WHERE token = %s AND user_id = %s AND expires_at > %s",
        (token, user_id, current_time)
    )
    
    if result:
        # Clean up expired tokens while we're here
        await execute_update(
            "DELETE FROM callback_tokens WHERE expires_at < %s",
            (current_time,)
        )
        return result[0]['callback_data']
    else:
        logger.error(f"Callback token not found or expired: {token}")
        return None

async def decompress_callback(callback_data: Optional[str], context) -> str:
    """Decompress callback data from token with database-first approach"""
    if not callback_data or not callback_data.startswith("c:"):
        return callback_data or "error:no_callback_data"
    
    token = callback_data[2:]  # Remove "c:" prefix
    
    # Get user_id from context
    user_id = context._user_id if hasattr(context, '_user_id') else None
    if not user_id and hasattr(context, 'user_data') and 'user_id' in context.user_data:
        user_id = context.user_data['user_id']
    
    # Try database first (primary storage)
    if user_id:
        try:
            result = await retrieve_callback_token(user_id, token)
            if result:
                logger.info(f"Decompressed callback from database: {callback_data} -> {len(result)} chars")
                return result
        except Exception as e:
            logger.error(f"Error retrieving callback from database: {e}")
    
    # Fallback to context storage (for backward compatibility)
    callback_states = context.user_data.get('callback_states', {})
    
    if token in callback_states:
        stored = callback_states[token]
        if isinstance(stored, dict):
            # Check expiration
            if stored.get('expires', 0) > time.time():
                original = stored['data']
                logger.info(f"Decompressed callback from context: {callback_data} -> {len(original)} chars")
                return original
            else:
                # Remove expired token
                del callback_states[token]
        else:
            # Old format
            original = stored
            logger.info(f"Decompressed callback (legacy): {callback_data} -> {len(original)} chars")
            return original
    
    # Final fallback
    logger.error(f"Callback token not found: {callback_data}")
    return "error:token_not_found"

# Global dictionary to store content hashes per message
_message_content_hashes = {}

async def safe_edit_message(query, message, reply_markup=None, parse_mode='HTML'):
    """Centralized safe message editing with deduplication"""
    try:
        # Enhanced logging for debugging - handle both regular and inline messages
        user = query.from_user
        if query.message:
            message_key = f"{query.message.chat.id}_{query.message.message_id}"
        else:
            message_key = query.inline_message_id or "unknown_inline"
        logger.info(f"Attempting message edit for user {user.id if user else 'unknown'}, message {message_key}")
        
        # Create content hash to check for duplicates
        content_hash = hashlib.md5(f"{message}_{reply_markup}".encode()).hexdigest()
        
        # Use message ID as key for storing last content hash
        last_hash = _message_content_hashes.get(message_key)
        
        if last_hash == content_hash:
            logger.info(f"Prevented duplicate message edit for message {message_key}")
            return True
        
        # Attempt the edit with timeout protection to prevent event loop issues
        logger.info(f"Executing message edit for user {user.id if user else 'unknown'}")
        await asyncio.wait_for(
            query.edit_message_text(message, reply_markup=reply_markup, parse_mode=parse_mode),
            timeout=15.0  # 15 second timeout to prevent event loop hanging
        )
        
        # Store the content hash to prevent future duplicates
        _message_content_hashes[message_key] = content_hash
        logger.info(f"Message edit successful for user {user.id if user else 'unknown'}")
        
        # Clean up old hashes to prevent memory leak (keep only last 1000 entries)
        if len(_message_content_hashes) > 1000:
            # Remove oldest entries
            keys_to_remove = list(_message_content_hashes.keys())[:-500]
            for key in keys_to_remove:
                del _message_content_hashes[key]
        
        return True
        
    except Exception as e:
        user = query.from_user
        if query.message:
            message_key = f"{query.message.chat.id}_{query.message.message_id}"
        else:
            message_key = query.inline_message_id or "unknown_inline"
        error_msg = str(e)
        if "Message is not modified" in error_msg or "exactly the same" in error_msg:
            logger.info(f"Message content identical for user {user.id if user else 'unknown'}, message {message_key}")
            return True
        else:
            logger.warning(f"Message edit failed for user {user.id if user else 'unknown'}: {e}")
            
            # Don't try fallback for "Message can't be edited" errors - these are expected
            # when the message is too old or already deleted
            if "can't be edited" in error_msg.lower():
                logger.info(f"Message edit not possible for user {user.id if user else 'unknown'} (message too old or deleted)")
                return False
            
            # Re-raise the original error for other cases
            raise e

# ====================================================================
# AUTHENTICATION SYSTEM
# ====================================================================

async def require_user_onboarding(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """
    Check if user has completed onboarding (terms acceptance).
    Returns True if user is authenticated, False if they need to complete /start.
    """
    user = update.effective_user
    effective_message = update.effective_message
    
    if not user or not effective_message:
        logger.error("Missing user or message in authentication check")
        return False
    
    try:
        # Get user data from database
        user_data = await get_or_create_user_with_status(
            telegram_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        # Check if user has accepted terms
        if not user_data['terms_accepted_bool']:
            # User hasn't completed onboarding - direct them to /start
            user_lang = await resolve_user_language(user.id, user.language_code)
            
            onboarding_message = t('auth.onboarding_required', user_lang)
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.start_onboarding", user_lang), url=f"https://t.me/{context.bot.username}?start=onboard")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await effective_message.reply_text(
                onboarding_message,
                reply_markup=reply_markup,
                parse_mode=ParseMode.HTML
            )
            
            logger.warning(f"🚫 SECURITY: User {user.id} (@{user.username or 'no_username'}) attempted to access command without completing onboarding")
            return False
        
        # User is authenticated
        return True
        
    except Exception as e:
        logger.error(f"Error in authentication check for user {user.id}: {e}")
        
        # Get user_lang for error message
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Fallback error message
        await effective_message.reply_text(
            t('auth.error', user_lang),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t("buttons.start_bot", user_lang), url=f"https://t.me/{context.bot.username}?start=auth")
            ]])
        )
        return False

# Initialize services
cloudflare = CloudflareService()
openprovider = OpenProviderService()
cpanel = CPanelService()

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command with terms acceptance check and routing"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in start command")
        return
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and not is_admin_user(user.id):
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
        await message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
        logger.info(f"🔧 MAINTENANCE: Blocked /start command from non-admin user {user.id}")
        return
    
    try:
        # Clear admin states when user starts fresh
        from admin_handlers import clear_admin_states
        clear_admin_states(context)
        
        # Clear all DNS wizard state to ensure fresh start
        clear_all_dns_wizard_state(context)
        
        # USER INTERACTION LOG: Enhanced logging for anomaly detection
        logger.info(f"🚀 USER_ACTIVITY: /start command from user {user.id} (@{user.username or 'no_username'}) '{user.first_name or 'Unknown'}'")
        
        # PERFORMANCE OPTIMIZATION: Single query for all user data
        user_data = await get_or_create_user_with_status(
            telegram_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        # LANGUAGE SELECTION LOGIC: Show to users who haven't manually selected language
        from database import execute_query
        
        # Check if user has manually selected a language
        lang_result = await execute_query(
            "SELECT preferred_language, language_selected_manually FROM users WHERE telegram_id = %s",
            (user.id,)
        )
        
        if lang_result:
            stored_language = lang_result[0]['preferred_language']
            manually_selected = lang_result[0]['language_selected_manually']
            # Normalize empty string to None
            if stored_language == '':
                stored_language = None
        else:
            stored_language = None
            manually_selected = False
        
        # CRITICAL FIX: Only show language selection for truly new users or users who haven't accepted terms
        # Existing users who already accepted terms should not be forced through language selection
        terms_accepted = user_data['terms_accepted_bool']
        
        # Show language selection if:
        # 1. User is newly created AND hasn't accepted terms yet (true new users)
        # 2. User hasn't accepted terms yet AND has no language preference (incomplete onboarding)
        should_show_language_selection = (
            not terms_accepted and (
                stored_language is None or  # Never selected language
                user_data.get('created_recently', False) or  # Newly created user
                not manually_selected  # Never manually selected (for users in onboarding)
            )
        )
        
        if should_show_language_selection:
            logger.info(f"🌍 User {user.id} needs language selection (stored: {stored_language}, manually_selected: {manually_selected}, new: {user_data.get('created_recently', False)})")
            language_selected = await show_language_selection(update, context)
            if language_selected:
                return  # Wait for user to select language
            else:
                # Robust fallback to English if language selection fails
                logger.warning(f"Language selection failed for user {user.id}, using English fallback")
                await set_user_language_preference(user.id, 'en', manually_selected=False)
        elif terms_accepted and stored_language is None:
            # EXISTING USER FIX: Auto-assign language for existing users who accepted terms before language selection was implemented
            from localization import detect_user_language
            auto_language = detect_user_language(user.language_code)
            await set_user_language_preference(user.id, auto_language, manually_selected=False)
            logger.info(f"🔄 Auto-assigned language '{auto_language}' to existing user {user.id} who already accepted terms")
        
        # Get current language preference after potential selection
        current_lang = await get_user_language_preference(user.id)
        
        terms_accepted = user_data['terms_accepted_bool']
        logger.info(f"🔍 TERMS CHECK: User {user.id} ({user.username}) terms_accepted = {terms_accepted}")
        
        if terms_accepted:
            # User has already accepted terms, show dashboard directly
            await show_dashboard(update, context, user_data)
            logger.info(f"✅ DASHBOARD: User {user.id} started bot - showing dashboard (terms already accepted)")
        else:
            # User has not accepted terms, show terms acceptance screen
            await show_terms_acceptance(update, context)
            logger.info(f"📋 TERMS: User {user.id} started bot - showing terms acceptance")
            
    except Exception as e:
        logger.error(f"Error in start command: {e}")
        
        # Get user_lang for error fallback
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Fallback to original welcome message on error
        welcome_message = get_welcome_message()
        keyboard = [
            [InlineKeyboardButton(t("buttons.search", user_lang), callback_data="search_domains"), InlineKeyboardButton(t("buttons.domains", user_lang), callback_data="my_domains")],
            [InlineKeyboardButton(t("buttons.wallet", user_lang), callback_data="wallet_main"), InlineKeyboardButton(t("buttons.hosting", user_lang), callback_data="hosting_main")],
            [InlineKeyboardButton(t("buttons.link_domain", user_lang), callback_data="domain_linking_intro"), InlineKeyboardButton(t("buttons.profile", user_lang), callback_data="profile_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        try:
            await message.reply_text(welcome_message, reply_markup=reply_markup)
        except Exception as fallback_error:
            logger.error(f"Error in start command fallback: {fallback_error}")

async def show_terms_acceptance(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """OPTIMIZED: Show terms and conditions acceptance screen (text only)"""
    import time
    start_time = time.perf_counter()
    
    user = update.effective_user
    
    if not user:
        logger.error("Missing user in show_terms_acceptance")
        return
    
    # Get user language with caching optimization
    user_lang = await resolve_user_language(user.id, user.language_code)
    platform_name = get_platform_name()
    
    # Translated terms message with proper placeholder substitution
    terms_title = t_fmt('terms.title', user_lang, platform_name=platform_name)
    terms_content = t_fmt('terms.content', user_lang)
    terms_message = terms_title + "\n\n" + terms_content

    keyboard = [
        [InlineKeyboardButton(btn_t('accept', user_lang), callback_data="terms:accept"),
         InlineKeyboardButton(btn_t('view_full', user_lang), callback_data="terms:view")],
        [InlineKeyboardButton(btn_t('decline', user_lang), callback_data="terms:decline")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Get chat_id once for all attempts
    chat_id = update.effective_chat.id if update.effective_chat else user.id
    
    try:
        await context.bot.send_message(
            chat_id=chat_id,
            text=terms_message,
            reply_markup=reply_markup
        )
        elapsed = (time.perf_counter() - start_time) * 1000
        logger.info(f"⚡ TERMS SENT: User {user.id} in {elapsed:.1f}ms")
        
    except Exception as e:
        logger.error(f"Error sending terms message: {e}")
        # Final fallback with no formatting
        try:
            terms_title = t_fmt('terms.title', user_lang, platform_name=platform_name)
            terms_content = t_fmt('terms.content', user_lang)
            plain_message = terms_title + "\n\n" + terms_content
            
            await context.bot.send_message(
                chat_id=chat_id,
                text=plain_message,
                reply_markup=reply_markup
            )
        except Exception as fallback_error:
            logger.error(f"Error in terms fallback: {fallback_error}")

async def handle_terms_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle terms acceptance/decline callbacks"""
    query = update.callback_query
    user = update.effective_user
    
    if not query or not user:
        logger.error("Missing query or user in handle_terms_callback")
        return
    
    try:
        await query.answer()
        
        if query.data == "terms:accept":
            # Check if user has already accepted terms to prevent duplicate processing
            already_accepted = await has_user_accepted_terms(user.id)
            
            if already_accepted:
                # Duplicate callback - user already accepted terms, just show dashboard
                logger.info(f"User {user.id} - duplicate terms:accept callback ignored (already accepted)")
                await show_dashboard(update, context)
                return
            
            # Accept terms and create/update user
            db_user = await get_or_create_user(
                telegram_id=user.id,
                username=user.username,
                first_name=user.first_name,
                last_name=user.last_name
            )
            
            # Mark terms as accepted
            success = await accept_user_terms(user.id)
            
            if success:
                # Show success message and go to dashboard
                user_lang = await resolve_user_language(user.id, user.language_code)
                success_message = t_fmt('terms.accepted', user_lang)
                
                try:
                    await query.edit_message_text(
                        text=success_message
                    )
                except Exception as edit_error:
                    logger.warning(f"Could not edit message, sending new one: {edit_error}")
                    # Fallback to sending new message if edit fails
                    await context.bot.send_message(
                        chat_id=user.id,
                        text=success_message
                    )
                
                # Wait a moment then show dashboard
                await asyncio.sleep(1.5)
                await show_dashboard(update, context)
                
                logger.info(f"User {user.id} accepted terms successfully")
            else:
                try:
                    await query.edit_message_text(
                        text=t('errors.terms_acceptance_failed', 'en')
                    )
                except Exception as edit_error:
                    logger.warning(f"Could not edit message, sending new one: {edit_error}")
                    # Fallback to sending new message if edit fails
                    await context.bot.send_message(
                        chat_id=user.id,
                        text=t('errors.terms_acceptance_failed', 'en')
                    )
                
        elif query.data == "terms:decline":
            decline_message = f"""❌ Terms Declined

You need to accept our terms to use {get_platform_name()}.

You can restart anytime with /start to accept terms."""
            
            try:
                await query.edit_message_text(
                    text=decline_message
                )
            except Exception as edit_error:
                logger.warning(f"Could not edit message, sending new one: {edit_error}")
                # Fallback to sending new message if edit fails
                await context.bot.send_message(
                    chat_id=user.id,
                    text=decline_message
                )
            
        elif query.data == "terms:view":
            # Show full terms using localization system with proper placeholder substitution
            user_lang = await resolve_user_language(user.id, user.language_code)
            terms_title = t_fmt('terms.title', user_lang)
            terms_content = t_fmt('terms.content', user_lang)
            full_terms = f"{terms_title}\n\n{terms_content}"
            
            keyboard = [
                [InlineKeyboardButton(btn_t('accept', user_lang), callback_data="terms:accept")],
                [InlineKeyboardButton(btn_t('decline', user_lang), callback_data="terms:decline")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            try:
                await query.edit_message_text(
                    text=full_terms,
                    reply_markup=reply_markup
                )
            except Exception as edit_error:
                logger.warning(f"Could not edit message, sending new one: {edit_error}")
                # Fallback to sending new message if edit fails
                await context.bot.send_message(
                    chat_id=user.id,
                    text=full_terms,
                    reply_markup=reply_markup
                )
            
    except Exception as e:
        logger.error(f"Error in handle_terms_callback: {e}")

async def show_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE, user_data: Optional[Dict] = None):
    """Show main dashboard with wallet balance and menu options - Production-ready with event loop protection"""
    user = update.effective_user
    query = update.callback_query
    
    if not user:
        logger.error("Missing user in show_dashboard")
        return
    
    # PRODUCTION FIX: Add timeout and async protection for event loop stability
    async def _safe_dashboard_operation():
        # PERFORMANCE OPTIMIZATION: Parallel database queries to reduce timeout risk
        if user_data is None:
            # OPTIMIZED: Run all database queries in parallel instead of sequentially
            try:
                # Define all queries to run in parallel
                async def get_user_data():
                    return await get_or_create_user(
                        telegram_id=user.id,
                        username=user.username,
                        first_name=user.first_name,
                        last_name=user.last_name
                    )
                
                async def get_wallet():
                    return await get_user_wallet_balance(user.id)
                
                async def get_min_hosting():
                    result = await execute_query(
                        "SELECT MIN(monthly_price) as min_price FROM hosting_plans WHERE is_active = true"
                    )
                    return int(result[0]['min_price']) if result and result[0]['min_price'] else 40
                
                async def get_min_rdp():
                    result = await execute_query(
                        "SELECT MIN(our_monthly_price) as min_price FROM rdp_plans WHERE is_active = true"
                    )
                    return int(result[0]['min_price']) if result and result[0]['min_price'] else 60
                
                # Execute all queries in parallel with overall timeout
                results = await asyncio.wait_for(
                    asyncio.gather(
                        get_user_data(),
                        get_wallet(),
                        get_min_hosting(),
                        get_min_rdp(),
                        return_exceptions=True
                    ),
                    timeout=20.0  # PRODUCTION FIX: Allow time for Neon cold start (15s connect + 5s query)
                )
                
                # Extract results with fallbacks for any individual failures
                db_user = results[0] if not isinstance(results[0], Exception) else {'id': user.id}
                wallet_balance = results[1] if not isinstance(results[1], Exception) else 0.0
                min_hosting_price = results[2] if not isinstance(results[2], Exception) else 40
                min_rdp_price = results[3] if not isinstance(results[3], Exception) else 60
                
                # Log any individual query failures
                for i, (name, result) in enumerate([
                    ('user_data', results[0]), ('wallet', results[1]),
                    ('hosting_price', results[2]), ('rdp_price', results[3])
                ]):
                    if isinstance(result, Exception):
                        logger.warning(f"Dashboard query {name} failed for user {user.id}: {result}")
                
            except asyncio.TimeoutError:
                logger.warning(f"Dashboard parallel queries timeout for user {user.id}, using fallbacks")
                db_user = {'id': user.id}
                wallet_balance = 0.0
                min_hosting_price = 40
                min_rdp_price = 60
            except Exception as db_error:
                logger.warning(f"Dashboard database error for user {user.id}: {db_error}, using fallbacks")
                db_user = {'id': user.id}
                wallet_balance = 0.0
                min_hosting_price = 40
                min_rdp_price = 60
        else:
            # Use provided user_data (from optimized query) + fetch prices in parallel
            db_user = user_data
            wallet_balance = user_data['wallet_balance']
            
            # Still need to fetch min prices in parallel
            min_hosting_price = 40
            min_rdp_price = 60
            try:
                price_results = await asyncio.wait_for(
                    asyncio.gather(
                        execute_query("SELECT MIN(monthly_price) as min_price FROM hosting_plans WHERE is_active = true"),
                        execute_query("SELECT MIN(our_monthly_price) as min_price FROM rdp_plans WHERE is_active = true"),
                        return_exceptions=True
                    ),
                    timeout=5.0
                )
                # Extract hosting price safely
                if len(price_results) > 0 and not isinstance(price_results[0], BaseException):
                    hosting_rows = price_results[0]
                    if hosting_rows and len(hosting_rows) > 0 and hosting_rows[0].get('min_price'):
                        min_hosting_price = int(hosting_rows[0]['min_price'])
                
                # Extract RDP price safely
                if len(price_results) > 1 and not isinstance(price_results[1], BaseException):
                    rdp_rows = price_results[1]
                    if rdp_rows and len(rdp_rows) > 0 and rdp_rows[0].get('min_price'):
                        min_rdp_price = int(rdp_rows[0]['min_price'])
            except:
                pass
        
        balance_display = format_money(Decimal(str(wallet_balance)))
        platform_name = get_platform_name()
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Check if user is admin using unified admin check
        is_admin = is_admin_user(user.id)
        
        # Create dashboard message with translations
        dashboard_message = t_fmt('dashboard.title', user_lang) + "\n\n"
        # Use t_html for safe user name display
        welcome_text, _ = t_html('dashboard.welcome_back', user_lang, name=user.first_name or 'User')
        dashboard_message += welcome_text + "\n\n"
        dashboard_message += t('dashboard.balance', user_lang, balance=balance_display) + "\n\n"
        dashboard_message += t('dashboard.what_to_do', user_lang)
        
        keyboard = [
            [InlineKeyboardButton(btn_t('search_domains', user_lang), callback_data="search_domains")],
            [InlineKeyboardButton(btn_t('my_domains', user_lang), callback_data="my_domains")],
            [InlineKeyboardButton(btn_t('wallet', user_lang), callback_data="wallet_main"), InlineKeyboardButton(btn_t('hosting_from_price', user_lang, price=str(min_hosting_price)), callback_data="unified_hosting_plans")],
            [InlineKeyboardButton(btn_t('rdp_from_price', user_lang, price=str(min_rdp_price)), callback_data="rdp_purchase_start")],
            [InlineKeyboardButton(btn_t('api_management', user_lang), callback_data="api_management_main")],
            [InlineKeyboardButton(btn_t('become_reseller', user_lang), callback_data="reseller_program")],
            [InlineKeyboardButton(btn_t('profile', user_lang), callback_data="profile_main"), InlineKeyboardButton(btn_t('change_language', user_lang), callback_data="language_selection_from_profile")],
            [InlineKeyboardButton(btn_t('contact_support', user_lang), callback_data="contact_support")]
        ]
        
        # Add admin commands for admin users
        if is_admin:
            dashboard_message += "\n\n" + t('admin.admin_panel', user_lang)
            keyboard.append([InlineKeyboardButton(btn_t('broadcast_message', user_lang), callback_data="admin_broadcast")])
            keyboard.append([InlineKeyboardButton(btn_t('credit_user_wallet', user_lang), callback_data="admin_credit_wallet")])
            keyboard.append([InlineKeyboardButton(btn_t('openprovider_accounts', user_lang), callback_data="admin_openprovider_accounts")])
            keyboard.append([InlineKeyboardButton("🔄 DNS Sync", callback_data="admin_dns_sync")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # PRODUCTION FIX: Send or edit message with timeout and retry protection
        if query:
            try:
                await asyncio.wait_for(
                    safe_edit_message(query, dashboard_message, reply_markup),
                    timeout=15.0  # 15 second timeout for Telegram operations
                )
            except asyncio.TimeoutError:
                logger.warning(f"Telegram edit timeout for user {user.id}, trying fallback")
                # Fallback to sending new message if edit times out
                await asyncio.wait_for(
                    context.bot.send_message(
                        chat_id=user.id,
                        text=dashboard_message,
                        reply_markup=reply_markup
                    ),
                    timeout=15.0
                )
        else:
            # Direct message with timeout protection
            if update.message:
                await asyncio.wait_for(
                    update.message.reply_text(
                        text=dashboard_message,
                        reply_markup=reply_markup
                    ),
                    timeout=15.0
                )
            else:
                await asyncio.wait_for(
                    context.bot.send_message(
                        chat_id=user.id,
                        text=dashboard_message,
                        reply_markup=reply_markup
                    ),
                    timeout=15.0
                )
        
        logger.info(f"Dashboard shown to user {user.id} with balance {balance_display}")
    
    try:
        # PRODUCTION FIX: Run the entire operation with overall timeout protection
        await asyncio.wait_for(_safe_dashboard_operation(), timeout=30.0)
        
    except asyncio.TimeoutError:
        logger.error(f"⚠️ PRODUCTION: Dashboard operation timed out for user {user.id} - using emergency fallback")
        # Emergency fallback for total timeout
        await _emergency_dashboard_fallback(update, context, user)
        
    except Exception as e:
        logger.error(f"⚠️ PRODUCTION: Dashboard error for user {user.id}: {e} - using emergency fallback")
        # Emergency fallback for any other error
        await _emergency_dashboard_fallback(update, context, user)

async def _emergency_dashboard_fallback(update: Update, context: ContextTypes.DEFAULT_TYPE, user):
    """Emergency fallback dashboard when main dashboard fails - Production resilience
    
    CRITICAL: This fallback must be 100% database-free to work even when DB is hanging
    """
    user_lang = 'en'
    try:
        lang_code = getattr(user, 'language_code', None) or 'en'
        user_lang = lang_code[:2].lower() if lang_code else 'en'
        if user_lang not in ['en', 'es', 'fr']:
            user_lang = 'en'
    except:
        user_lang = 'en'
    
    emergency_messages = {
        'en': "Welcome to HostBay! What would you like to do?",
        'es': "Bienvenido a HostBay! Que te gustaria hacer?",
        'fr': "Bienvenue chez HostBay! Que souhaitez-vous faire?"
    }
    emergency_buttons = {
        'en': ["Search Domains", "My Domains", "Wallet", "Hosting"],
        'es': ["Buscar Dominios", "Mis Dominios", "Cartera", "Hosting"],
        'fr': ["Rechercher", "Mes Domaines", "Portefeuille", "Hebergement"]
    }
    
    error_message = emergency_messages.get(user_lang, emergency_messages['en'])
    btn_labels = emergency_buttons.get(user_lang, emergency_buttons['en'])
    
    keyboard = [
        [InlineKeyboardButton(btn_labels[0], callback_data="search_domains"), 
         InlineKeyboardButton(btn_labels[1], callback_data="my_domains")],
        [InlineKeyboardButton(btn_labels[2], callback_data="wallet_main"), 
         InlineKeyboardButton(btn_labels[3], callback_data="hosting_main")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        query = update.callback_query
        if query:
            try:
                await asyncio.wait_for(
                    safe_edit_message(query, error_message, reply_markup),
                    timeout=10.0
                )
            except:
                await asyncio.wait_for(
                    context.bot.send_message(
                        chat_id=user.id,
                        text=error_message,
                        reply_markup=reply_markup
                    ),
                    timeout=10.0
                )
        else:
            await asyncio.wait_for(
                context.bot.send_message(
                    chat_id=user.id,
                    text=error_message,
                    reply_markup=reply_markup
                ),
                timeout=10.0
            )
        
        logger.info(f"✅ PRODUCTION: Emergency dashboard fallback successful for user {user.id}")
        
    except Exception as fallback_error:
        logger.error(f"❌ CRITICAL: Emergency dashboard fallback failed for user {user.id}: {fallback_error}")
        try:
            await asyncio.wait_for(
                context.bot.send_message(
                    chat_id=user.id,
                    text="Welcome to HostBay! Please try again in a moment."
                ),
                timeout=5.0
            )
        except Exception as final_error:
            logger.error(f"❌ CRITICAL: Final emergency message failed for user {user.id}: {final_error}")

async def domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /domain command - show user's domains"""
    user = update.effective_user
    
    if not user:
        logger.error("Missing user in domain command")
        return
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and not is_admin_user(user.id):
        effective_message = update.effective_message
        if effective_message:
            user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
            maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
            await effective_message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
            logger.info(f"🔧 MAINTENANCE: Blocked /domain command from non-admin user {user.id}")
        return
    
    # Check if user has completed onboarding
    if not await require_user_onboarding(update, context):
        return
    
    # USER INTERACTION LOG: Enhanced logging for anomaly detection
    logger.info(f"🌐 USER_ACTIVITY: /domain command from user {user.id} (@{user.username or 'no_username'}) '{user.first_name or 'Unknown'}')")
    
    try:
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get user's domains
        domains = await get_user_domains(db_user['id'])
        
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        if not domains:
            message = f"{t('dashboard.domains_list_title', user_lang)}\n\n{t('dashboard.no_domains_message', user_lang)}"
            keyboard = [
                [InlineKeyboardButton(t("buttons.search_domains", user_lang), callback_data="search_domains")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
            ]
        else:
            message = f"{t('dashboard.domains_list_title', user_lang)}\n\n{t('dashboard.domain_count', user_lang, count=len(domains))}\n\n"
            keyboard = []
            
            for domain in domains:
                domain_name = domain['domain_name']
                status = domain.get('status', 'unknown')
                emoji = "✅" if status == 'active' else "⏳"
                status_text = t(f'common_labels.{status}', user_lang) if status else status.title()
                message += f"{emoji} {domain_name} ({status_text})\n"
                keyboard.append([InlineKeyboardButton(f"🌐 {domain_name}", callback_data=f"dns_{domain_name}")])
            
            keyboard.extend([
                [InlineKeyboardButton(btn_t("register_new_domain", user_lang), callback_data="search_domains")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        effective_message = update.effective_message
        if effective_message:
            await effective_message.reply_text(message, reply_markup=reply_markup, parse_mode=ParseMode.HTML)
        
    except Exception as e:
        logger.error(f"Error in domain command: {e}")
        effective_message = update.effective_message
        if effective_message:
            user_lang = await resolve_user_language(user.id, user.language_code)
            await effective_message.reply_text(t('errors.general', user_lang))

async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dns command"""
    effective_message = update.effective_message
    if not effective_message:
        logger.error("Missing message in dns command")
        return
    
    user = update.effective_user
    if not user:
        logger.error("Missing user in dns_command")
        return
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and not is_admin_user(user.id):
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
        await effective_message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
        logger.info(f"🔧 MAINTENANCE: Blocked /dns command from non-admin user {user.id}")
        return
    
    # Check if user has completed onboarding
    if not await require_user_onboarding(update, context):
        return
    
    user_lang = await resolve_user_language(user.id, user.language_code)
        
    message_text = get_dns_management_intro()
    keyboard = [
        [InlineKeyboardButton(btn_t('my_domains', user_lang), callback_data="my_domains")],
        [InlineKeyboardButton(btn_t('back', user_lang), callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await effective_message.reply_text(message_text, reply_markup=reply_markup)

async def wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /wallet command"""
    user = update.effective_user
    if user:
        # USER INTERACTION LOG: Enhanced logging for anomaly detection  
        logger.info(f"💰 USER_ACTIVITY: /wallet command from user {user.id} (@{user.username or 'no_username'}) '{user.first_name or 'Unknown'}'")
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and user and not is_admin_user(user.id):
        effective_message = update.effective_message
        if effective_message:
            user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
            maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
            await effective_message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
            logger.info(f"🔧 MAINTENANCE: Blocked /wallet command from non-admin user {user.id}")
        return
    
    # Check if user has completed onboarding
    if not await require_user_onboarding(update, context):
        return
    
    # Clear admin states when user navigates to wallet
    from admin_handlers import clear_admin_states
    clear_admin_states(context)
    
    await show_wallet_interface_message(update)

async def show_wallet_interface_message(update: Update):
    """Show wallet interface for direct message"""
    user = update.effective_user
    effective_message = update.effective_message
    
    if not user or not effective_message:
        logger.error("Missing user or message in wallet interface")
        return
    
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        balance = await get_user_wallet_balance(user.id)
        
        # Get recent transactions
        transactions = await get_user_wallet_transactions(user_record['id'], 5)
        
        # Format transaction history
        transaction_history = ""
        if transactions:
            for tx in transactions[:3]:  # Only show 3 recent
                amount = float(tx['amount'])
                date = tx['created_at'].strftime('%m/%d')
                emoji = "➕" if amount > 0 else "➖"
                tx_type = tx['transaction_type'] or 'transaction'
                
                # Extract simple type from verbose descriptions
                if 'domain' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.domain', user_lang)
                elif 'deposit' in tx_type.lower() or 'crypto' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.deposit', user_lang)
                elif 'credit' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.credit', user_lang)
                elif 'refund' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.refund', user_lang)
                elif 'debit' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.debit', user_lang)
                else:
                    # Fallback to generic transaction label
                    simple_type = t('wallet.transaction_type.transaction', user_lang)
                
                transaction_history += f"{emoji} {format_money(abs(Decimal(str(amount))), 'USD', include_currency=True)} - {simple_type} ({date})\n"
        else:
            transaction_history = f"\n{t('wallet.no_transactions', user_lang)}"
        
        # Get brand config for dynamic support contact
        config = BrandConfig()
        
        message = f"""
{t('wallet.title', user_lang)}

{t('wallet.balance_label', user_lang)} {format_money(balance, 'USD', include_currency=True)}
{transaction_history}

{t('wallet.help_message', user_lang, support_contact=config.support_contact)}"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.add_funds", user_lang), callback_data="wallet_deposit")],
            [InlineKeyboardButton(t("buttons.transaction_history", user_lang), callback_data="wallet_history")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await effective_message.reply_text(message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing wallet interface: {e}")
        if effective_message:
            # Get user_lang for error message
            user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
            await effective_message.reply_text(t('errors.wallet_load_failed', user_lang))

async def credit_wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to credit wallet balance with enhanced security validation"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in credit wallet command")
        return
    
    # SECURITY: Multi-layer admin validation using unified admin check
    if not is_admin_user(user.id):
        user_lang = await resolve_user_language(user.id, user.language_code)
        await message.reply_text(t('admin.access.denied', user_lang))
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to use credit_wallet command")
        return
    
    # Resolve admin user's language for all messages
    user_lang = await resolve_user_language(user.id, user.language_code)
    
    try:
        if not context.args or len(context.args) < 2:
            await message.reply_text(
                "📋 Usage: <code>/credit_wallet &lt;user_id&gt; &lt;amount&gt;</code>"
            )
            return
        
        # Enhanced input validation
        try:
            target_user_id = int(context.args[0])
            amount = float(context.args[1])
        except (ValueError, IndexError) as ve:
            await message.reply_text(
                "❌ Invalid Input\n\n"
                "User ID must be a number and amount must be a valid decimal."
            )
            logger.warning(f"🚫 ADMIN VALIDATION: Invalid input in credit_wallet by admin {user.id}: {context.args}")
            return
        
        # CRITICAL: Administrative safety bounds
        if amount <= 0:
            user_lang = await resolve_user_language(user.id, user.language_code)
            await message.reply_text(f"❌ {t('errors.general', user_lang)}\n\n{t('errors.amount_must_positive', user_lang)}")
            logger.warning(f"🚫 ADMIN VALIDATION: Non-positive amount attempted by admin {user.id}: {amount}")
            return
        
        if amount > 10000.00:  # $10,000 limit for safety
            await message.reply_text(
                "🚫 Amount Too Large\n\n"
                "Maximum credit amount is $10,000.00 per operation.\n"
                "For larger amounts, use multiple operations."
            )
            logger.error(f"🚫 ADMIN VALIDATION: Excessive amount attempted by admin {user.id}: ${amount}")
            return
        
        # Get and validate target user
        user_record = await get_or_create_user(target_user_id)
        if not user_record:
            user_lang = await resolve_user_language(user.id, user.language_code)
            await message.reply_text(f"❌ {t('errors.not_found', user_lang)}\n\n{t('errors.user_record_failed', user_lang)}")
            logger.error(f"🚫 ADMIN ERROR: Failed to get user record for {target_user_id}")
            return
        
        # Check current balance to prevent excessive accumulation
        current_balance = await get_user_wallet_balance(target_user_id)
        if current_balance + Decimal(str(amount)) > Decimal('50000.00'):  # $50,000 total balance limit
            await message.reply_text(
                f"🚫 Balance Limit Exceeded\n\n"
                f"{t('wallet.current_balance', user_lang)} {format_money(current_balance, 'USD', include_currency=True)}\n"
                f"Requested Credit: {format_money(Decimal(str(amount)), 'USD', include_currency=True)}\n"
                f"Would Result In: {format_money(current_balance + Decimal(str(amount)), 'USD', include_currency=True)}\n\n"
                f"Maximum wallet balance is $50,000.00"
            )
            logger.warning(f"🚫 ADMIN VALIDATION: Credit would exceed balance limit for user {target_user_id}: ${current_balance + Decimal(str(amount))}")
            return
        
        # Perform atomic credit operation
        await message.reply_text("💳 Processing Admin Credit...")
        
        # Use unified credit function with admin defaults
        success = await credit_user_wallet(
            user_id=user_record['id'],
            amount_usd=Decimal(str(amount)),
            provider="admin",
            txid=f"admin_{int(time.time())}_{user.id}",
            order_id=f"admin_credit_{int(time.time())}"
        )
        
        if success:
            new_balance = await get_user_wallet_balance(target_user_id)
            await message.reply_text(
                f"✅ Wallet Credited Successfully\n\n"
                f"👤 Target User ID: {target_user_id}\n"
                f"💰 Amount Credited: {format_money(Decimal(str(amount)), 'USD', include_currency=True)}\n"
                f"📊 {t('wallet.previous_balance', user_lang)} {format_money(current_balance, 'USD', include_currency=True)}\n"
                f"🔄 {t('wallet.new_balance', user_lang)} {format_money(new_balance, 'USD', include_currency=True)}\n\n"
                f"🔒 Admin: {user.id}\n"
                f"🕐 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            logger.info(f"✅ ADMIN CREDIT: ${amount:.2f} credited to user {target_user_id} by admin {user.id}. New balance: ${new_balance:.2f}")
        else:
            await message.reply_text(
                "❌ Credit Failed\n\n"
                "Could not credit wallet. Check logs for details."
            )
            logger.error(f"🚫 ADMIN ERROR: Failed to credit ${amount:.2f} to user {target_user_id} by admin {user.id}")
            
    except Exception as e:
        logger.error(f"🚫 ADMIN ERROR: Exception in credit_wallet_command by admin {user.id}: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        await message.reply_text(t('errors.system_error', user_lang))

async def send_broadcast(broadcast_message: str, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Shared broadcast helper function with batching and retry logic.
    Used by both /broadcast command and button interface.
    """
    import asyncio
    from database import get_all_user_telegram_ids
    
    user = update.effective_user
    
    # Validate message
    if len(broadcast_message.strip()) == 0:
        return {
            'success': False,
            'error': "Empty message",
            'message': "❌ Empty Message\n\nPlease provide a message to broadcast."
        }
    
    if len(broadcast_message) > 4096:  # Telegram message limit
        return {
            'success': False,
            'error': "Message too long",
            'message': "❌ Message Too Long\n\nMessage must be under 4096 characters."
        }
    
    # Get all user telegram IDs
    user_ids = await get_all_user_telegram_ids()
    
    if not user_ids:
        return {
            'success': False,
            'error': "No users found",
            'message': "⚠️ No Users Found\n\nNo users available for broadcasting."
        }
    
    total_users = len(user_ids)
    batch_size = 30
    delay_between_batches = 1  # seconds
    max_retries = 3
    
    # Determine if we should send or edit message
    if hasattr(update, 'message') and update.message:
        # From command - reply to the message
        status_msg = await update.message.reply_text(
            f"📢 Broadcasting Started\n\n"
            f"👥 Target Users: {total_users}\n"
            f"📦 Batch Size: {batch_size}\n"
            f"⏱️ Delay: {delay_between_batches}s between batches\n"
            f"🔄 Max Retries: {max_retries}\n\n"
            f"Message:\n{broadcast_message[:200]}{'...' if len(broadcast_message) > 200 else ''}"
        )
    else:
        # From button interface - send new message
        if not user:
            return {
                'success': False,
                'error': "User not found",
                'message': "❌ Error\n\nUser information not available."
            }
        
        status_msg = await context.bot.send_message(
            chat_id=user.id,
            text=f"📢 Broadcasting Started\n\n"
            f"👥 Target Users: {total_users}\n"
            f"📦 Batch Size: {batch_size}\n"
            f"⏱️ Delay: {delay_between_batches}s between batches\n"
            f"🔄 Max Retries: {max_retries}\n\n"
            f"Message:\n{broadcast_message[:200]}{'...' if len(broadcast_message) > 200 else ''}"
        )
    
    # Process in batches
    total_sent = 0
    total_failed = 0
    batch_number = 0
    
    for i in range(0, total_users, batch_size):
        batch_number += 1
        batch_users = user_ids[i:i + batch_size]
        batch_sent = 0
        batch_failed = 0
        
        logger.info(f"📢 BROADCAST: Processing batch {batch_number} with {len(batch_users)} users")
        
        # Send to each user in batch with retry logic
        for user_telegram_id in batch_users:
            retry_count = 0
            sent_successfully = False
            
            while retry_count < max_retries and not sent_successfully:
                try:
                    await context.bot.send_message(
                        chat_id=user_telegram_id,
                        text=broadcast_message
                    )
                    batch_sent += 1
                    sent_successfully = True
                    logger.debug(f"📢 BROADCAST: Message sent to user {user_telegram_id}")
                    
                except Exception as e:
                    retry_count += 1
                    logger.warning(f"📢 BROADCAST: Failed to send to user {user_telegram_id} (attempt {retry_count}/{max_retries}): {e}")
                    
                    if retry_count < max_retries:
                        await asyncio.sleep(0.1)  # Brief pause before retry
            
            if not sent_successfully:
                batch_failed += 1
                logger.error(f"📢 BROADCAST: Failed to send to user {user_telegram_id} after {max_retries} attempts")
        
        total_sent += batch_sent
        total_failed += batch_failed
        
        # Update status
        progress = f"📊 Batch {batch_number} Complete\n"
        progress += f"✅ Sent: {batch_sent}/{len(batch_users)}\n"
        progress += f"❌ Failed: {batch_failed}\n"
        progress += f"📈 Total Progress: {total_sent}/{total_users}"
        
        try:
            await status_msg.edit_text(
                f"📢 Broadcasting in Progress...\n\n"
                f"👥 Target Users: {total_users}\n"
                f"📦 Current Batch: {batch_number}\n\n"
                f"{progress}"
            )
        except Exception:
            pass  # Ignore edit failures
        
        # Delay between batches (except for last batch)
        if i + batch_size < total_users:
            logger.info(f"📢 BROADCAST: Waiting {delay_between_batches}s before next batch...")
            await asyncio.sleep(delay_between_batches)
    
    # Final status
    success_rate = (total_sent / total_users * 100) if total_users > 0 else 0
    final_message = f"🎯 Broadcast Complete!\n\n"
    final_message += f"✅ Successfully Sent: {total_sent}\n"
    final_message += f"❌ Failed: {total_failed}\n"
    final_message += f"📊 Success Rate: {success_rate:.1f}%\n"
    final_message += f"📦 Total Batches: {batch_number}\n\n"
    final_message += f"Message: {broadcast_message[:150]}{'...' if len(broadcast_message) > 150 else ''}"
    
    await status_msg.edit_text(final_message)
    
    logger.info(f"✅ BROADCAST COMPLETE: Admin {user.id if user else 'unknown'} sent message to {total_sent}/{total_users} users ({success_rate:.1f}% success)")
    
    return {
        'success': True,
        'total_sent': total_sent,
        'total_failed': total_failed,
        'success_rate': success_rate
    }

async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to broadcast message to all users with batching and retry logic"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in broadcast command")
        return
    
    # SECURITY: Multi-layer admin validation using unified admin check
    if not is_admin_user(user.id):
        user_lang = await resolve_user_language(user.id, user.language_code)
        await message.reply_text(t('admin.access.denied', user_lang))
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to use broadcast command")
        return
    
    try:
        if not context.args:
            await message.reply_text(
                "📢 Usage: /broadcast <message>"
            )
            return
        
        # Get broadcast message
        broadcast_message = ' '.join(context.args)
        
        # Use shared broadcast function
        result = await send_broadcast(broadcast_message, update, context)
        
        if not result['success']:
            await message.reply_text(result['message'])
        
    except Exception as e:
        logger.error(f"🚫 ADMIN ERROR: Exception in broadcast_command by admin {user.id}: {e}")
        await message.reply_text(
            "❌ Broadcast Failed\n\nCritical error occurred. Check logs for details."
        )

async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cancel command to exit broadcast mode"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in cancel command")
        return
    
    try:
        # Check if user is admin using unified admin check
        if not is_admin_user(user.id):
            await message.reply_text(
                "🚫 Access Denied\n\nOnly admin can use this command."
            )
            logger.warning(f"🚫 SECURITY: Non-admin user {user.id} attempted to use /cancel command")
            return
        
        # Check if awaiting broadcast
        if context.user_data and context.user_data.get('awaiting_broadcast'):
            # Clear broadcast flag
            del context.user_data['awaiting_broadcast']
            
            await message.reply_text(
                "🚫 Broadcast Cancelled\n\nBroadcast mode deactivated.\n\nYou can start a new broadcast anytime from the admin panel."
            )
            logger.info(f"📢 ADMIN: User {user.id} cancelled broadcast mode via /cancel command")
        else:
            await message.reply_text(
                "ℹ️ No Active Operation\n\nThere is no active operation to cancel."
            )
            logger.info(f"📢 ADMIN: User {user.id} used /cancel but no active broadcast mode")
            
    except Exception as e:
        logger.error(f"Error in cancel_command: {e}")
        await message.reply_text(
            "❌ Error\n\nCould not process cancel command."
        )

# Admin text handling moved to admin_handlers.py to avoid conflicts

async def show_openprovider_accounts(query, context):
    """Display OpenProvider accounts for admin management"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    if not is_admin_user(user.id):
        await query.answer("Access denied", show_alert=True)
        return
    
    try:
        from database import get_openprovider_accounts
        
        accounts = await get_openprovider_accounts()
        
        if not accounts:
            await query.edit_message_text(
                "🏢 <b>OpenProvider Accounts</b>\n\n"
                "No accounts configured.\n"
                "Add accounts to the database to manage them here.",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton(btn_t('back', user_lang), callback_data="main_menu")
                ]])
            )
            return
        
        from services.openprovider_manager import get_account_manager
        
        manager = get_account_manager()
        
        message = "🏢 <b>OpenProvider Account Management</b>\n\n"
        message += "Select an account to set as default for new domain registrations:\n\n"
        
        keyboard = []
        for account in accounts:
            account_id = account['id']
            name = account['account_name']
            username = account['username']
            is_default = account.get('is_default', False)
            is_active = account.get('is_active', True)
            
            client = manager.get_account(account_id)
            auth_status = "✅" if client and client.is_token_valid() else "⏳"
            
            status_icon = "✅" if is_active else "⚠️"
            default_mark = " ⭐" if is_default else ""
            
            message += f"• <b>{name}</b>{default_mark}\n"
            message += f"  {username}\n"
            message += f"  Status: {status_icon} Active | Auth: {auth_status}\n\n"
            
            if is_default:
                label = f"⭐ {name} [DEFAULT]"
                keyboard.append([InlineKeyboardButton(label, callback_data="noop")])
            else:
                label = f"🏢 {name} - Set Default"
                keyboard.append([InlineKeyboardButton(
                    label, 
                    callback_data=f"admin_op_set_default:{account_id}"
                )])
        
        keyboard.append([InlineKeyboardButton("🔄 Validate Credentials", callback_data="admin_op_validate")])
        keyboard.append([InlineKeyboardButton(btn_t('back', user_lang), callback_data="main_menu")])
        
        await query.edit_message_text(
            message,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        
    except Exception as e:
        logger.error(f"Error showing OpenProvider accounts: {e}")
        await query.answer("Error loading accounts", show_alert=True)


async def handle_validate_openprovider_credentials(query, context):
    """Validate credentials for all OpenProvider accounts"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    if not is_admin_user(user.id):
        await query.answer("Access denied", show_alert=True)
        return
    
    await query.answer("Validating credentials...", show_alert=False)
    
    try:
        from services.openprovider_manager import get_account_manager
        from database import get_openprovider_accounts
        
        manager = get_account_manager()
        accounts = await get_openprovider_accounts()
        
        message = "🔐 <b>Credential Validation Results</b>\n\n"
        
        all_valid = True
        for account in accounts:
            account_id = account['id']
            name = account['account_name']
            username = account['username']
            
            client = manager.get_account(account_id)
            if client:
                success = await client.authenticate()
                if success:
                    message += f"✅ <b>{name}</b>\n   {username}\n   Token valid\n\n"
                else:
                    message += f"❌ <b>{name}</b>\n   {username}\n   Authentication failed\n\n"
                    all_valid = False
            else:
                message += f"⚠️ <b>{name}</b>\n   {username}\n   Client not loaded\n\n"
                all_valid = False
        
        if all_valid:
            message += "✅ All accounts authenticated successfully!"
        else:
            message += "⚠️ Some accounts have issues. Check credentials."
        
        keyboard = [
            [InlineKeyboardButton("🔙 Back to Accounts", callback_data="admin_openprovider")],
            [InlineKeyboardButton(btn_t('back', user_lang), callback_data="main_menu")]
        ]
        
        await query.edit_message_text(
            message,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        
        logger.info(f"🏢 ADMIN: User {user.id} validated OpenProvider credentials")
        
    except Exception as e:
        logger.error(f"Error validating OpenProvider credentials: {e}")
        await query.answer("Error validating credentials", show_alert=True)


async def handle_set_default_openprovider_account(query, context, account_id: int):
    """Handle setting a new default OpenProvider account"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    if not is_admin_user(user.id):
        await query.answer("Access denied", show_alert=True)
        return
    
    try:
        from database import set_default_openprovider_account, get_openprovider_account_by_id
        from services.openprovider_manager import get_account_manager
        
        account = await get_openprovider_account_by_id(account_id)
        if not account:
            await query.answer("Account not found", show_alert=True)
            return
        
        success = await set_default_openprovider_account(account_id)
        
        if success:
            manager = get_account_manager()
            manager.set_default_account(account_id)
            
            await query.answer(f"Default set to: {account['account_name']}", show_alert=True)
            logger.info(f"🏢 ADMIN: User {user.id} set OpenProvider default account to {account['account_name']} (ID: {account_id})")
            
            await show_openprovider_accounts(query, context)
        else:
            await query.answer("Failed to set default account", show_alert=True)
            
    except Exception as e:
        logger.error(f"Error setting default OpenProvider account: {e}")
        await query.answer("Error updating account", show_alert=True)


async def handle_admin_dns_sync(query, context):
    """Handle admin DNS synchronization - reconcile database with Cloudflare"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    if not is_admin_user(user.id):
        await query.answer("Access denied", show_alert=True)
        return
    
    try:
        await query.answer("Starting DNS sync...", show_alert=False)
        
        await query.edit_message_text(
            "🔄 <b>DNS Reconciliation</b>\n\n"
            "⏳ Syncing database with Cloudflare...\n"
            "This may take a moment.",
            parse_mode=ParseMode.HTML
        )
        
        from services.dns_reconciliation import dns_reconciliation
        
        result = await dns_reconciliation.reconcile_all_domains(notify_admin=False)
        
        message = (
            "🔄 <b>DNS Reconciliation Complete</b>\n\n"
            f"📊 Domains processed: {result.get('domains_processed', 0)}\n"
            f"🗑️ Orphaned records cleaned: {result.get('total_orphans_deleted', 0)}\n"
            f"📥 Records synced from CF: {result.get('total_records_synced', 0)}\n"
            f"⚠️ Invalid zones found: {result.get('invalid_zones', 0)}\n"
            f"⏱️ Duration: {result.get('duration_seconds', 0):.1f}s"
        )
        
        if result.get('errors'):
            message += f"\n\n❌ Errors: {len(result['errors'])}"
            for err in result['errors'][:3]:
                message += f"\n   • {err[:50]}..."
        
        keyboard = [
            [InlineKeyboardButton("🔄 Run Again", callback_data="admin_dns_sync")],
            [InlineKeyboardButton(btn_t('back', user_lang), callback_data="main_menu")]
        ]
        
        await query.edit_message_text(
            message,
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        
        logger.info(f"🔄 ADMIN: User {user.id} ran DNS sync - {result.get('total_orphans_deleted', 0)} orphans cleaned")
        
    except Exception as e:
        logger.error(f"Error running DNS sync: {e}")
        await query.answer("Error running DNS sync", show_alert=True)


async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /search command"""
    message = update.effective_message
    if not message:
        logger.error("Missing message in search command")
        return
    
    user = update.effective_user
    if not user:
        logger.error("Missing user in search_command")
        return
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and not is_admin_user(user.id):
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
        await message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
        logger.info(f"🔧 MAINTENANCE: Blocked /search command from non-admin user {user.id}")
        return
    
    # Check if user has completed onboarding
    if not await require_user_onboarding(update, context):
        return
        
    # USER INTERACTION LOG: Enhanced logging for anomaly detection
    logger.info(f"🔍 USER_ACTIVITY: /search command from user {user.id} (@{user.username or 'no_username'}) '{user.first_name or 'Unknown'}'")
        
    args = context.args
    
    if not args:
        logger.info(f"🔍 USER_ACTIVITY: /search command with no query from user {user.id}")
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        help_text = t('search.help_title', user_lang) + "\n\n"
        help_text += t('search.help_description', user_lang) + "\n\n"
        help_text += t('search.help_usage', user_lang) + "\n\n"
        help_text += t('search.help_note', user_lang)
        
        keyboard = [
            [InlineKeyboardButton(btn_t('back', user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await message.reply_text(help_text, reply_markup=reply_markup)
        return
    
    domain_name = ' '.join(args).lower().strip()
    
    # USER INTERACTION LOG: Capture actual search query for anomaly detection
    logger.info(f"🔍 USER_DOMAIN_QUERY: User {user.id} searching for domain '{domain_name}'")
    
    # Validate domain before calling OpenProvider
    if not is_valid_domain(domain_name):
        await message.reply_text(
            f"❌ Invalid domain: {domain_name}"
        )
        return
        
    user_lang = await resolve_user_language(user.id, user.language_code) if user else 'en'
    searching_msg = await message.reply_text(f"🔄 {t('wallet.searching_domain', user_lang, domain=domain_name)}")
    
    # Perform enhanced domain search with validation and warnings
    try:
        # Use enhanced validation to detect potential issues before registration
        enhanced_result = await openprovider.check_domain_with_enhanced_validation(domain_name)
        
        if enhanced_result is None:
            # API error or no response - provide helpful fallback
            response_text = f"""
⚠️ Search Unavailable: {domain_name}

{t('errors.service_temporarily_down', user_lang)}
"""
            keyboard = [
                [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="search_domains")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
            ]
        elif enhanced_result.get('available'):
            # Domain is available - extract marked-up pricing and show warnings if any
            price_info = enhanced_result.get('price_info', {})
            create_price = price_info.get('create_price', 0)
            currency = price_info.get('currency', 'USD')  # Now returns USD from markup system
            is_premium = enhanced_result.get('premium', False)
            
            # Format pricing display (price is already marked-up and in USD)
            if create_price > 0:
                price_display = f"{format_money(create_price, currency, include_currency=True)}/year"
                
                # Add markup indicator if markup was applied
                pricing_breakdown = price_info.get('pricing_breakdown', {})
                if pricing_breakdown.get('markup_applied', False):
                    base_price = pricing_breakdown.get('base_price_usd', 0)
                    markup = pricing_breakdown.get('actual_markup', 0)
                    if markup > 0:
                        price_display += f" (includes {format_money(markup, currency, include_currency=True)} service fee)"
            else:
                price_display = t('domain.contact_for_pricing', user_lang)
            
            # Check for warnings and risk factors from enhanced validation
            warnings = enhanced_result.get('warnings', [])
            risk_factors = enhanced_result.get('risk_factors', [])
            recommendations = enhanced_result.get('recommendations', [])
            registration_recommendation = enhanced_result.get('registration_recommendation', 'recommended')
            
            # Build response text with enhanced information
            if registration_recommendation == 'recommended':
                status_icon = "✅"
                status_text = t('domain.status.available', user_lang)
            elif registration_recommendation == 'proceed_with_caution':
                status_icon = "⚠️"
                status_text = t('domain.status.available_with_warnings', user_lang)
            else:
                status_icon = "❌"
                status_text = t('domain.status.not_recommended', user_lang)
            
            domain_type = t('domain.status.premium_domain', user_lang) if is_premium else t('domain.status.standard_domain', user_lang)
            response_text = f"""
{status_icon} {domain_name} {status_text}

{domain_type}
{price_display}
"""
            
            # Add warnings if present
            if warnings:
                response_text += f"\n⚠️ <b>{t('domain.sections.potential_issues', user_lang)}</b>\n"
                for warning in warnings[:2]:  # Show first 2 warnings
                    response_text += f"• {warning}\n"
                
            # Add risk factors if present  
            if risk_factors:
                response_text += f"\n🔍 <b>{t('domain.sections.risk_factors', user_lang)}</b>\n"
                for risk in risk_factors[:2]:  # Show first 2 risks
                    response_text += f"• {risk}\n"
                    
            # Add recommendations if present
            if recommendations and registration_recommendation != 'recommended':
                response_text += f"\n💡 <b>{t('domain.sections.recommendations', user_lang)}</b>\n"
                for rec in recommendations[:1]:  # Show first recommendation
                    response_text += f"• {rec}\n"
            
            # Determine button text based on recommendation
            if registration_recommendation == 'recommended':
                register_button_text = t('domain.buttons.register_domain', user_lang, domain=domain_name)
            elif registration_recommendation == 'proceed_with_caution':
                register_button_text = t('domain.buttons.register_caution', user_lang, domain=domain_name)
            else:
                register_button_text = t('domain.buttons.not_recommended_button', user_lang)
            
            keyboard = []
            
            # Only show register button if domain is eligible for registration
            if enhanced_result.get('eligible_for_registration', False):
                keyboard.append([InlineKeyboardButton(register_button_text, callback_data=f"register_{domain_name}")])
            
            keyboard.extend([
                [InlineKeyboardButton(t("buttons.search_another", user_lang), callback_data="search_domains")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
            ])
        else:
            # Domain is not available or not eligible
            warnings = enhanced_result.get('warnings', [])
            
            if enhanced_result.get('available', False) and not enhanced_result.get('eligible_for_registration', False):
                # Available but not eligible due to validation issues
                response_text = f"""
❌ {domain_name} {t('domain.status.registration_not_recommended', user_lang)}

{t('domain.validation_issues_detected', user_lang)}
"""
                if warnings:
                    response_text += f"\n⚠️ <b>{t('domain.sections.issues', user_lang)}</b>\n"
                    for warning in warnings[:3]:  # Show first 3 warnings
                        response_text += f"• {warning}\n"
                    
                response_text += f"\n💡 {t('domain.try_unique_name', user_lang)}"
            else:
                # Domain is not available
                response_text = f"""
❌ {domain_name} {t('domain.status.unavailable', user_lang)}

{t('domain.already_registered_try_alternatives', user_lang)}
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.search_another", user_lang), callback_data="search_domains")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        if searching_msg:
            await searching_msg.edit_text(response_text, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error searching domain {domain_name}: {e}")
        if searching_msg:
            await searching_msg.edit_text(t('errors.domain_search_failed', user_lang))

async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /profile command with localization and community engagement"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in profile command")
        return
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and not is_admin_user(user.id):
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
        await message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
        logger.info(f"🔧 MAINTENANCE: Blocked /profile command from non-admin user {user.id}")
        return
    
    # Check if user has completed onboarding
    if not await require_user_onboarding(update, context):
        return
    
    try:
        # Get user language for localized response
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get user data for wallet balance and terms status
        user_data = await get_or_create_user(user.id, user.username, user.first_name, user.language_code)
        wallet_balance = await get_user_wallet_balance(user.id)
        has_accepted_terms = await has_user_accepted_terms(user.id)
        
        # Build profile information using localized strings
        username_display = f"@{user.username}" if user.username else "Not set"
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip() or "Not set"
        
        # Get brand configuration for community engagement
        config = BrandConfig()
        
        # Build profile sections
        profile_parts = []
        
        # Profile title
        title_text, _ = t_html('profile.title', user_lang)
        profile_parts.append(title_text)
        profile_parts.append("")
        
        # Telegram details section
        telegram_details, _ = t_html('profile.telegram_details', user_lang)
        profile_parts.append(telegram_details)
        
        username_text, _ = t_html('profile.username', user_lang, username=user.username or "Not set")
        profile_parts.append(username_text)
        
        name_text, _ = t_html('profile.name', user_lang, name=full_name)
        profile_parts.append(name_text)
        
        user_id_text, _ = t_html('profile.user_id', user_lang, user_id=user.id)
        profile_parts.append(user_id_text)
        profile_parts.append("")
        
        # Account status section
        account_status_text, _ = t_html('profile.account_status', user_lang)
        profile_parts.append(account_status_text)
        
        wallet_text, _ = t_html('profile.wallet_balance', user_lang, balance=format_money(wallet_balance))
        profile_parts.append(wallet_text)
        
        terms_status = "✅" if has_accepted_terms else "⏳"
        terms_text, _ = t_html('profile.terms_status', user_lang, status=terms_status)
        profile_parts.append(terms_text)
        profile_parts.append("")
        
        # Available features section
        features_text, _ = t_html('profile.features', user_lang)
        profile_parts.append(features_text)
        
        feature_domains, _ = t_html('profile.feature_domains', user_lang)
        profile_parts.append(feature_domains)
        
        feature_dns, _ = t_html('profile.feature_dns', user_lang)
        profile_parts.append(feature_dns)
        
        feature_hosting, _ = t_html('profile.feature_hosting', user_lang)
        profile_parts.append(feature_hosting)
        
        feature_crypto, _ = t_html('profile.feature_crypto', user_lang)
        profile_parts.append(feature_crypto)
        profile_parts.append("")
        
        # Community engagement section with configurable branding
        community_engagement, _ = t_html('profile.community_engagement', user_lang, 
                                        hostbay_channel=config.hostbay_channel,
                                        hostbay_email=config.hostbay_email,
                                        support_contact=config.support_contact)
        profile_parts.append(community_engagement)
        
        # Join all parts into final profile info
        profile_info = "\n".join(profile_parts)
        
        # Create keyboard with localized back button
        keyboard = [
            [InlineKeyboardButton(btn_t('back', user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await message.reply_text(profile_info, reply_markup=reply_markup, parse_mode=ParseMode.HTML)
        logger.info(f"✅ Profile command completed for user {user.id} in language {user_lang}")
        
    except Exception as e:
        logger.error(f"Error in profile command for user {user.id}: {e}")
        # Get user_lang for error message
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        # Fallback error message
        error_msg = t('errors.profile_load_failed', user_lang)
        keyboard = [
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await message.reply_text(error_msg, reply_markup=reply_markup)

async def hosting_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /hosting command"""
    effective_message = update.effective_message
    if not effective_message:
        logger.error("Missing message in hosting command")
        return
    
    user = update.effective_user
    if user:
        # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
        from services.maintenance_manager import MaintenanceManager
        is_active = await MaintenanceManager.is_maintenance_active()
        if is_active and not is_admin_user(user.id):
            user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
            maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
            await effective_message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
            logger.info(f"🔧 MAINTENANCE: Blocked /hosting command from non-admin user {user.id}")
            return
    
    # Check if user has completed onboarding
    if not await require_user_onboarding(update, context):
        return
    
    # Get user language for localized buttons
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
        
    message_text = """
🏠 Hosting

Choose a plan:
"""
    keyboard = [
        [InlineKeyboardButton(t("buttons.plans", user_lang), callback_data="hosting_plans")],
        [InlineKeyboardButton(t("buttons.my_hosting", user_lang), callback_data="my_hosting")],
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await effective_message.reply_text(message_text, reply_markup=reply_markup)

async def language_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /language command - show language selection interface"""
    user = update.effective_user
    effective_message = update.effective_message
    
    if not user or not effective_message:
        logger.error("Missing user or message in language command")
        return
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and not is_admin_user(user.id):
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
        await effective_message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
        logger.info(f"🔧 MAINTENANCE: Blocked /language command from non-admin user {user.id}")
        return
    
    # Check if user has completed onboarding
    if not await require_user_onboarding(update, context):
        return
    
    try:
        # Get current user language for the interface message
        current_lang = await resolve_user_language(user.id, user.language_code)
        
        # Show language selection interface
        # TODO: Update to use new language selection flow
        await effective_message.reply_text(
            "🌍 Language settings will be available soon. Currently using English.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t("buttons.back", current_lang), callback_data="main_menu")
            ]])
        )
        logger.info(f"✅ Language selection shown to user {user.id}")
        
    except Exception as e:
        logger.error(f"Error in language command for user {user.id}: {e}")
        
        # Get user_lang for error message
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Fallback message
        await effective_message.reply_text(
            t('errors.language_settings_load_failed', user_lang),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="language_selection")
            ]])
        )

async def link_domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /link command - start domain linking process"""
    user = update.effective_user
    effective_message = update.effective_message
    
    if not user or not effective_message:
        logger.error("Missing user or message in link domain command")
        return
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and not is_admin_user(user.id):
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
        await effective_message.reply_text(maintenance_message, parse_mode=ParseMode.HTML)
        logger.info(f"🔧 MAINTENANCE: Blocked /link command from non-admin user {user.id}")
        return
    
    # Check if user has completed onboarding
    if not await require_user_onboarding(update, context):
        return
    
    try:
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Clear any existing domain linking state
        if context.user_data:
            context.user_data.pop('domain_linking_state', None)
        
        # Show domain linking introduction
        await show_domain_linking_intro(user, effective_message, user_lang)
        
    except Exception as e:
        logger.error(f"Error in link domain command for user {user.id}: {e}")
        
        # Get user_lang for error message
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Fallback message
        await effective_message.reply_text(
            t('errors.domain_linking_start_failed', user_lang),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="domain_linking_intro")
            ]])
        )

# ====================================================================
# DOMAIN LINKING FUNCTIONS - Phase 2 Implementation
# ====================================================================

async def show_domain_linking_intro(user, message, user_lang: str):
    """Show domain linking introduction and main interface"""
    try:
        intro_text = f"""
🔗 <b>{t('domain_linking.intro_title', user_lang)}</b>

{t('domain_linking.intro_description', user_lang)} This feature allows you to:

✅ <b>Link External Domains</b>
{t('domain_linking.features.link_external', user_lang)}
{t('domain_linking.features.verify_ownership', user_lang)}
{t('domain_linking.features.configure_hosting', user_lang)}

✅ <b>{t('domain_linking.features.smart_config', user_lang)}</b>
{t('domain_linking.features.dns_analysis', user_lang)}
{t('domain_linking.features.nameserver_mgmt', user_lang)}
{t('domain_linking.features.cloudflare_support', user_lang)}

🚀 <b>Get Started</b>
{t('domain_linking.messages.get_started', user_lang)}

<i>{t('domain_linking.messages.domain_format_example', user_lang)}</i>
        """.strip()
        
        keyboard = [
            [InlineKeyboardButton(t('domain_linking.buttons.start_linking', user_lang), callback_data="domain_linking_start")],
            [InlineKeyboardButton(t('domain_linking.buttons.how_it_works', user_lang), callback_data="domain_linking_help")],
            [InlineKeyboardButton(btn_t('back', user_lang), callback_data="main_menu")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await message.reply_text(intro_text, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing domain linking intro: {e}")
        await message.reply_text(
            t('errors.domain_linking_load_failed', user_lang),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")
            ]])
        )

async def handle_domain_linking_callback(query, callback_data: str, context, user_lang: str):
    """Handle domain linking related callbacks"""
    try:
        action = callback_data.replace("domain_linking_", "")
        
        if action == "intro":
            await show_domain_linking_intro(query.from_user, query.message, user_lang)
            
        elif action == "start":
            await start_domain_linking_flow(query, context, user_lang)
            
        elif action == "help":
            await show_domain_linking_help(query, user_lang)
            
        elif action.startswith("verify_"):
            domain_name = action.replace("verify_", "")
            # Note: query.answer() already called by main callback router
            await safe_edit_message(query, t('domain_linking.verification_coming_soon', user_lang))
            
        elif action.startswith("analyze_"):
            domain_name = action.replace("analyze_", "")
            # Note: query.answer() already called by main callback router
            await safe_edit_message(query, t('domain_linking.analysis_coming_soon', user_lang))
            
        else:
            logger.warning(f"Unknown domain linking action: {action}")
            # Note: query.answer() already called by main callback router
            await safe_edit_message(query, t('errors.unknown_action', user_lang))
            
    except Exception as e:
        logger.error(f"Error in domain linking callback: {e}")
        # Note: query.answer() already called by main callback router
        await safe_edit_message(query, t('errors.general_retry', user_lang))

async def start_domain_linking_flow(query, context, user_lang: str):
    """Start the domain linking workflow by asking for domain name"""
    try:
        # Set user state to expect domain input
        if not context.user_data:
            context.user_data = {}
        context.user_data['awaiting_domain_for_linking'] = True
        
        message_text = t('domain_linking.input_prompt', user_lang, format_example=t('domain_linking.messages.domain_format_example', user_lang))
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data="domain_linking_intro")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message_text, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error starting domain linking flow: {e}")
        # Note: query.answer() already called by main callback router
        await safe_edit_message(query, t('errors.process_start_failed', user_lang))

async def show_domain_linking_help(query, user_lang: str):
    """Show help information for domain linking"""
    try:
        help_text = f"""
{t('domain_linking.messages.how_it_works_title', user_lang)}

<b>{t('domain_linking.messages.step1_title', user_lang)}</b>
{t('domain_linking.messages.step1_desc', user_lang)}

<b>{t('domain_linking.messages.step2_title', user_lang)}</b>
{t('domain_linking.messages.step2_desc', user_lang)}

<b>{t('domain_linking.messages.step3_title', user_lang)}</b>
{t('domain_linking.messages.step3_desc', user_lang)}

<b>{t('domain_linking.messages.requirements_title', user_lang)}</b>
{t('domain_linking.messages.requirements', user_lang)}

<b>{t('domain_linking.messages.supported_title', user_lang)}</b>
{t('domain_linking.messages.supported', user_lang)}
        """.strip()
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.start_linking", user_lang), callback_data="domain_linking_start")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="domain_linking_intro")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, help_text, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing domain linking help: {e}")
        # Note: query.answer() already called by main callback router
        await safe_edit_message(query, t('errors.help_load_failed', user_lang))

async def handle_domain_linking_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text input for domain linking process"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message or not message.text:
        return
    
    # Check if user is in domain linking flow
    if not context.user_data or not context.user_data.get('awaiting_domain_for_linking'):
        return
    
    try:
        domain_name = message.text.strip().lower()
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Clear the awaiting state
        context.user_data['awaiting_domain_for_linking'] = False
        
        # Validate domain format
        if not is_valid_domain_format(domain_name):
            error_msg = f"""
❌ <b>{t('domain_linking.messages.invalid_format', user_lang)}</b>

{t('domain_linking.messages.format_requirements', user_lang)}
            """.strip()
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="domain_linking_start")],
                [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data="domain_linking_intro")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await message.reply_text(error_msg, reply_markup=reply_markup, parse_mode='HTML')
            return
        
        # Start domain linking orchestration
        await initiate_domain_linking_process(user, message, domain_name, context, user_lang)
        
    except Exception as e:
        logger.error(f"Error handling domain linking text input: {e}")
        # Get user_lang for error message
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        await message.reply_text(
            t('errors.domain_processing_failed', user_lang),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="domain_linking_start")
            ]])
        )

def is_valid_domain_format(domain: str) -> bool:
    """Validate domain format"""
    import re
    
    # Basic domain validation regex
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not re.match(domain_pattern, domain):
        return False
    
    # Additional checks
    if len(domain) > 253:
        return False
    
    if '.' not in domain:
        return False
        
    # Check for common invalid patterns
    if domain.startswith('http://') or domain.startswith('https://'):
        return False
    
    if domain.startswith('www.'):
        return False
    
    return True

async def initiate_domain_linking_process(user, message, domain_name: str, context, user_lang: str):
    """Initiate the domain linking process using the orchestrator"""
    try:
        # Get user ID
        user_id = await get_internal_user_id_from_telegram_id(user.id)
        if not user_id:
            await message.reply_text(t('errors.user_not_found_start_required', user_lang))
            return
        
        # Create orchestrator instance
        orchestrator = DomainLinkingOrchestrator()
        
        # Show processing message
        processing_msg = await message.reply_text(
            t('domain_linking.analyzing', user_lang, domain=domain_name),
            parse_mode='HTML'
        )
        
        # Start the linking process
        result = await orchestrator.create_linking_intent(
            user_id=user_id,
            domain_name=domain_name,
            hosting_subscription_id=None,  # For Phase 1, no specific hosting subscription
            intent_type="smart_mode"  # Default to smart mode
        )
        
        if result['success']:
            # Show success message with next steps
            success_msg = t('domain_linking.analysis_complete', user_lang, 
                          domain=domain_name,
                          status=result.get('status', 'Analyzed'),
                          message=result.get('message', 'Domain linking process initiated successfully.'),
                          next_steps=result.get('next_steps', 'Please follow the verification instructions.'))
            
            keyboard = []
            if result.get('verification_token'):
                keyboard.append([InlineKeyboardButton(t("buttons.view_instructions", user_lang), callback_data=f"domain_linking_verify_{domain_name}")])
            
            keyboard.extend([
                [InlineKeyboardButton(t("buttons.check_status", user_lang), callback_data=f"domain_linking_status_{domain_name}")],
                [InlineKeyboardButton(t("buttons.back_to_menu", user_lang), callback_data="main_menu")]
            ])
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await processing_msg.edit_text(success_msg, reply_markup=reply_markup, parse_mode='HTML')
            
        else:
            # Show error message
            error_msg = t('domain_linking.analysis_failed', user_lang,
                        domain=domain_name,
                        error=result.get('error', 'Unknown error occurred'),
                        message=result.get('message', 'Please check the domain and try again.'))
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="domain_linking_start")],
                [InlineKeyboardButton(t("buttons.get_help", user_lang), callback_data="domain_linking_help")],
                [InlineKeyboardButton(t("buttons.back_to_menu", user_lang), callback_data="main_menu")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await processing_msg.edit_text(error_msg, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error initiating domain linking process: {e}")
        await message.reply_text(
            t('errors.domain_linking_process_failed', user_lang),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t("buttons.back_to_menu", user_lang), callback_data="main_menu")
            ]])
        )

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all inline keyboard callback queries"""
    query = update.callback_query
    if not query:
        logger.error("Missing callback query in handle_callback")
        return
    
    # USER INTERACTION LOG: Enhanced logging for anomaly detection
    user = query.from_user
    logger.info(f"🖱️ USER_ACTIVITY: Button click from user {user.id if user else 'unknown'} (@{user.username if user else 'no_username'}) - action: {query.data}")
    
    # Resolve user language early for error messages
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    from services.maintenance_manager import MaintenanceManager
    is_active = await MaintenanceManager.is_maintenance_active()
    if is_active and user and not is_admin_user(user.id):
        try:
            await query.answer()
        except:
            pass
        maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
        
        # Try to send maintenance message via the message object if available
        from telegram import Message
        if query.message and isinstance(query.message, Message):
            try:
                await query.message.edit_text(maintenance_message, parse_mode=ParseMode.HTML)
            except:
                pass
        logger.info(f"🔧 MAINTENANCE: Blocked callback from non-admin user {user.id}")
        return
    
    # Answer callback query with error handling for expired queries
    try:
        await query.answer()
    except Exception as e:
        # Silently handle expired/old callback queries (common after bot restart)
        if "too old" in str(e).lower() or "timeout" in str(e).lower() or "invalid" in str(e).lower():
            logger.debug(f"Handled expired callback query: {e}")
        else:
            logger.warning(f"Callback answer error: {e}")
        # Continue processing the callback even if answer fails
    
    # Decompress callback data if it's compressed
    data = await decompress_callback(query.data, context)
    
    # Log callback resolution if needed
    if query.data != data or data.startswith("error:"):
        logger.info(f"Callback data resolved: {query.data} -> {data}")
    
    try:
        # Terms acceptance callbacks
        if data.startswith("terms:") or data in ["accept_terms", "decline_terms", "full_terms"]:
            logger.info(f"Routing to: handle_terms_callback")
            await handle_terms_callback(update, context)
        elif data == "main_menu":
            logger.info(f"Routing to: show_personalized_dashboard")
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await show_personalized_dashboard(query)
        elif data == "search_domains":
            logger.info(f"Routing to: show_search_interface")
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await show_search_interface(query)
        elif data == "my_domains":
            logger.info(f"Routing to: show_user_domains_complete")
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await show_user_domains_complete(query, context)
        elif data == "wallet_main":
            logger.info(f"Routing to: show_wallet_interface")
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await show_wallet_interface(query, context)
        elif data == "profile_main":
            logger.info(f"Routing to: show_profile_interface")
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await show_profile_interface(query)
        elif data == "reseller_program":
            logger.info(f"Routing to: show_reseller_info")
            await show_reseller_info(query)
        elif data == "contact_support":
            logger.info(f"Routing to: show_contact_support")
            await show_contact_support(query)
        
        # API Management routes
        elif data == "api_management_main":
            logger.info(f"Routing to: show_api_management_dashboard")
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await show_api_management_dashboard(update, context)
        elif data == "api_create_start":
            logger.info(f"Routing to: start_api_key_creation")
            await start_api_key_creation(update, context)
        elif data.startswith("api_env_"):
            logger.info(f"Routing to: toggle_environment")
            await toggle_environment(update, context)
        elif data == "api_create_environment":
            logger.info(f"Routing to: show_environment_selector (back)")
            await show_environment_selector(update, context)
        elif data == "api_create_security":
            logger.info(f"Routing to: show_security_settings")
            await show_security_settings(update, context)
        elif data == "api_create_generate":
            logger.info(f"Routing to: generate_and_show_api_key")
            await generate_and_show_api_key(update, context)
        elif data.startswith("api_manage_"):
            logger.info(f"Routing to: show_api_key_management")
            await show_api_key_management(update, context)
        elif data.startswith("api_stats_"):
            logger.info(f"Routing to: show_api_key_stats")
            await show_api_key_stats(update, context)
        elif data.startswith("api_revoke_confirm_"):
            logger.info(f"Routing to: revoke_api_key")
            await revoke_api_key(update, context)
        elif data.startswith("api_revoke_"):
            logger.info(f"Routing to: confirm_api_key_revoke")
            await confirm_api_key_revoke(update, context)
        elif data == "api_docs_main":
            logger.info(f"Routing to: show_api_documentation")
            await show_api_documentation(update, context)
        
        elif data.startswith("domain_linking_"):
            logger.info(f"Routing to: handle_domain_linking_callback")
            user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code)
            await handle_domain_linking_callback(query, data, context, user_lang)
        elif data == "language_selection":
            logger.info(f"Routing to: show_language_selection")
            # Create an Update object from the query for proper routing
            mock_update = Update(update_id=0, callback_query=query)
            await show_language_selection(mock_update, context)
        elif data == "language_selection_from_profile":
            logger.info(f"Routing to: show_language_selection_from_profile")
            # Create an Update object from the query for proper routing
            mock_update = Update(update_id=0, callback_query=query)
            await show_language_selection_from_profile(mock_update, context)
        elif data.startswith("language_select_from_profile_"):
            # Handle language selection from profile: language_select_from_profile_{lang_code}
            lang_code = data.replace("language_select_from_profile_", "")
            logger.info(f"Routing to: handle_language_selection_from_profile for {lang_code}")
            # Create an Update object from the query for the new handler
            mock_update = Update(update_id=0, callback_query=query)
            await handle_language_selection_from_profile(mock_update, context)
        elif data.startswith("language_select_"):
            # Handle language selection: language_select_{lang_code}
            lang_code = data.replace("language_select_", "")
            logger.info(f"Routing to: handle_language_selection for {lang_code}")
            # Create an Update object from the query for the new handler
            mock_update = Update(update_id=0, callback_query=query)
            await handle_language_selection(mock_update, context)
        elif data == "domain_hosting_bundle":
            await show_domain_hosting_bundle(query)
        elif data == "bundle_how_it_works":
            await show_bundle_how_it_works(query)
        elif data.startswith("bundle_plan_"):
            plan_id = data.replace("bundle_plan_", "")
            await start_bundle_domain_search(query, context, plan_id)
        elif data.startswith("confirm_bundle_"):
            # Parse: confirm_bundle_{plan_id}_{domain_name}
            parts = data.replace("confirm_bundle_", "").split("_", 1)
            if len(parts) >= 2:
                plan_id = parts[0]
                domain_name = parts[1]
                await confirm_bundle_purchase(query, plan_id, domain_name)
        elif data == "admin_broadcast":
            logger.info(f"Routing to: handle_admin_broadcast")
            await handle_admin_broadcast(query, context)
        elif data == "admin_credit_wallet":
            logger.info(f"Routing to: handle_admin_credit_wallet")
            await handle_admin_credit_wallet(update, context)
        elif data == "admin_openprovider_accounts":
            logger.info(f"Routing to: show_openprovider_accounts")
            await show_openprovider_accounts(query, context)
        elif data.startswith("admin_op_set_default:"):
            account_id = int(data.replace("admin_op_set_default:", ""))
            logger.info(f"Routing to: set_default_openprovider_account for {account_id}")
            await handle_set_default_openprovider_account(query, context, account_id)
        elif data == "admin_op_validate":
            logger.info(f"Routing to: handle_validate_openprovider_credentials")
            await handle_validate_openprovider_credentials(query, context)
        elif data == "admin_openprovider":
            logger.info(f"Routing to: show_openprovider_accounts (back)")
            await show_openprovider_accounts(query, context)
        elif data == "admin_dns_sync":
            logger.info(f"Routing to: handle_admin_dns_sync")
            await handle_admin_dns_sync(query, context)
        elif data.startswith("admin_execute_credit:"):
            # Handle admin credit execution: admin_execute_credit:{user_id}:{amount}
            parts = data.split(":")
            if len(parts) >= 3:
                target_user_id = int(parts[1])
                amount = float(parts[2])
                await execute_admin_credit(query, target_user_id, amount)
        elif data == "cancel_broadcast":
            logger.info(f"Routing to: handle_cancel_broadcast")
            await handle_cancel_broadcast(query, context)
        elif data.startswith("maintenance:"):
            logger.info(f"Routing to: maintenance handlers")
            from admin_handlers import handle_maintenance_enable, handle_maintenance_disable, handle_maintenance_status
            if data == "maintenance:status":
                await handle_maintenance_status(query, context)
            elif data == "maintenance:disable":
                await handle_maintenance_disable(query, context)
            elif data.startswith("maintenance:enable:"):
                duration_str = data.replace("maintenance:enable:", "")
                duration_minutes = int(duration_str)
                await handle_maintenance_enable(query, context, duration_minutes)
        elif data.startswith("register_"):
            domain_name = data.replace("register_", "")
            # Check if user is in unified hosting flow context
            if hasattr(context, 'user_data') and context.user_data:
                unified_flow = context.user_data.get('unified_flow')
                plan_id = context.user_data.get('unified_plan_id')
                if unified_flow == 'awaiting_new_domain' and plan_id:
                    # Route to hosting+domain bundle flow
                    logger.info(f"🔄 Redirecting register_{domain_name} to unified hosting bundle for plan {plan_id}")
                    await unified_checkout(query, 'new', plan_id, domain_name)
                    return
            # Default to domain-only registration
            await start_domain_registration(query, domain_name)
        elif data.startswith("pay_hosting_"):
            # Handle hosting payment selection: pay_hosting_{method}_{subscription_id}_{price}
            parts = data.split("_", 4)
            if len(parts) >= 5:
                payment_method = parts[2]  # wallet, btc, ltc, etc.
                subscription_id = parts[3]
                price = parts[4]
                
                if payment_method == "wallet":
                    await process_hosting_wallet_payment(query, subscription_id, price)
                else:
                    await process_hosting_crypto_payment(query, payment_method, subscription_id, price)
        elif data.startswith("pay_"):
            # Handle domain payment selection: pay_{method}_{domain}_{price}_{currency}
            parts = data.split("_", 4)
            if len(parts) >= 5:
                payment_method = parts[1]
                domain_name = parts[2]
                price = parts[3]
                currency = parts[4]
                
                # 🎯 INSTANT FEEDBACK: Show immediate payment processing message
                if payment_method == "wallet":
                    feedback_msg = f"💳 <b>Wallet Payment</b> • ${float(price):.2f}\n🌐 <code>{domain_name}</code>\n⏳ Verifying balance..."
                else:
                    crypto_name = payment_method.upper()
                    feedback_msg = f"₿ <b>Setting up {crypto_name} Payment...</b>\n\n"
                    feedback_msg += f"🌐 Domain: <code>{domain_name}</code>\n"
                    feedback_msg += f"💰 Amount: ${float(price):.2f}\n"
                    feedback_msg += f"⏳ Generating payment address..."
                
                await safe_edit_message(query, feedback_msg, parse_mode='HTML')
                
                if payment_method == "wallet":
                    await process_wallet_payment(query, domain_name, price, currency)
                else:
                    await process_crypto_payment(query, payment_method, domain_name, price, currency)
        # Removed manual payment checking - payments are processed automatically via webhooks
        elif data == "wallet_deposit":
            await show_wallet_deposit_options(query)
        elif data.startswith("deposit_amount_"):
            # Handle deposit amount selection: deposit_amount_{amount} or deposit_amount_custom
            amount_str = data.replace("deposit_amount_", "")
            if amount_str == "custom":
                # Set user state to expect custom amount input using context.user_data
                context.user_data['awaiting_deposit_amount'] = True
                keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="wallet_deposit")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await safe_edit_message(query, "💵 Custom Amount\n\nPlease send your desired deposit amount (minimum $10).\n\nExample: 50", reply_markup=reply_markup)
            else:
                # Preset amount selected
                try:
                    amount = float(amount_str)
                    if amount < 10:
                        await safe_edit_message(query, f"❌ Minimum deposit is $10 USD")
                    else:
                        await show_crypto_selection_for_deposit(query, amount)
                except ValueError:
                    await safe_edit_message(query, "❌ Invalid amount")
        elif data.startswith("deposit_"):
            # Handle crypto deposits: deposit_{crypto_code} or deposit_{crypto_code}:{amount}
            crypto_and_amount = data.replace("deposit_", "")
            
            # Check if amount is included using colon separator
            if ":" in crypto_and_amount:
                # New flow: deposit_{crypto}:{amount}
                parts = crypto_and_amount.split(":", 1)
                crypto_code = parts[0]
                try:
                    amount_usd = float(parts[1])
                    if amount_usd < 10:
                        await safe_edit_message(query, f"❌ Minimum deposit is $10 USD")
                    elif crypto_config.is_supported(crypto_code):
                        await process_wallet_crypto_deposit(query, crypto_code, amount_usd)
                    else:
                        await safe_edit_message(query, f"❌ Unsupported cryptocurrency: {crypto_code}")
                except ValueError:
                    await safe_edit_message(query, "❌ Invalid amount format")
            else:
                # Legacy flow: deposit_{crypto} without amount (old UI or backwards compatibility)
                crypto_code = crypto_and_amount
                if crypto_config.is_supported(crypto_code):
                    # Redirect to amount selection for better UX
                    await safe_edit_message(query, "Please select deposit amount first")
                    await show_wallet_deposit_options(query)
                else:
                    await safe_edit_message(query, f"❌ Unsupported cryptocurrency: {crypto_code}")
        elif data.startswith("check_wallet_deposit:"):
            # Handle wallet deposit status check: check_wallet_deposit:{order_id}
            order_id = data.replace("check_wallet_deposit:", "")
            await check_wallet_deposit_status(query, order_id)
        elif data.startswith("copy_address_"):
            # Handle copy address - provide immediate feedback
            address = data.replace("copy_address_", "")
            await handle_copy_address(query, address)
        elif data.startswith("copy_memo_"):
            # Handle copy memo - provide immediate feedback  
            memo = data.replace("copy_memo_", "")
            await handle_copy_memo(query, memo)
        # Removed copy username and copy password handlers as requested
        elif data.startswith("copy_server_"):
            # Handle copy hosting server
            server = data.replace("copy_server_", "")
            await handle_copy_hosting_credential(query, server, "Server")
        elif data.startswith("copy_url_"):
            # Handle copy hosting URL
            url = data.replace("copy_url_", "")
            await handle_copy_hosting_credential(query, url, "URL")
        elif data.startswith("show_wallet_qr:"):
            # Handle wallet QR code display: show_wallet_qr:{order_id}
            order_id = data.replace("show_wallet_qr:", "")
            await show_wallet_qr_code(query, order_id)
        elif data.startswith("cancel_wallet_deposit:"):
            # Handle wallet deposit cancellation: cancel_wallet_deposit:{order_id}
            order_id = data.replace("cancel_wallet_deposit:", "")
            await cancel_wallet_deposit(query, order_id)
        elif data.startswith("back_to_wallet_payment:"):
            # Handle return to wallet payment: back_to_wallet_payment:{order_id}
            order_id = data.replace("back_to_wallet_payment:", "")
            await back_to_wallet_payment(query, order_id)
        elif data == "wallet_deposit_from_qr":
            # Handle return to crypto selection from QR code photo
            await handle_wallet_deposit_from_qr(query)
        elif data.startswith("qr_back_to_payment:"):
            # Handle back to payment from domain QR code photo
            domain_name = data.replace("qr_back_to_payment:", "")
            await handle_qr_back_to_payment(query, domain_name)
        elif data == "qr_cancel_order":
            # Handle cancel order from domain QR code photo
            await handle_qr_cancel_order(query)
        elif data.startswith("cancel_wallet_deposit_from_qr:"):
            # Handle cancel deposit from QR code photo
            order_id = data.replace("cancel_wallet_deposit_from_qr:", "")
            await handle_cancel_wallet_deposit_from_qr(query, order_id)
        elif data.startswith("cancel_deposit:"):
            # Handle cancel deposit from QR code photo (shorter callback)
            order_id = data.replace("cancel_deposit:", "")
            await handle_cancel_wallet_deposit_from_qr(query, order_id)
        elif data == "wallet_history":
            await show_wallet_transaction_history(query)
        elif data.startswith("domain_manage_"):
            domain_id = data.replace("domain_manage_", "")
            await show_domain_management(query, domain_id)
        elif data.startswith("dns_rec:") or data.startswith("dns_record:"):
            # Short DNS record callback (compressed to avoid 64-byte limit)
            short_id = data.replace("dns_rec:", "").replace("dns_record:", "")
            result = resolve_short_dns_callback(short_id)
            if result:
                domain, record_id = result
                await show_dns_record_detail(query, domain, record_id)
            else:
                user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
                await safe_edit_message(query, t('errors.dns_record_link_expired', user_lang))
        elif data.startswith("dns_edit:") and ":" not in data[9:]:
            # Short DNS edit callback (compressed to avoid 64-byte limit)
            # Only handle if there are NO additional colons after "dns_edit:" (short hash format)
            short_id = data.replace("dns_edit:", "")
            result = resolve_short_dns_callback(short_id)
            if result:
                domain, record_id = result
                # Store edit context for simplified callback routing
                if context.user_data is None:
                    context.user_data = {}
                context.user_data['edit_context'] = {
                    'domain': domain,
                    'record_id': record_id
                }
                await start_dns_edit_wizard(query, context, domain, record_id)
            else:
                user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
                await safe_edit_message(query, t('errors.dns_edit_link_expired', user_lang))
        elif data.startswith("dns_delete:"):
            # Short DNS delete callback (compressed to avoid 64-byte limit)
            short_id = data.replace("dns_delete:", "")
            result = resolve_short_dns_callback(short_id)
            if result:
                domain, record_id = result
                await confirm_dns_delete(query, context, domain, record_id)
            else:
                user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
                await safe_edit_message(query, t('errors.dns_delete_link_expired', user_lang))
        elif data.startswith("dns_nav:"):
            # Short DNS navigation callback (compressed for long domains)
            short_id = data.replace("dns_nav:", "")
            result = resolve_short_dns_nav(short_id)
            if result:
                domain, path = result
                # Route to appropriate handler based on path
                if path == "view":
                    await show_dns_dashboard(query, domain)
                elif path == "list" or path.startswith("list:"):
                    page = int(path.split(":")[1]) if ":" in path else 1
                    await show_dns_record_list(query, domain, page)
                elif path == "add":
                    await show_dns_add_type_picker(query, domain)
                elif path.startswith("add:"):
                    record_type = path.split(":")[1]
                    await continue_dns_add_wizard(query, domain, record_type, 1)
                elif path == "nameservers" or path == "ns":
                    await show_nameserver_management(query, domain, context)
                elif path == "ns:update":
                    await show_custom_nameserver_form(query, context, domain)
                else:
                    user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
                    await safe_edit_message(query, t('errors.unknown_navigation_path', user_lang))
            else:
                user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
                await safe_edit_message(query, t('errors.navigation_link_expired', user_lang))
        elif data.startswith("dns:"):
            # New standardized DNS callback routing: dns:{domain}:{action}[:type][:id][:page]
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await handle_dns_callback(query, context, data)
        elif data.startswith("del:"):
            # Shortened delete callback: del:{record_id}
            await handle_delete_callback(query, context, data)
        elif data.startswith("edit_mx_priority:"):
            # MX priority selection: edit_mx_priority:{record_id}:{priority}
            await handle_mx_priority_selection(query, context, data)
        elif data.startswith("dns_edit:"):
            # DNS edit callbacks: dns_edit:{domain}:{type}:{action}:{record_id}
            await handle_dns_edit_callback(query, context, data)
        elif data.startswith("edit_ttl:"):
            # TTL selection callbacks: edit_ttl:{record_id}:{ttl_value}
            await handle_ttl_selection(query, context, data)
        elif data.startswith("dns_wizard:"):
            # Handle DNS wizard callbacks: dns_wizard:{domain}:{type}:{field}:{value}
            logger.info(f"Routing to: handle_dns_wizard_callback")
            await handle_dns_wizard_callback(query, context, data)
        elif data.startswith("setup_dns_"):
            # Handle DNS zone setup for domains missing Cloudflare zones
            domain_name = data.replace("setup_dns_", "")
            logger.info(f"Routing to: handle_setup_dns_zone (domain: {domain_name})")
            await handle_setup_dns_zone(query, context, domain_name)
        elif data.startswith("dns_") and ":" not in data:
            # Legacy DNS callback - redirect to new system (only for plain domain names)
            domain_name = data.replace("dns_", "")
            logger.info(f"Converting dns_ callback: {data} -> dns:{domain_name}:view")
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await handle_dns_callback(query, context, f"dns:{domain_name}:view")
        elif data == "hosting_main":
            logger.info(f"Routing to: show_hosting_interface")
            from admin_handlers import clear_admin_states
            clear_admin_states(context)
            await show_hosting_interface(query, context)
        # RDP Server callbacks
        elif data == "rdp_main":
            logger.info(f"Routing to: handle_rdp_main")
            await handle_rdp_main(query)
        elif data == "rdp_purchase_start":
            logger.info(f"Routing to: handle_rdp_purchase_start")
            await handle_rdp_purchase_start(query, context)
        elif data == "rdp_quick_deploy":
            logger.info(f"Routing to: handle_rdp_quick_deploy")
            await handle_rdp_quick_deploy(query, context)
        elif data == "rdp_quick_confirm":
            logger.info(f"Routing to: handle_rdp_quick_confirm")
            await handle_rdp_quick_confirm(query, context)
        elif data == "rdp_customize_start":
            logger.info(f"Routing to: handle_rdp_customize_start")
            await handle_rdp_customize_start(query, context)
        elif data == "rdp_change_windows":
            logger.info(f"Routing to: handle_rdp_change_windows")
            await handle_rdp_change_windows(query, context)
        elif data.startswith("rdp_select_plan_"):
            plan_id = data.replace("rdp_select_plan_", "")
            logger.info(f"Routing to: handle_rdp_select_plan (plan {plan_id})")
            await handle_rdp_select_plan(query, context, plan_id)
        elif data.startswith("rdp_set_template_"):
            template_id = data.replace("rdp_set_template_", "")
            logger.info(f"Routing to: handle_rdp_set_template (template {template_id})")
            await handle_rdp_set_template(query, context, template_id)
        elif data == "rdp_region_smart":
            logger.info(f"Routing to: handle_rdp_region_smart")
            await handle_rdp_region_smart(query, context)
        elif data.startswith("rdp_change_billing_"):
            region_code = data.replace("rdp_change_billing_", "")
            logger.info(f"Routing to: handle_rdp_change_billing (region {region_code})")
            await handle_rdp_change_billing(query, context, region_code)
        elif data.startswith("rdp_set_region_"):
            region_code = data.replace("rdp_set_region_", "")
            logger.info(f"Routing to: handle_rdp_set_region (region {region_code})")
            await handle_rdp_set_region(query, context, region_code)
        elif data == "rdp_regions_all":
            logger.info(f"Routing to: handle_rdp_regions_all")
            await handle_rdp_regions_all(query, context)
        elif data == "rdp_back_to_confirmation":
            logger.info(f"Routing to: handle_rdp_back_to_confirmation")
            wizard = context.user_data.get('rdp_wizard', {})
            confirmation_source = wizard.get('confirmation_source', 'customize')
            if confirmation_source == 'quick_deploy':
                await handle_rdp_quick_deploy(query, context)
            else:
                await handle_rdp_compact_confirmation(query, context)
        elif data.startswith("rdp_template_"):
            template_id = data.replace("rdp_template_", "")
            logger.info(f"Routing to: handle_rdp_template_selection (template {template_id})")
            await handle_rdp_template_selection(query, context, template_id)
        elif data.startswith("rdp_plan_"):
            plan_id = data.replace("rdp_plan_", "")
            logger.info(f"Routing to: handle_rdp_plan_selection (plan {plan_id})")
            await handle_rdp_plan_selection(query, context, plan_id)
        elif data.startswith("rdp_region_"):
            region_id = data.replace("rdp_region_", "")
            logger.info(f"Routing to: handle_rdp_region_selection (region {region_id})")
            await handle_rdp_region_selection(query, context, region_id)
        elif data.startswith("rdp_billing_") and data.endswith("_confirm"):
            billing_cycle = data.replace("rdp_billing_", "").replace("_confirm", "")
            logger.info(f"Routing to: handle_rdp_billing_confirm (cycle {billing_cycle})")
            await handle_rdp_billing_confirm(query, context, billing_cycle)
        elif data.startswith("rdp_billing_"):
            billing_cycle = data.replace("rdp_billing_", "")
            logger.info(f"Routing to: handle_rdp_billing_selection (cycle {billing_cycle})")
            await handle_rdp_billing_selection(query, context, billing_cycle)
        elif data == "rdp_confirm_and_create_order":
            logger.info(f"Routing to: handle_rdp_confirm_and_create_order")
            await handle_rdp_confirm_and_create_order(query, context)
        elif data == "rdp_select_payment_method":
            logger.info(f"Routing to: handle_rdp_select_payment_method")
            await handle_rdp_select_payment_method(query, context)
        elif data == "rdp_pay_wallet":
            logger.info(f"Routing to: handle_rdp_pay_wallet")
            await handle_rdp_pay_wallet(query, context)
        elif data == "rdp_pay_crypto":
            logger.info(f"Routing to: handle_rdp_pay_crypto")
            await handle_rdp_pay_crypto(query, context)
        elif data.startswith("rdp_crypto_"):
            currency = data.replace("rdp_crypto_", "")
            logger.info(f"Routing to: handle_rdp_crypto_currency (currency: {currency})")
            await handle_rdp_crypto_currency(query, context, currency)
        elif data.startswith("rdp_cancel_order:"):
            order_uuid = data.replace("rdp_cancel_order:", "")
            logger.info(f"Routing to: handle_rdp_cancel_order (order {order_uuid})")
            await handle_rdp_cancel_order(query, context, order_uuid)
        elif data.startswith("rdp_crypto_from_qr:"):
            # Handle return to RDP crypto selection from QR code photo
            order_uuid = data.replace("rdp_crypto_from_qr:", "")
            logger.info(f"Routing to: handle_rdp_crypto_from_qr (order {order_uuid})")
            await handle_rdp_crypto_from_qr(query, context, order_uuid)
        elif data.startswith("rdp_payment_back:"):
            order_uuid = data.replace("rdp_payment_back:", "")
            logger.info(f"Routing to: handle_rdp_payment_back (order {order_uuid})")
            await handle_rdp_payment_back(query, context, order_uuid)
        elif data == "rdp_my_servers":
            logger.info(f"Routing to: handle_rdp_my_servers")
            await handle_rdp_my_servers(query, context)
        elif data.startswith("rdp_server_") and not data.startswith("rdp_servers"):
            server_id = data.replace("rdp_server_", "")
            logger.info(f"Routing to: handle_rdp_server_details (server {server_id})")
            await handle_rdp_server_details(query, context, server_id)
        elif data.startswith("rdp_start_"):
            server_id = data.replace("rdp_start_", "")
            logger.info(f"Routing to: handle_rdp_start_server (server {server_id})")
            await handle_rdp_start_server(query, context, server_id)
        elif data.startswith("rdp_stop_"):
            server_id = data.replace("rdp_stop_", "")
            logger.info(f"Routing to: handle_rdp_stop_server (server {server_id})")
            await handle_rdp_stop_server(query, context, server_id)
        elif data.startswith("rdp_restart_"):
            server_id = data.replace("rdp_restart_", "")
            logger.info(f"Routing to: handle_rdp_restart_server (server {server_id})")
            await handle_rdp_restart_server(query, context, server_id)
        elif data.startswith("rdp_reinstall_confirm_"):
            server_id = data.replace("rdp_reinstall_confirm_", "")
            logger.info(f"Routing to: handle_rdp_reinstall_confirm (server {server_id})")
            await handle_rdp_reinstall_confirm(query, context, server_id)
        elif data.startswith("rdp_reinstall_"):
            server_id = data.replace("rdp_reinstall_", "")
            logger.info(f"Routing to: handle_rdp_reinstall (server {server_id})")
            await handle_rdp_reinstall(query, context, server_id)
        elif data.startswith("rdp_delete_confirm_"):
            server_id = data.replace("rdp_delete_confirm_", "")
            logger.info(f"Routing to: handle_rdp_delete_confirm (server {server_id})")
            await handle_rdp_delete_confirm(query, context, server_id)
        elif data.startswith("rdp_delete_"):
            server_id = data.replace("rdp_delete_", "")
            logger.info(f"Routing to: handle_rdp_delete (server {server_id})")
            await handle_rdp_delete(query, context, server_id)
        elif data == "hosting_plans":
            # Legacy route - redirect to unified flow
            logger.info(f"Redirecting legacy hosting_plans to unified flow")
            await unified_hosting_flow(query)
        elif data == "my_hosting":
            await show_my_hosting(query)
        elif data.startswith("select_plan_"):
            # Legacy route - redirect to unified plan selection
            plan_id = data.replace("select_plan_", "")
            logger.info(f"Redirecting legacy select_plan_{plan_id} to unified flow")
            await handle_unified_plan_selection(query, context, plan_id)
        elif data.startswith("purchase_plan_"):
            # Legacy route - redirect to unified plan selection
            plan_id = data.replace("purchase_plan_", "")
            logger.info(f"Redirecting legacy purchase_plan_{plan_id} to unified flow")
            await handle_unified_plan_selection(query, context, plan_id)
        elif data.startswith("confirm_purchase_"):
            # Legacy route - redirect to unified plan selection
            plan_id = data.replace("confirm_purchase_", "")
            logger.info(f"Redirecting legacy confirm_purchase_{plan_id} to unified flow")
            await handle_unified_plan_selection(query, context, plan_id)
        # UNIFIED HOSTING FLOW CALLBACKS
        elif data == "unified_hosting_plans":
            await unified_hosting_flow(query)
        elif data.startswith("unified_plan_"):
            plan_id = data.replace("unified_plan_", "")
            await handle_unified_plan_selection(query, context, plan_id)
        elif data.startswith("unified_new_domain_"):
            plan_id = data.replace("unified_new_domain_", "")
            await handle_unified_new_domain(query, context, plan_id)
        elif data.startswith("unified_existing_domain_"):
            plan_id = data.replace("unified_existing_domain_", "")
            await handle_unified_existing_domain(query, context, plan_id)
        elif data.startswith("unified_hosting_only_"):
            plan_id = data.replace("unified_hosting_only_", "")
            await handle_unified_hosting_only(query, context, plan_id)
        elif data.startswith("unified_checkout_new_"):
            # Format: unified_checkout_new_{plan_id}:{domain_name}
            checkout_data = data.replace("unified_checkout_new_", "")
            if ":" in checkout_data:
                plan_id, domain_name = checkout_data.split(":", 1)
                await unified_checkout(query, 'new', plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid checkout data.")
        elif data.startswith("unified_checkout_existing_"):
            # Format: unified_checkout_existing_{plan_id}:{domain_name}
            checkout_data = data.replace("unified_checkout_existing_", "")
            if ":" in checkout_data:
                plan_id, domain_name = checkout_data.split(":", 1)
                await unified_checkout(query, 'existing', plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid checkout data.")
        elif data.startswith("unified_checkout_only_"):
            plan_id = data.replace("unified_checkout_only_", "")
            await unified_checkout(query, 'only', plan_id)
        elif data.startswith("intent_wallet_"):
            # Format: intent_wallet_{intent_id}:{price}
            wallet_data = data.replace("intent_wallet_", "")
            if ":" in wallet_data:
                intent_id, price = wallet_data.split(":", 1)
                await process_intent_wallet_payment(query, intent_id, price)
            else:
                await safe_edit_message(query, t('errors.invalid_payment_data', user_lang))
        elif data.startswith("unified_wallet_"):
            # Format: unified_wallet_{subscription_id}:{price}
            wallet_data = data.replace("unified_wallet_", "")
            if ":" in wallet_data:
                subscription_id, price = wallet_data.split(":", 1)
                await process_unified_wallet_payment(query, subscription_id, price)
            else:
                await safe_edit_message(query, t('errors.invalid_payment_data', user_lang))
        elif data.startswith("unified_crypto_"):
            # Format: unified_crypto_{crypto_type}_{subscription_id}:{price}
            crypto_data = data.replace("unified_crypto_", "")
            if "_" in crypto_data and ":" in crypto_data:
                crypto_type, rest = crypto_data.split("_", 1)
                if ":" in rest:
                    subscription_id, price = rest.split(":", 1)
                    await process_unified_crypto_payment(query, crypto_type, subscription_id, price)
                else:
                    await safe_edit_message(query, "❌ Invalid crypto payment data.")
            else:
                await safe_edit_message(query, "❌ Invalid crypto payment data.")
        elif data.startswith("intent_crypto_"):
            # Format: intent_crypto_{crypto}_{intent_id}:{price}
            crypto_data = data.replace("intent_crypto_", "")
            if ":" in crypto_data:
                crypto_intent_part, price = crypto_data.split(":", 1)
                crypto_intent_parts = crypto_intent_part.split("_")
                if len(crypto_intent_parts) >= 2:
                    crypto = crypto_intent_parts[0]
                    intent_id = "_".join(crypto_intent_parts[1:])
                    await process_intent_crypto_payment(query, intent_id, crypto, price)
                else:
                    await safe_edit_message(query, t('errors.invalid_payment_data', user_lang))
            else:
                await safe_edit_message(query, t('errors.invalid_payment_format', user_lang))
        elif data.startswith("unified_checkout_review_"):
            # Format: unified_checkout_review_{subscription_id}
            subscription_id = data.replace("unified_checkout_review_", "")
            await handle_unified_checkout_review(query, subscription_id)
        elif data.startswith("notify_ready_"):
            plan_id = data.replace("notify_ready_", "")
            await handle_notify_ready(query, plan_id)
        elif data.startswith("collect_domain_"):
            plan_id = data.replace("collect_domain_", "")
            await collect_hosting_domain(query, context, plan_id)
        elif data.startswith("hosting_new_domain_"):
            plan_id = data.replace("hosting_new_domain_", "")
            await start_hosting_domain_search(query, context, plan_id)
        elif data.startswith("hosting_existing_domain_"):
            plan_id = data.replace("hosting_existing_domain_", "")
            await request_existing_domain(query, context, plan_id)
        elif data.startswith("confirm_hosting_bundle_"):
            # Handle domain + hosting bundle confirmation: confirm_hosting_bundle_{plan_id}:{domain_name}
            bundle_data = data.replace("confirm_hosting_bundle_", "")
            if ":" in bundle_data:
                plan_id, domain_name = bundle_data.split(":", 1)
                await confirm_hosting_purchase(query, plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid bundle data. Please try again.")
        elif data.startswith("confirm_hosting_existing_"):
            # Handle existing domain + hosting confirmation: confirm_hosting_existing_{plan_id}:{domain_name}
            existing_data = data.replace("confirm_hosting_existing_", "")
            if ":" in existing_data:
                plan_id, domain_name = existing_data.split(":", 1)
                await confirm_hosting_purchase(query, plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid hosting data. Please try again.")
        elif data.startswith("retry_ns_update:"):
            logger.info(f"Routing to: handle_retry_nameserver_update")
            await handle_retry_nameserver_update(query, context, data)
        elif data.startswith("recheck_ns_"):
            # Handle nameserver recheck for hosting: recheck_ns_{plan_id}:{domain_name}
            ns_data = data.replace("recheck_ns_", "")
            if ":" in ns_data:
                plan_id, domain_name = ns_data.split(":", 1)
                await recheck_hosting_nameservers(query, plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid nameserver recheck data. Please try again.")
        elif data.startswith("manage_hosting_"):
            # Handle individual hosting management: manage_hosting_{subscription_id}
            subscription_id = data.replace("manage_hosting_", "")
            await show_hosting_management(query, subscription_id)
        elif data.startswith("hosting_details_"):
            # Handle hosting account details: hosting_details_{subscription_id}
            subscription_id = data.replace("hosting_details_", "")
            await show_hosting_details(query, subscription_id)
        elif data.startswith("cpanel_login_"):
            # Handle cPanel login info: cpanel_login_{subscription_id}
            subscription_id = data.replace("cpanel_login_", "")
            await show_cpanel_login(query, subscription_id)
        elif data.startswith("hosting_usage_"):
            # Handle hosting usage stats: hosting_usage_{subscription_id}
            subscription_id = data.replace("hosting_usage_", "")
            await show_hosting_usage(query, subscription_id)
        elif data.startswith("suspend_hosting_"):
            # Handle hosting suspension: suspend_hosting_{subscription_id}
            subscription_id = data.replace("suspend_hosting_", "")
            await suspend_hosting_account(query, subscription_id)
        elif data.startswith("unsuspend_hosting_"):
            # Handle hosting unsuspension: unsuspend_hosting_{subscription_id}
            subscription_id = data.replace("unsuspend_hosting_", "")
            await unsuspend_hosting_account(query, subscription_id)
        elif data.startswith("confirm_suspend_"):
            # Handle suspension confirmation: confirm_suspend_{subscription_id}
            subscription_id = data.replace("confirm_suspend_", "")
            await confirm_hosting_suspension(query, subscription_id)
        elif data.startswith("cancel_suspend_"):
            # Handle suspension cancellation: cancel_suspend_{subscription_id}
            subscription_id = data.replace("cancel_suspend_", "")
            await show_hosting_management(query, subscription_id)
        elif data.startswith("restart_hosting_"):
            # Handle hosting service restart: restart_hosting_{subscription_id}
            subscription_id = data.replace("restart_hosting_", "")
            await restart_hosting_services(query, subscription_id)
        elif data.startswith("check_hosting_status_"):
            # Handle hosting status check: check_hosting_status_{subscription_id}
            subscription_id = data.replace("check_hosting_status_", "")
            await check_hosting_status(query, subscription_id)
        elif data.startswith("renew_suspended_"):
            # Handle manual renewal for suspended hosting: renew_suspended_{subscription_id}
            subscription_id = data.split("_", 2)[2]
            await handle_renew_suspended_hosting(query, subscription_id)
        elif data.startswith("renew_wallet_"):
            # Handle wallet payment for renewal: renew_wallet_{subscription_id}
            subscription_id = data.split("_", 2)[2]
            await process_manual_renewal_wallet(query, subscription_id)
        elif data.startswith("renew_crypto_"):
            # Handle crypto payment for renewal: renew_crypto_{subscription_id}
            subscription_id = data.split("_", 2)[2]
            await process_manual_renewal_crypto(query, subscription_id)
        elif data.startswith("insufficient_funds_"):
            # Handle insufficient funds message: insufficient_funds_{subscription_id}
            subscription_id = data.split("_", 2)[2]
            await show_insufficient_funds_message(query, subscription_id)
        elif data.startswith("manual_renew:"):
            # Handle manual renewal from /renew command: manual_renew:{subscription_id}
            subscription_id = data.split(":", 1)[1]
            await handle_manual_renewal(query, subscription_id)
        else:
            await safe_edit_message(query, "❌ Unknown action. Please try again.")
            
    except Exception as e:
        user = query.from_user
        error_msg = str(e)
        
        # Downgrade log level for benign "Message is not modified" errors (user clicking same button twice)
        if "Message is not modified" in error_msg or "exactly the same" in error_msg:
            logger.info(f"Callback ignored for user {user.id if user else 'unknown'} with data '{data}': {e}")
            # Don't show error message to user - this is normal behavior (clicking same button twice)
            return
        else:
            logger.error(f"Callback error for user {user.id if user else 'unknown'} with data '{data}': {e}")
            
        try:
            await safe_edit_message(query, "❌ An error occurred. Please try again.")
        except Exception as edit_error:
            # Don't log if it's just another "message not modified" error
            if "Message is not modified" not in str(edit_error):
                logger.error(f"Failed to send error message to user {user.id if user else 'unknown'}: {edit_error}")

async def show_language_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show language selection buttons for onboarding"""
    message = update.effective_message
    
    if not message:
        logger.error("No message object in show_language_selection")
        return False
    
    try:
        # Get supported languages
        supported_langs = get_supported_languages()
        
        # Create keyboard with language options
        keyboard = []
        for lang_code in supported_langs:
            # Use hardcoded language info for now
            lang_options = {
                'en': {'flag': '🇺🇸', 'name': 'English'},
                'fr': {'flag': '🇫🇷', 'name': 'Français'},
                'es': {'flag': '🇪🇸', 'name': 'Español'}
            }
            flag = lang_options.get(lang_code, {}).get('flag', '🌐')
            name = lang_options.get(lang_code, {}).get('name', lang_code.upper())
            keyboard.append([
                InlineKeyboardButton(f"{flag} {name}", callback_data=f"language_select_{lang_code}")
            ])
        
        # Get localized welcome message  
        platform_name = get_platform_name()
        # Use default English for initial selection screen since user hasn't chosen language yet
        selection_message = t('onboarding.language_selection', 'en', platform_name=platform_name)
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await message.reply_text(selection_message, reply_markup=reply_markup)
        return True
        
    except Exception as e:
        logger.error(f"Error showing language selection: {e}")
        return False

async def handle_language_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle language selection callback"""
    query = update.callback_query
    if not query:
        logger.error("No callback query in handle_language_selection")
        return
    user = query.from_user
    
    if not query or not user:
        logger.error("Missing query or user in handle_language_selection")
        return
    
    try:
        await query.answer()
        if not query.data:
            logger.error("Missing callback data in language selection")
            return
        # Extract language code from callback data (format: language_select_{lang_code})
        lang_code = query.data.replace("language_select_", "")
        
        # Validate language code
        if not is_language_supported(lang_code):
            await query.edit_message_text("❌ Invalid language selection. Please try again.")
            return
        
        # Set user preference (marked as manually selected)
        success = await set_user_language_preference(user.id, lang_code, manually_selected=True)
        
        if success:
            # Get localized confirmation message
            lang_names = {
                'en': 'English',
                'fr': 'Français',
                'es': 'Español'
            }
            lang_name = lang_names.get(lang_code, lang_code.upper())
            platform_name = get_platform_name()
            
            success_message = await t_for_user(
                'onboarding.language_set',
                user.id,
                language=lang_name,
                platform_name=platform_name
            )
            
            await query.edit_message_text(f"✅ {success_message}")
            
            # Continue with onboarding in selected language - always show terms acceptance
            await show_terms_acceptance(update, context)
        else:
            await query.edit_message_text("❌ Error setting language. Please try again.")
            
    except Exception as e:
        logger.error(f"Error handling language selection: {e}")
        await query.edit_message_text("❌ Error processing language selection. Please try again.")

async def handle_language_selection_callback(query, lang_code: str, context: ContextTypes.DEFAULT_TYPE):
    """Handle language selection callback from menu"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    if not user:
        logger.error("Missing user in language selection callback")
        return
    
    try:
        # Validate language code
        if not is_language_supported(lang_code):
            await safe_edit_message(
                query,
                "❌ Unsupported language. Please try again.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="language_selection")
                ]])
            )
            return
        
        # Update user language preference (marked as manually selected)
        success = await set_user_language_preference(user.id, lang_code, manually_selected=True)
        
        if success:
            lang_names = {
                'en': 'English',
                'fr': 'Français',
                'es': 'Español'
            }
            selected_language = lang_names.get(lang_code, lang_code.upper())
            
            # Use localized confirmation message in the selected language
            confirmation_text = t('onboarding.language_set', lang_code)
            
            # Show confirmation and return to main menu
            keyboard = [
                [InlineKeyboardButton(t("buttons.main_menu", user_lang), callback_data="main_menu")],
                [InlineKeyboardButton(t("buttons.change_language", user_lang), callback_data="language_selection")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await safe_edit_message(query, confirmation_text, reply_markup=reply_markup)
            logger.info(f"✅ Language updated to {lang_code} for user {user.id}")
        else:
            await safe_edit_message(
                query,
                "❌ Failed to update language. Please try again.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="language_selection")
                ]])
            )
            
    except Exception as e:
        logger.error(f"Error handling language selection callback: {e}")
        await safe_edit_message(
            query,
            "❌ Error processing language selection. Please try again.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="language_selection")
            ]])
        )

async def show_terms_or_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE, user, user_lang: str):
    """Show terms acceptance or dashboard based on user status"""
    try:
        # Get user data with terms status
        user_data = await get_or_create_user_with_status(
            telegram_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        if not user_data.get('terms_accepted'):
            await show_terms_acceptance(update, context)
        else:
            await show_dashboard(update, context, user_data)
            
    except Exception as e:
        logger.error(f"Error in show_terms_or_dashboard: {e}")
        # Fallback to terms acceptance
        await show_terms_acceptance(update, context)

async def show_personalized_dashboard(query):
    """Show personalized dashboard with user name and balance (used for back button navigation)"""
    user = query.from_user
    if not user:
        logger.error("Missing user in show_personalized_dashboard")
        return
    
    try:
        # Get user data and wallet balance
        try:
            db_user = await asyncio.wait_for(
                get_or_create_user(
                    telegram_id=user.id,
                    username=user.username,
                    first_name=user.first_name,
                    last_name=user.last_name
                ),
                timeout=10.0  # 10 second timeout to prevent hanging
            )
            wallet_balance = await asyncio.wait_for(
                get_user_wallet_balance(user.id),
                timeout=10.0  # 10 second timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Database timeout for user {user.id}, using fallback")
            # Use fallback values if database is slow/unavailable
            db_user = {'id': user.id}
            wallet_balance = 0.0
        except Exception as db_error:
            logger.warning(f"Database error for user {user.id}: {db_error}, using fallback")
            # Use fallback values if database error
            db_user = {'id': user.id}
            wallet_balance = 0.0
        
        balance_display = format_money(Decimal(str(wallet_balance)))
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Check if user is admin using unified admin check
        is_admin = is_admin_user(user.id)
        
        # Create personalized dashboard message with translations
        dashboard_message = t_fmt('dashboard.title', user_lang) + "\n\n"
        # Use t_html for safe user name display
        welcome_text, _ = t_html('dashboard.welcome_back', user_lang, name=user.first_name or 'User')
        dashboard_message += welcome_text + "\n\n"
        dashboard_message += t('dashboard.balance', user_lang, balance=balance_display) + "\n\n"
        dashboard_message += t('dashboard.what_to_do', user_lang)

        # Get minimum hosting price dynamically from database
        try:
            min_price_result = await execute_query(
                "SELECT MIN(monthly_price) as min_price FROM hosting_plans WHERE is_active = true"
            )
            min_hosting_price = int(min_price_result[0]['min_price']) if min_price_result and min_price_result[0]['min_price'] else 40
        except Exception as db_error:
            logger.warning(f"Failed to get minimum hosting price, using fallback: {db_error}")
            min_hosting_price = 40  # Fallback to current minimum (Pro 7 Days)
        
        # Get minimum RDP price dynamically from database
        try:
            min_rdp_result = await execute_query(
                "SELECT MIN(our_monthly_price) as min_price FROM rdp_plans WHERE is_active = true"
            )
            min_rdp_price = int(min_rdp_result[0]['min_price']) if min_rdp_result and min_rdp_result[0]['min_price'] else 10
        except Exception as db_error:
            logger.warning(f"Failed to get minimum RDP price, using fallback: {db_error}")
            min_rdp_price = 60  # Fallback to Starter plan markup price
        
        keyboard = [
            [InlineKeyboardButton(btn_t('search_domains', user_lang), callback_data="search_domains")],
            [InlineKeyboardButton(btn_t('my_domains', user_lang), callback_data="my_domains")],
            [InlineKeyboardButton(btn_t('wallet', user_lang), callback_data="wallet_main"), InlineKeyboardButton(btn_t('hosting_from_price', user_lang, price=str(min_hosting_price)), callback_data="unified_hosting_plans")],
            [InlineKeyboardButton(btn_t('rdp_from_price', user_lang, price=str(min_rdp_price)), callback_data="rdp_purchase_start")],
            [InlineKeyboardButton(btn_t('api_management', user_lang), callback_data="api_management_main")],
            [InlineKeyboardButton(btn_t('become_reseller', user_lang), callback_data="reseller_program")],
            [InlineKeyboardButton(btn_t('profile', user_lang), callback_data="profile_main"), InlineKeyboardButton(btn_t('change_language', user_lang), callback_data="language_selection_from_profile")],
            [InlineKeyboardButton(btn_t('contact_support', user_lang), callback_data="contact_support")]
        ]
        
        # Add admin commands for admin users
        if is_admin:
            dashboard_message += "\n\n" + t('admin.admin_panel', user_lang)
            keyboard.append([InlineKeyboardButton(btn_t('broadcast_message', user_lang), callback_data="admin_broadcast")])
            keyboard.append([InlineKeyboardButton(btn_t('credit_user_wallet', user_lang), callback_data="admin_credit_wallet")])
            keyboard.append([InlineKeyboardButton(btn_t('openprovider_accounts', user_lang), callback_data="admin_openprovider_accounts")])
            keyboard.append([InlineKeyboardButton("🔄 DNS Sync", callback_data="admin_dns_sync")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send the personalized dashboard with timeout protection
        try:
            await asyncio.wait_for(
                safe_edit_message(query, dashboard_message, reply_markup),
                timeout=15.0  # 15 second timeout for Telegram operations
            )
        except asyncio.TimeoutError:
            logger.warning(f"Telegram edit timeout for user {user.id}, trying fallback")
            # Fallback to sending new message if edit times out
            await asyncio.wait_for(
                query.bot.send_message(
                    chat_id=user.id,
                    text=dashboard_message,
                    reply_markup=reply_markup
                ),
                timeout=15.0
            )
        
        logger.info(f"✅ Personalized dashboard shown to user {user.id} with balance {balance_display}")
        
    except Exception as e:
        logger.error(f"Error showing personalized dashboard for user {user.id}: {e}")
        # Fallback to basic dashboard
        await show_main_menu(query)

async def show_main_menu(query):
    """Show the main menu with proper localization"""
    user = query.from_user
    if not user:
        logger.error("Missing user in show_main_menu")
        return
    
    try:
        # Get user's language preference
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get localized main menu message
        platform_title = await t_for_user('dashboard.complete_hosting_platform', user.id, platform_name=get_platform_name())
        quick_actions_text = await t_for_user('dashboard.quick_actions', user.id)
        
        # Fallback to branded format if translation keys don't exist
        if 'dashboard.complete_hosting_platform' in platform_title or 'dashboard.quick_actions' in quick_actions_text:
            message = """
🌐 {platform_name} - Complete Hosting Platform

Quick Actions:
"""
        else:
            message = f"{platform_title}\n\n{quick_actions_text}:"
        
        # ALWAYS format brand placeholders (whether translated or fallback)
        message = format_branded_message(message)
        
        # Localized button texts
        search_text = await t_for_user('buttons.search_domains', user.id)
        domains_text = await t_for_user('buttons.my_domains', user.id)
        hosting_text = await t_for_user('buttons.hosting', user.id)
        wallet_text = await t_for_user('buttons.wallet', user.id)
        profile_text = await t_for_user('buttons.profile', user.id)
        reseller_text = await t_for_user('buttons.become_reseller', user.id)
        
        # Fallback button texts if translations missing
        if 'buttons.' in search_text: search_text = "🌐 Register Domain - ❌ DMCA"
        if 'buttons.' in domains_text: domains_text = "🌐 My Domains"
        if 'buttons.' in hosting_text: hosting_text = "🏠 Web Hosting"
        if 'buttons.' in wallet_text: wallet_text = "💰 Wallet"
        if 'buttons.' in profile_text: profile_text = "👤 Profile"
        if 'buttons.' in reseller_text: reseller_text = "🤝 Become a Reseller"
        
        keyboard = [
            [InlineKeyboardButton(search_text, callback_data="search_domains")],
            [InlineKeyboardButton(domains_text, callback_data="my_domains")],
            [InlineKeyboardButton(hosting_text, callback_data="hosting_main")],
            [InlineKeyboardButton(await t_for_user('buttons.windows_rdp', user.id), callback_data="rdp_main")],
            [InlineKeyboardButton(wallet_text, callback_data="wallet_main")],
            [InlineKeyboardButton(profile_text, callback_data="profile_main"), InlineKeyboardButton(await t_for_user('buttons.change_language', user.id), callback_data="language_selection_from_profile")],
            [InlineKeyboardButton(reseller_text, callback_data="reseller_program")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        logger.info(f"✅ Main menu shown to user {user.id} in language: {user_lang}")
        
    except Exception as e:
        logger.error(f"Error localizing main menu for user {user.id}: {e}")
        # Get user_lang for fallback
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        # Fallback to original hardcoded version
        message = format_branded_message("""
🌐 {platform_name} - Complete Hosting Platform

Quick Actions:
""")
        keyboard = [
            [InlineKeyboardButton(btn_t("search_domains", user_lang), callback_data="search_domains")],
            [InlineKeyboardButton(btn_t("my_domains", user_lang), callback_data="my_domains")],
            [InlineKeyboardButton(t("buttons.web_hosting", user_lang), callback_data="hosting_main")],
            [InlineKeyboardButton(btn_t("rdp_main", user_lang), callback_data="rdp_main")],
            [InlineKeyboardButton(btn_t("wallet", user_lang), callback_data="wallet_main")],
            [InlineKeyboardButton(t("buttons.profile", user_lang), callback_data="profile_main"), InlineKeyboardButton(btn_t("change_language", user_lang), callback_data="language_selection_from_profile")],
            [InlineKeyboardButton(t("buttons.become_reseller", user_lang), callback_data="reseller_program")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_reseller_info(query):
    """Show reseller program information"""
    user = query.from_user
    if not user:
        logger.error("Missing user in show_reseller_info")
        return
    
    try:
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        reseller_message = await t_for_user('reseller.message', user.id)
        contact_button_text = await t_for_user('buttons.contact_support', user.id)
        back_button_text = await t_for_user('buttons.back', user.id)
        
        if 'reseller.message' in reseller_message:
            reseller_message = """🤝 <b>Reseller Program</b>

Grow your business by partnering with {platform_name}!

💼 <b>Benefits:</b>
• Competitive commission rates
• White-label solutions
• Dedicated support
• Bulk pricing discounts

📞 Interested? Contact our team to learn more:
{support_contact}

We'll help you get started!"""
        
        # ALWAYS format brand placeholders (whether translated or fallback)
        reseller_message = format_branded_message(reseller_message)
        
        if 'buttons.' in contact_button_text: contact_button_text = "💬 Contact Support"
        if 'buttons.' in back_button_text: back_button_text = "⬅️ Back"
        
        keyboard = [
            [InlineKeyboardButton(contact_button_text, url=f"https://t.me/{get_support_contact().lstrip('@')}")],
            [InlineKeyboardButton(back_button_text, callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, reseller_message, reply_markup=reply_markup)
        logger.info(f"✅ Reseller info shown to user {user.id} in language: {user_lang}")
        
    except Exception as e:
        logger.error(f"Error showing reseller info for user {user.id}: {e}")
        # Get user_lang for fallback
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        fallback_message = format_branded_message("""🤝 <b>Reseller Program</b>

Grow your business by partnering with {platform_name}!

💼 <b>Benefits:</b>
• Competitive commission rates
• White-label solutions
• Dedicated support
• Bulk pricing discounts

📞 Interested? Contact our team to learn more:
{support_contact}

We'll help you get started!""")
        keyboard = [
            [InlineKeyboardButton(t("buttons.contact_support", user_lang), url=f"https://t.me/{get_support_contact().lstrip('@')}")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)

async def show_search_interface(query):
    """Show domain search interface"""
    user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
    
    message = f"""
{t('domain.search.title', user_lang)}

{t('domain.search.prompt_line1', user_lang)}

{t('domain.search.prompt_line2', user_lang)}
"""
    keyboard = [
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_user_domains(query):
    """Show user's domains - placeholder"""
    user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
    message = f"""
{t('domain.list.title', user_lang)}

{t('domain.list.loading', user_lang)}
"""
    await safe_edit_message(query, message)

async def show_user_domains_complete(query, context=None):
    """Show complete domains management interface"""
    # Clear admin states when navigating to domains
    from admin_handlers import clear_admin_states
    if context:
        clear_admin_states(context)
    
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        domains = await get_user_domains(user_record['id'])
        
        if not domains:
            message = f"{t('dashboard.domains_list_title', user_lang)}\n\n{t('dashboard.no_domains_message', user_lang)}"
            keyboard = [
                [InlineKeyboardButton(t("buttons.search_domains", user_lang), callback_data="search_domains")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
            ]
        else:
            message = f"{t('dashboard.domains_list_title', user_lang)}\n\n{t('dashboard.domain_count', user_lang, count=len(domains))}\n\n"
            keyboard = []
            for domain in domains:
                domain_name = domain['domain_name']
                status = domain['status']
                restriction = domain.get('registrar_restriction')
                
                # Determine emoji and status based on restriction
                if restriction:
                    # Domain has registrar restriction (abuse lock, verification, etc.)
                    emoji = "🔒"
                    status_text = t('common_labels.restricted', user_lang, fallback='Restricted')
                elif status == 'active':
                    emoji = "✅"
                    status_text = t(f'common_labels.{status}', user_lang) if status else status.title()
                else:
                    emoji = "⏳"
                    status_text = t(f'common_labels.{status}', user_lang) if status else status.title()
                
                message += f"{emoji} {domain_name} ({status_text})\n"
                keyboard.append([InlineKeyboardButton(f"🌐 {domain_name}", callback_data=f"dns_{domain_name}")])
            
            keyboard.extend([
                [InlineKeyboardButton(btn_t("register_new_domain", user_lang), callback_data="search_domains")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing domains interface: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load domains.")

async def show_wallet_interface(query, context=None):
    """Show wallet interface with real balance"""
    # Clear admin states when navigating to wallet
    from admin_handlers import clear_admin_states  
    if context:
        clear_admin_states(context)
    
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        balance = await get_user_wallet_balance(user.id)
        
        # Get recent transactions
        transactions = await get_user_wallet_transactions(user_record['id'], 5)
        
        # Format transaction history
        transaction_history = ""
        if transactions:
            for tx in transactions[:3]:  # Only show 3 recent
                amount = float(tx['amount'])
                date = tx['created_at'].strftime('%m/%d')
                emoji = "➕" if amount > 0 else "➖"
                tx_type = tx['transaction_type'] or 'transaction'
                
                # Extract simple type from verbose descriptions
                if 'domain' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.domain', user_lang)
                elif 'deposit' in tx_type.lower() or 'crypto' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.deposit', user_lang)
                elif 'credit' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.credit', user_lang)
                elif 'refund' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.refund', user_lang)
                elif 'debit' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.debit', user_lang)
                else:
                    # Fallback to generic transaction label
                    simple_type = t('wallet.transaction_type.transaction', user_lang)
                
                transaction_history += f"{emoji} {format_money(abs(Decimal(str(amount))), 'USD', include_currency=True)} - {simple_type} ({date})\n"
        else:
            transaction_history = f"\n{t('wallet.no_transactions', user_lang)}"
        
        # Get brand config for dynamic support contact
        config = BrandConfig()
        
        message = f"""
{t('wallet.title', user_lang)}

{t('wallet.balance_label', user_lang)} {format_money(balance, 'USD', include_currency=True)}
{transaction_history}

{t('wallet.help_message', user_lang, support_contact=config.support_contact)}"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.add_funds", user_lang), callback_data="wallet_deposit")],
            [InlineKeyboardButton(t("buttons.transaction_history", user_lang), callback_data="wallet_history")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing wallet interface: {e}")
        user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
        await safe_edit_message(query, t('errors.wallet_load_failed', user_lang))

async def show_profile_interface(query):
    """Show profile interface"""
    user = query.from_user
    config = BrandConfig()
    
    # Get user language for localization
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Get localized text
    language_settings_text = await t_for_user('profile.language_settings', user.id)
    back_text = await t_for_user('navigation.back', user.id)
    
    # Build full name
    full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
    
    # Get translated strings
    profile_title = t('profile.simple_title', user_lang)
    username_display = user.username or t('profile.not_set', user_lang)
    user_info = t('profile.user_info_line', user_lang, username=username_display, id=user.id)
    features = t('profile.features_line', user_lang)
    help_line = t('profile.help_line', user_lang, support_contact=config.support_contact)
    
    message = f"""{profile_title}

{full_name}
{user_info}

{features}

{help_line}"""
    
    keyboard = [
        [InlineKeyboardButton(f"🌍 {language_settings_text}", callback_data="language_selection_from_profile")],
        [InlineKeyboardButton(f"⬅️ {back_text}", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_contact_support(query):
    """Show contact support information"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    platform_name = get_platform_name()
    
    # Use the new HTML-formatted message template
    message = create_contact_support_message(platform_name, query.from_user.id)
    
    # Get dynamic support contact from BrandConfig
    config = BrandConfig()
    support_url = f"https://t.me/{config.support_contact.lstrip('@')}"
    
    keyboard = [
        [InlineKeyboardButton(btn_t("message_support", user_lang, support_contact=config.support_contact), url=support_url)],
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def show_language_selection_from_profile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show language selection buttons from profile interface"""
    message = update.effective_message
    
    if not message:
        logger.error("No message object in show_language_selection_from_profile")
        return False
    
    try:
        user = update.effective_user
        if not user:
            logger.error("No user in show_language_selection_from_profile")
            return False
            
        # Get current user language for displaying proper title
        current_lang = await get_user_language_preference(user.id)
        
        # Get supported languages
        supported_langs = get_supported_languages()
        
        # Create keyboard with language options (profile specific callback data)
        keyboard = []
        for lang_code in supported_langs:
            # Use hardcoded language info for now
            lang_options = {
                'en': {'flag': '🇺🇸', 'name': 'English'},
                'fr': {'flag': '🇫🇷', 'name': 'Français'},
                'es': {'flag': '🇪🇸', 'name': 'Español'}
            }
            flag = lang_options.get(lang_code, {}).get('flag', '🌐')
            name = lang_options.get(lang_code, {}).get('name', lang_code.upper())
            
            # Add current language indicator
            if lang_code == current_lang:
                button_text = f"{flag} {name} ✓"
            else:
                button_text = f"{flag} {name}"
                
            keyboard.append([
                InlineKeyboardButton(button_text, callback_data=f"language_select_from_profile_{lang_code}")
            ])
        
        # Add back button
        back_text = await t_for_user('navigation.back', user.id)
        keyboard.append([
            InlineKeyboardButton(f"⬅️ {back_text}", callback_data="profile_main")
        ])
        
        # Get localized title
        title = await t_for_user('profile.language_selection_title', user.id)
        platform_name = get_platform_name()
        
        message_text = f"🌍 {title}\n\n{platform_name}"
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if hasattr(message, 'edit_text'):
            await message.edit_text(message_text, reply_markup=reply_markup)
        else:
            query = update.callback_query
            if query:
                await query.edit_message_text(message_text, reply_markup=reply_markup)
        
        return True
        
    except Exception as e:
        logger.error(f"Error showing language selection from profile: {e}")
        return False

async def handle_language_selection_from_profile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle language selection from profile - no terms re-acceptance needed"""
    query = update.callback_query
    if not query:
        logger.error("No callback query in handle_language_selection_from_profile")
        return
    user = query.from_user
    
    if not query or not user:
        logger.error("Missing query or user in handle_language_selection_from_profile")
        return
    
    try:
        await query.answer()
        if not query.data:
            logger.error("Missing callback data in language selection from profile")
            return
        # Extract language code from callback data (format: language_select_from_profile_{lang_code})
        lang_code = query.data.replace("language_select_from_profile_", "")
        
        # Validate language code
        if not is_language_supported(lang_code):
            await query.edit_message_text("❌ Invalid language selection. Please try again.")
            return
        
        # Set user preference (marked as manually selected)
        success = await set_user_language_preference(user.id, lang_code, manually_selected=True)
        
        if success:
            # Get localized confirmation message
            lang_names = {
                'en': 'English',
                'fr': 'Français',
                'es': 'Español'
            }
            lang_name = lang_names.get(lang_code, lang_code.upper())
            
            success_message = await t_for_user(
                'profile.language_changed',
                user.id,
                language=lang_name
            )
            
            # Show brief confirmation then return to profile
            await query.edit_message_text(f"✅ {success_message}")
            
            # Auto-return to profile after 1.5 seconds
            import asyncio
            await asyncio.sleep(1.5)
            await show_profile_interface(query)
        else:
            await query.edit_message_text("❌ Error setting language. Please try again.")
            
    except Exception as e:
        logger.error(f"Error handling language selection from profile: {e}")
        await query.edit_message_text("❌ Error processing language selection. Please try again.")

# UNIFIED HOSTING FLOW - Single Entry Point System
# ================================================================

async def smart_domain_handler(query, context, plan_id: str, domain_text: Optional[str] = None):
    """
    Intelligent domain scenario detection and handling
    Automatically determines: registration, existing domain, or transfer needed
    """
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get plan information
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        plan_price = plan.get('period_price', plan.get('monthly_price', 0))
        
        if domain_text:
            # Domain provided - analyze it
            domain_name = domain_text.lower().strip()
            
            # Basic domain validation
            if not is_valid_domain(domain_name):
                await safe_edit_message(query, 
                    f"❌ Invalid domain format: {domain_name}\n\n"
                    "Please enter a valid domain name (e.g., mywebsite.com)")
                return
            
            # Check if domain is already registered
            user_record = await get_or_create_user(query.from_user.id)
            domain_status = await analyze_domain_status(domain_name, user_record['id'])
            
            # CRITICAL: Use bulletproof hosting context enforcement guard
            if enforce_hosting_context(domain_status, domain_name, "smart domain handler"):
                # MANDATORY: Route to hosting handlers using centralized enforcement
                if domain_status['exists']:
                    log_routing_enforcement(domain_name, "smart_domain_handler", True, "routing to existing domain hosting bundle")
                    await handle_existing_domain_hosting(query, context, plan_id, domain_name, domain_status)
                else:
                    log_routing_enforcement(domain_name, "smart_domain_handler", True, "routing to new domain hosting bundle")
                    await handle_new_domain_hosting(query, context, plan_id, domain_name, plan)
                return  # CRITICAL: Exit to prevent non-hosting routing
            
            # Non-hosting context - proceed with regular routing (should not happen in hosting flows)
            if domain_status['exists']:
                logger.info(f"🔄 Domain {domain_name} exists - regular domain flow (NOT hosting bundle)")
                await handle_existing_domain_hosting(query, context, plan_id, domain_name, domain_status)
            else:
                logger.info(f"🆕 Domain {domain_name} available - regular domain flow (NOT hosting bundle)")
                await handle_new_domain_hosting(query, context, plan_id, domain_name, plan)
                
        else:
            # No domain provided - show smart domain options
            await show_smart_domain_options(query, context, plan_id, plan)
            
    except Exception as e:
        logger.error(f"Error in smart domain handler: {e}")
        await safe_edit_message(query, "❌ Error processing domain. Please try again.")

def _get_estimated_domain_price(tld: str) -> float:
    """
    Get estimated domain pricing when OpenProvider API doesn't return pricing
    """
    # Common TLD pricing estimates (in USD, wholesale rates)
    tld_estimates = {
        'com': 11.99,
        'net': 13.99,
        'org': 12.99,
        'info': 12.99,
        'biz': 13.99,
        'co': 29.99,
        'io': 49.99,
        'ai': 79.99,
        'dev': 12.99,
        'app': 17.99,
        'tech': 39.99,
        'online': 2.99,
        'site': 2.99,
        'website': 2.99,
        'store': 39.99,
        'blog': 29.99,
        'news': 25.99,
        'cloud': 19.99,
        'me': 19.99,
        'tv': 29.99,
        'cc': 29.99,
        'ws': 29.99,
        'sbs': 2.99,
        'xyz': 1.99,
        'top': 1.99,
        'click': 1.99,
        'link': 9.99,
        'pro': 15.99,
        'mobi': 19.99
    }
    
    # Return estimated price or default for unknown TLDs
    return tld_estimates.get(tld.lower(), 15.99)  # Default to $15.99 for unknown TLDs

async def analyze_domain_status(domain_name: str, user_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Comprehensive domain analysis with 3-table state management system
    Checks: ownership_state in domains table, active intents, OpenProvider availability
    ENHANCED: Now checks for hosting bundle context to ensure proper routing
    Logs all searches to domain_searches table without affecting ownership state
    """
    try:
        logger.info(f"🔍 Analyzing domain: {domain_name} for user {user_id or 'unknown'}")
        
        # CRITICAL: Check for hosting bundle context first to prevent misrouting
        hosting_bundle_context = False
        if user_id:
            db_user = await get_or_create_user_with_status(user_id)
            if db_user:
                hosting_intent = await get_active_hosting_intent(db_user['id'], domain_name)
                if hosting_intent:
                    service_type = hosting_intent.get('service_type', '')
                    hosting_bundle_context = is_hosting_bundle_service_type(service_type)
                    if hosting_bundle_context:
                        logger.info(f"🏠 HOSTING BUNDLE CONTEXT: Domain {domain_name} analysis in hosting context (service_type: {service_type})")
        
        # Check ownership state (NOT just existence in domains table)
        ownership_state = await check_domain_ownership_state(domain_name)
        
        # Check for active registration intents for this user
        active_intent = None
        if user_id:
            active_intent = await get_active_registration_intent(user_id, domain_name)
        
        if ownership_state in ['internal_owned', 'external_verified']:
            # Domain is owned - check DNS configuration
            existing_domain = await get_domain_by_name(domain_name)
            cf_zone = await get_cloudflare_zone(domain_name)
            nameservers = await get_domain_nameservers(domain_name)
            
            search_result = {
                'exists': True,
                'in_our_system': True,
                'ownership_state': ownership_state,
                'has_cloudflare': bool(cf_zone),
                'nameservers': nameservers,
                'status': 'managed_domain',
                'auto_dns_possible': bool(cf_zone),
                'dns_status': 'managed',
                'can_auto_configure': True,
                'active_intent': active_intent,
                'hosting_bundle_context': hosting_bundle_context  # CRITICAL: Context for routing decisions
            }
            
            # Log search to domain_searches table (don't affect ownership)
            if user_id:
                await log_domain_search(user_id, domain_name, search_result)
            
            return search_result
        else:
            # No ownership state - check OpenProvider for availability and log search
            logger.info(f"🔍 Checking domain availability: {domain_name}")
            
            # Check domain availability via OpenProvider
            openprovider = OpenProviderService()
            check_result = await openprovider.check_domain_availability(domain_name)
            
            if check_result and check_result.get('available', True):
                # Domain available for registration
                # Get price from provider's price_info structure
                price_info = check_result.get('price_info', {})
                provider_price = price_info.get('create_price')
                
                if provider_price is not None and provider_price > 0:
                    # Use provider pricing (already marked up)
                    registration_price = provider_price
                    base_price = price_info.get('base_price_usd', provider_price)
                    logger.info(f"✅ Domain pricing from provider: ${base_price:.2f} → ${registration_price:.2f}")
                else:
                    # Fallback: Use estimated pricing based on TLD
                    tld = domain_name.split('.')[-1] if '.' in domain_name else 'com'
                    estimated_price = _get_estimated_domain_price(tld)
                    registration_price = calculate_marked_up_price(Decimal(str(estimated_price)), 'USD', tld=tld)['final_price']
                    logger.warning(f"⚠️ No pricing from provider for {domain_name}, using estimated ${estimated_price:.2f} → ${registration_price:.2f}")
                
                search_result = {
                    'exists': False,
                    'in_our_system': False,
                    'ownership_state': None,
                    'has_cloudflare': False,
                    'nameservers': None,
                    'status': 'available',
                    'auto_dns_possible': True,  # Will be after registration
                    'registration_price': registration_price,
                    'dns_status': 'not_registered',
                    'can_auto_configure': True,
                    'active_intent': active_intent,
                    'available': True,
                    'hosting_bundle_context': hosting_bundle_context  # CRITICAL: Context for routing decisions
                }
                
                # Log search to domain_searches table (ephemeral, does NOT affect ownership)
                if user_id:
                    await log_domain_search(user_id, domain_name, search_result)
                
                return search_result
            else:
                # Domain exists externally - check real nameservers and DNS status
                logger.info(f"🌐 Domain {domain_name} exists externally, checking DNS configuration...")
                
                # Get real nameservers for external domain
                actual_nameservers = await _get_real_nameservers(domain_name)
                
                # Check if domain is using Cloudflare nameservers
                is_using_cloudflare = _check_cloudflare_nameservers(actual_nameservers)
                
                # Try to find Cloudflare zone if using CF nameservers
                cf_zone = None
                if is_using_cloudflare:
                    try:
                        cf_service = CloudflareService()
                        zone = await cf_service.get_zone_by_name(domain_name)
                        if zone:
                            cf_zone = zone
                    except Exception as e:
                        logger.debug(f"Cloudflare zone check failed: {e}")
                
                # Determine auto-configuration possibility
                auto_dns_possible = is_using_cloudflare and bool(cf_zone)
                
                search_result = {
                    'exists': True,
                    'in_our_system': False,
                    'ownership_state': None,
                    'has_cloudflare': bool(cf_zone),
                    'nameservers': actual_nameservers,
                    'status': 'external_domain',
                    'auto_dns_possible': auto_dns_possible,
                    'dns_status': 'cloudflare_managed' if is_using_cloudflare else 'external_dns',
                    'can_auto_configure': auto_dns_possible,
                    'using_cloudflare_ns': is_using_cloudflare,
                    'registration_price': None,  # External domain - no registration needed
                    'active_intent': active_intent,
                    'available': False,
                    'hosting_bundle_context': hosting_bundle_context  # CRITICAL: Context for routing decisions
                }
                
                # Log search to domain_searches table (ephemeral, does NOT affect ownership)
                if user_id:
                    await log_domain_search(user_id, domain_name, search_result)
                
                return search_result
                    
    except Exception as e:
        logger.error(f"Error analyzing domain status for {domain_name}: {e}")
        
        # CRITICAL: Preserve hosting bundle context even in exception case
        hosting_bundle_context = False
        if user_id:
            try:
                # Re-query hosting intent to preserve context
                db_user = await get_or_create_user_with_status(user_id)
                if db_user:
                    hosting_intent = await get_active_hosting_intent(db_user['id'], domain_name)
                    if hosting_intent:
                        service_type = hosting_intent.get('service_type', '')
                        hosting_bundle_context = is_hosting_bundle_service_type(service_type)
                        logger.info(f"🏠 EXCEPTION RECOVERY: Preserved hosting bundle context for {domain_name} (service_type: {service_type})")
            except Exception as context_error:
                logger.error(f"Failed to preserve hosting context in exception handler: {context_error}")
                hosting_bundle_context = False  # Safe fallback
        
        # Return safe fallback status with preserved hosting context
        fallback_result = {
            'exists': True,  # Assume exists to be safe
            'in_our_system': False,
            'ownership_state': None,
            'has_cloudflare': False,
            'nameservers': None,
            'status': 'unknown_external',
            'auto_dns_possible': False,
            'dns_status': 'unknown',
            'can_auto_configure': False,
            'active_intent': None,
            'available': False,
            'hosting_bundle_context': hosting_bundle_context  # CRITICAL: Preserved context
        }
        
        # Log error case to domain_searches table for debugging
        if user_id:
            try:
                await log_domain_search(user_id, domain_name, {**fallback_result, 'error': str(e)})
            except Exception as log_error:
                logger.error(f"Failed to log error search for {domain_name}: {log_error}")
        
        return fallback_result

async def _get_real_nameservers(domain_name: str) -> List[str]:
    """Get actual nameservers for a domain using DNS resolution"""
    try:
        # Try multiple methods to get nameservers
        nameservers = []
        
        # Method 1: Use DNS resolver service
        try:
            from services.dns_resolver import dns_resolver
            ns_list = await dns_resolver.get_nameservers(domain_name)
            if ns_list:
                nameservers.extend(ns_list)
        except Exception as e:
            logger.debug(f"DNS resolver service failed: {e}")
        
        # Method 2: Try direct DNS query if dnspython is available
        if not nameservers:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain_name, 'NS')
                nameservers = [str(answer).rstrip('.') for answer in answers]
            except ImportError:
                logger.debug("dnspython not available for NS lookup")
            except Exception as e:
                logger.debug(f"DNS resolver failed: {e}")
        
        # Clean and validate nameservers
        clean_ns = []
        for ns in nameservers:
            ns_clean = ns.lower().strip().rstrip('.')
            if ns_clean and is_valid_nameserver(ns_clean):
                clean_ns.append(ns_clean)
        
        # Remove duplicates while preserving order
        unique_ns = []
        for ns in clean_ns:
            if ns not in unique_ns:
                unique_ns.append(ns)
        
        logger.info(f"🔍 Found nameservers for {domain_name}: {unique_ns}")
        return unique_ns
        
    except Exception as e:
        logger.warning(f"Failed to get nameservers for {domain_name}: {e}")
        return []

def _check_cloudflare_nameservers(nameservers: List[str]) -> bool:
    """Check if nameservers are Cloudflare nameservers"""
    if not nameservers:
        return False
    
    # Common Cloudflare nameserver patterns
    cf_patterns = [
        'ns.cloudflare.com',
        '.ns.cloudflare.com',
        'cloudflare.com'
    ]
    
    cf_count = 0
    for ns in nameservers:
        ns_lower = ns.lower().strip()
        for pattern in cf_patterns:
            if pattern in ns_lower:
                cf_count += 1
                break
    
    # Consider it Cloudflare if majority of nameservers match
    is_cloudflare = cf_count >= len(nameservers) / 2
    
    if is_cloudflare:
        logger.info(f"✅ Domain uses Cloudflare nameservers: {nameservers}")
    else:
        logger.info(f"ℹ️ Domain uses external nameservers: {nameservers}")
    
    return is_cloudflare

async def show_smart_domain_options(query, context, plan_id: str, plan: Dict):
    """Show intelligent domain options based on user's needs"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    plan_name = plan.get('plan_name', 'Unknown')
    plan_price = plan.get('period_price', plan.get('monthly_price', 0))
    display_price = plan.get('display_price', f"${plan_price}")
    
    # Translate plan name
    translated_plan_name = t(f"hosting.plan_name_{plan_name.lower().replace(' ', '_')}", user_lang, fallback=plan_name)
    
    message = f"""🏠 <b>{translated_plan_name} {t("common_labels.hosting", user_lang)}</b>

<b>{t("hosting.plan_label", user_lang)}</b> {display_price} • {plan.get('disk_space_gb', 0)}{t("common_labels.gb", user_lang)} • {plan.get('databases', 0)} {t("common_labels.databases_short", user_lang)}

<b>{t("hosting.domain_label", user_lang)}</b>
"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.register_new", user_lang), callback_data=f"unified_new_domain_{plan_id}")],
        [InlineKeyboardButton(t("buttons.use_existing", user_lang), callback_data=f"unified_existing_domain_{plan_id}")],
        [InlineKeyboardButton(t("buttons.hosting_only", user_lang), callback_data=f"unified_hosting_only_{plan_id}")],
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="unified_hosting_plans")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def handle_new_domain_hosting(query, context, plan_id: str, domain_name: str, plan: Dict):
    """Handle new domain registration + hosting bundle"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    plan_name = plan.get('plan_name', 'Unknown')
    plan_price = plan.get('period_price', plan.get('monthly_price', 0))
    
    # Get domain pricing
    user_record = await get_or_create_user(query.from_user.id)
    domain_status = await analyze_domain_status(domain_name, user_record['id'])
    
    # CRITICAL: Check hosting bundle context first to prevent misrouting
    if domain_status.get('hosting_bundle_context', False):
        logger.info(f"🏠 HOSTING CONTEXT: Domain {domain_name} processing in hosting bundle context - staying in hosting flow")
    
    # Check if domain is already managed in our system
    if domain_status.get('in_our_system', False):
        # Domain already exists in system
        if domain_status.get('hosting_bundle_context', False):
            # In hosting bundle context - continue with existing domain hosting flow
            logger.info(f"🏠 Domain {domain_name} already managed - continuing in hosting bundle context")
            await handle_existing_domain_hosting(query, context, plan_id, domain_name, domain_status)
            return
        else:
            # Not in hosting context - show regular ownership message
            logger.info(f"🔄 Domain {domain_name} already managed - showing ownership message")
            message_text, parse_mode = t_html('search.domain_already_owned', await resolve_user_language(query.from_user.id), domain=domain_name)
            await safe_edit_message(query, message_text, parse_mode=parse_mode)
            return
    
    domain_price = domain_status.get('registration_price')
    if domain_price is None:
        # Check if domain is already registered vs pricing error
        domain_status_type = domain_status.get('status', 'unknown')
        if domain_status_type == 'external_domain':
            message_text, parse_mode = t_html('search.domain_unavailable_registered', await resolve_user_language(query.from_user.id), domain=domain_name)
            await safe_edit_message(query, message_text, parse_mode=parse_mode)
        else:
            message_text, parse_mode = t_html('search.domain_pricing_unavailable', await resolve_user_language(query.from_user.id), domain=domain_name)
            await safe_edit_message(query, message_text, parse_mode=parse_mode)
        return
    total_price = plan_price + domain_price
    
    message = f"""
🆕 <b>{domain_name} + {plan_name}</b>

💰 <b>Total: ${total_price:.2f}</b>
• Domain: ${domain_price:.2f}
• Hosting: ${plan_price:.2f}

✅ Auto-setup included
"""
    
    keyboard = [
        [InlineKeyboardButton(btn_t("purchase_bundle", user_lang, price=f"{total_price:.2f}"), callback_data=f"unified_checkout_new_{plan_id}:{domain_name}")],
        [InlineKeyboardButton(btn_t("try_different_domain", user_lang), callback_data=f"unified_new_domain_{plan_id}")],
        [InlineKeyboardButton(t("buttons.back_to_options", user_lang), callback_data=f"unified_plan_{plan_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def handle_existing_domain_hosting(query, context, plan_id: str, domain_name: str, domain_status: Dict):
    """Handle existing domain + hosting with smart DNS detection"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # CRITICAL: Enforce hosting bundle context first - MANDATORY ROUTING ENFORCEMENT
    if domain_status.get('hosting_bundle_context', False):
        logger.info(f"🏠 HOSTING CONTEXT ENFORCED: Domain {domain_name} existing domain handler MUST stay in hosting bundle context")
    else:
        # Log warning if called without hosting context (should not happen in properly routed flows)
        logger.warning(f"⚠️ ROUTING ANOMALY: handle_existing_domain_hosting called for {domain_name} without hosting bundle context")
    
    plans = cpanel.get_hosting_plans()
    plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
    
    if not plan:
        await safe_edit_message(query, "❌ Hosting plan not found.")
        return
    
    plan_name = plan.get('plan_name', 'Unknown')
    plan_price = plan.get('period_price', plan.get('monthly_price', 0))
    
    # Smart DNS configuration based on domain status
    if domain_status['in_our_system'] and domain_status['auto_dns_possible']:
        # Domain managed by us - automatic setup
        dns_setup = "🤖 <b>Automatic DNS Setup</b>\nYour domain is managed by us - DNS will be configured automatically!"
        action_text = btn_t("configure_hosting", user_lang)
    elif domain_status['auto_dns_possible']:
        # Can potentially set up DNS automatically
        dns_setup = "⚡ <b>Smart DNS Setup</b>\nWe'll attempt automatic DNS configuration for your domain."
        action_text = btn_t("setup_hosting", user_lang)
    else:
        # Manual DNS configuration required (compact mobile-friendly)
        dns_setup = """📋 <b>DNS Update Needed</b>
<i>Nameservers provided after purchase</i>"""
        action_text = btn_t("get_hosting", user_lang)
    
    # Translate plan name
    translated_plan_name = t(f"hosting.plan_name_{plan_name.lower().replace(' ', '_')}", user_lang, fallback=plan_name)
    message = f"""🔗 <b>{domain_name} + {translated_plan_name}</b>

<b>{t("common_labels.plan", user_lang)}</b> ${plan_price:.2f} • {plan.get('disk_space_gb', 0)}{t("common_labels.gb", user_lang)}
<b>{t("common_labels.domain", user_lang)}</b> ✅ {t("domain.already_registered", user_lang)}

{dns_setup}
"""
    
    keyboard = [
        [InlineKeyboardButton(f"🛒 {action_text} (${plan_price:.2f})", callback_data=f"unified_checkout_existing_{plan_id}:{domain_name}")],
        [InlineKeyboardButton(t("buttons.try_different_domain", user_lang), callback_data=f"unified_existing_domain_{plan_id}")],
        [InlineKeyboardButton(t("buttons.back_to_options", user_lang), callback_data=f"unified_plan_{plan_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def unified_hosting_flow(query):
    """Main entry point for unified hosting flow"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get user hosting subscriptions for context
        from database import get_or_create_user, get_user_hosting_subscriptions
        db_user = await get_or_create_user(telegram_id=user.id)
        subscriptions = await get_user_hosting_subscriptions(db_user['id'])
        
        # Show unified hosting interface
        plans = cpanel.get_hosting_plans()
        
        if subscriptions:
            hosting_summary = f" • <b>{len(subscriptions)} Active</b>"
        else:
            hosting_summary = ""
        
        message = f"""🏠 <b>{t("hosting.offshore_title", user_lang)}{hosting_summary}</b>

<b>{t("hosting.plans_label", user_lang)}</b>
"""
        
        keyboard = []
        
        # Add plan options
        for plan in plans:
            plan_name = plan.get('plan_name', 'Unknown')
            display_price = plan.get('display_price', f"${plan.get('period_price', 0)}")
            disk = plan.get('disk_space_gb', 0)
            databases = plan.get('databases', 0)
            
            # Translate plan name
            translated_plan_name = t(f"hosting.plan_name_{plan_name.lower().replace(' ', '_')}", user_lang, fallback=plan_name)
            message += f"\n<b>{translated_plan_name}</b> - {display_price} • {disk}{t('common_labels.gb', user_lang)} • {databases} {t('common_labels.databases_short', user_lang)} • ∞ {t('common_labels.domains', user_lang)}\n"
            
            keyboard.append([InlineKeyboardButton(
                f"🚀 {t('buttons.get_hosting_with_plan', user_lang, plan=translated_plan_name)}", 
                callback_data=f"unified_plan_{plan.get('id', '')}"
            )])
        
        # Add management options if user has hosting
        if subscriptions:
            keyboard.append([InlineKeyboardButton(t("buttons.manage_my_hosting", user_lang), callback_data="my_hosting")])
        
        keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in unified hosting flow: {e}")
        await safe_edit_message(query, "❌ Error loading hosting options. Please try again.")

# UNIFIED CHECKOUT SYSTEM
# ================================================================

async def unified_checkout(query, checkout_type: str, plan_id: str, domain_name: Optional[str] = None):
    """Unified checkout for hosting ± domain with dynamic pricing"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # 🎯 INSTANT FEEDBACK: Show immediate processing message
    processing_msg = "🔄 <b>Processing your order...</b>\n\n"
    if checkout_type == 'new' and domain_name:
        processing_msg += f"📋 Preparing bundle: {domain_name} + hosting\n"
    else:
        processing_msg += "📋 Preparing hosting checkout...\n"
    processing_msg += "⏳ Please wait a moment..."
    
    await safe_edit_message(query, processing_msg, parse_mode='HTML')
    
    try:
        # Get plan information
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        plan_price = plan.get('period_price', plan.get('monthly_price', 0))
        
        # Calculate total based on checkout type
        if checkout_type == 'new' and domain_name:
            # 🎯 PROGRESS UPDATE: Show domain checking status
            checking_msg = f"🔄 <b>Checking domain availability...</b>\n\n"
            checking_msg += f"🌐 Analyzing: <code>{domain_name}</code>\n"
            checking_msg += f"📋 Plan: {plan_name}\n"
            checking_msg += "⏳ This may take a few seconds..."
            
            await safe_edit_message(query, checking_msg, parse_mode='HTML')
            
            # New domain + hosting bundle
            from database import get_or_create_user
            user_record = await get_or_create_user(query.from_user.id)
            domain_status = await analyze_domain_status(domain_name, user_record['id'])
            
            # CRITICAL: Ensure we stay in hosting bundle context
            if domain_status.get('hosting_bundle_context', False):
                logger.info(f"🏠 HOSTING CONTEXT: Domain {domain_name} checkout in hosting bundle context")
            
            # Check if domain is already managed in our system
            if domain_status.get('in_our_system', False):
                # Domain already exists in system - stay in hosting context
                logger.info(f"🏠 Domain {domain_name} already managed - continuing hosting bundle flow")
                await safe_edit_message(query, f"✅ {domain_name} is already in your account! Connecting to hosting...")
                # Continue as existing domain connection in hosting context
                total_price = plan_price
                items = [
                    f"Connect domain: {domain_name}",
                    f"{plan_name} hosting"
                ]
                service_type = 'hosting_with_existing_domain'
            else:
                # Domain available for registration
                domain_price = domain_status.get('registration_price')
                if domain_price is None:
                    # Check if domain is already registered vs pricing error
                    domain_status_type = domain_status.get('status', 'unknown')
                    if domain_status_type == 'external_domain':
                        await safe_edit_message(query, "❌ Domain {} already registered. Try a different name.".format(domain_name))
                    else:
                        await safe_edit_message(query, "❌ Domain Pricing Unavailable\n\nUnable to get pricing for {}. Please try a different domain or contact support.".format(domain_name))
                    return
                total_price = plan_price + domain_price
                items = [
                    f"Domain registration: {domain_name}",
                    f"{plan_name} hosting"
                ]
                service_type = 'hosting_domain_bundle'
        elif checkout_type == 'existing' and domain_name:
            # Existing domain + hosting
            total_price = plan_price
            items = [
                f"Connect domain: {domain_name}",
                f"{plan_name} hosting"
            ]
            service_type = 'hosting_with_existing_domain'
        else:
            # Hosting only
            total_price = plan_price
            items = [f"{plan_name} hosting"]
            service_type = 'hosting_only'
        
        # Create hosting provision intent to prevent duplicates
        db_user = await get_or_create_user_with_status(telegram_id=user.id)
        
        # Ensure domain_name is provided for unified flow
        if not domain_name:
            domain_name = f"temp_{user.id}_{int(time.time())}"
        
        # Check for existing active hosting intent
        existing_intent = await get_active_hosting_intent(db_user['id'], domain_name)
        if existing_intent:
            # Use existing intent
            intent_id = existing_intent['id']
            logger.info(f"⚠️ Using existing hosting intent {intent_id} for {domain_name}")
        else:
            # Create new hosting provision intent
            intent_id = await create_hosting_intent(
                user_id=db_user['id'],
                domain_name=domain_name,
                hosting_plan_id=int(plan_id),
                estimated_price=total_price,  # FIX: Store total bundle price, not just hosting
                service_type=service_type  # CRITICAL: Pass service type for bundle detection
            )
        
        if not intent_id:
            await safe_edit_message(query, "❌ Error creating hosting order. Please try again.")
            return
        
        # Show payment options for hosting intent (ensure domain_name is not None)
        safe_domain_name = domain_name or f"temp_{user.id}_{int(time.time())}"
        await show_unified_payment_options_with_intent(
            query, 
            intent_id, 
            total_price, 
            plan_name, 
            safe_domain_name,
            items,
            service_type
        )
        
    except Exception as e:
        logger.error(f"Error in unified checkout: {e}")
        await safe_edit_message(query, "❌ Error processing checkout. Please try again.")

async def show_unified_payment_options(query, subscription_id: int, price: float, plan_name: str, domain_name: str, items: List[str], service_type: str):
    """Show unified payment options for hosting ± domain"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    items_text = "\n".join([f"• {item}" for item in items])
    
    # Get user's wallet balance for validation
    try:
        user_balance = await get_user_wallet_balance(query.from_user.id)
        has_sufficient_balance = user_balance >= price
        # Show order price on button, not user balance
        price_display = format_money(Decimal(str(price)), include_currency=False)
        wallet_text = f"💰 Pay with Wallet ({price_display})"
        if not has_sufficient_balance:
            wallet_text += " ⚠️"
    except Exception as e:
        logger.warning(f"Could not retrieve wallet balance: {e}")
        price_display = format_money(Decimal(str(price)), include_currency=False)
        wallet_text = f"💰 Pay with Wallet ({price_display})"
        has_sufficient_balance = False
        user_balance = 0.0  # Set fallback for display
    
    # Format wallet balance for display
    balance_display = format_money(Decimal(str(user_balance)), 'USD', include_currency=True)
    
    message = f"""
💳 <b>Order Checkout</b>

{items_text}

💰 <b>Total: ${price:.2f}</b>
💳 <b>{t('wallet.your_wallet_balance', user_lang)}</b> {balance_display}

Choose payment method:
"""
    
    keyboard = [
        [InlineKeyboardButton(wallet_text, callback_data=f"unified_wallet_{subscription_id}:{price}")],
    ]
    
    # Add cryptocurrency options using unified config
    for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
        keyboard.append([InlineKeyboardButton(
            f"{display_text}", 
            callback_data=f"unified_crypto_{callback_suffix}_{subscription_id}:{price}"
        )])
    
    keyboard.append([InlineKeyboardButton(t("buttons.back_to_plans", user_lang), callback_data="unified_hosting_plans")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def show_unified_payment_options_with_intent(query, intent_id: int, price: float, plan_name: str, domain_name: str, items: List[str], service_type: str):
    """
    Show unified payment options for hosting intent (before subscription creation)
    FIXED: Implements missing function that handlers were calling
    """
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    items_text = "\n".join([f"• {item}" for item in items])
    
    # Get user's wallet balance for validation
    try:
        user_balance = await get_user_wallet_balance(query.from_user.id)
        has_sufficient_balance = user_balance >= price
        # Show order price on button, not user balance
        price_display = format_money(Decimal(str(price)), include_currency=False)
        wallet_text = f"💰 Pay with Wallet ({price_display})"
        if not has_sufficient_balance:
            wallet_text += " ⚠️"
    except Exception as e:
        logger.warning(f"Could not retrieve wallet balance: {e}")
        price_display = format_money(Decimal(str(price)), include_currency=False)
        wallet_text = f"💰 Pay with Wallet ({price_display})"
        has_sufficient_balance = False
        user_balance = 0.0  # Set fallback for display
    
    # Format wallet balance for display
    balance_display = format_money(Decimal(str(user_balance)), 'USD', include_currency=True)
    
    message = f"""
💳 <b>Order Checkout</b>

{items_text}

💰 <b>Total: ${price:.2f}</b>
💳 <b>{t('wallet.your_wallet_balance', user_lang)}</b> {balance_display}

Choose payment method:
"""
    
    keyboard = [
        [InlineKeyboardButton(wallet_text, callback_data=f"intent_wallet_{intent_id}:{price}")],
    ]
    
    # Add cryptocurrency options using unified config  
    for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
        keyboard.append([InlineKeyboardButton(
            f"{display_text}", 
            callback_data=f"intent_crypto_{callback_suffix}_{intent_id}:{price}"
        )])
    
    keyboard.append([InlineKeyboardButton(t("buttons.back_to_plans", user_lang), callback_data="unified_hosting_plans")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

# UNIFIED HOSTING CALLBACK HANDLERS
# ================================================================

async def handle_unified_plan_selection(query, context, plan_id: str):
    """Handle plan selection in unified flow"""
    # ⚡ INSTANT FEEDBACK: Show immediate response
    await safe_edit_message(query, "⏳ Loading plan options...")
    
    plans = cpanel.get_hosting_plans()
    plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
    
    if not plan:
        await safe_edit_message(query, "❌ Hosting plan not found.")
        return
    
    await show_smart_domain_options(query, context, plan_id, plan)

async def handle_unified_new_domain(query, context, plan_id: str):
    """Handle new domain registration flow"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, "⏳ Loading domain options...")
        
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        display_price = plan.get('display_price', f"${plan.get('period_price', 0)}")
        
        message = f"""
🆕 <b>{plan_name} + Domain Bundle ({display_price})</b>

Enter domain name to register:
<i>Example: mywebsite.com</i>
"""
        
        # Set context for text input handling
        context.user_data['unified_flow'] = 'awaiting_new_domain'
        context.user_data['unified_plan_id'] = plan_id
        context.user_data['plan_name'] = plan_name
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.back_to_options", user_lang), callback_data=f"unified_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        logger.info(f"User {query.from_user.id} starting unified new domain search for plan {plan_id}")
        
    except Exception as e:
        logger.error(f"Error handling unified new domain: {e}")
        await safe_edit_message(query, "❌ Error processing domain search. Please try again.")

async def handle_unified_existing_domain(query, context, plan_id: str):
    """Handle existing domain connection flow"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, "⏳ Loading domain options...")
        
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        display_price = plan.get('display_price', f"${plan.get('period_price', 0)}")
        
        # Translate plan name
        translated_plan_name = t(f"hosting.plan_name_{plan_name.lower().replace(' ', '_')}", user_lang, fallback=plan_name)
        message = f"""
🔗 <b>{translated_plan_name} {t("common_labels.hosting", user_lang)}</b>

<b>{t("common_labels.plan", user_lang)}</b> {display_price}

<b>🌐 Enter your domain:</b>
<i>Example: myexistingsite.com</i>
"""
        
        # Set context for text input handling
        context.user_data['unified_flow'] = 'awaiting_existing_domain'
        context.user_data['unified_plan_id'] = plan_id
        context.user_data['plan_name'] = plan_name
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.back_to_options", user_lang), callback_data=f"unified_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        logger.info(f"User {query.from_user.id} starting unified existing domain flow for plan {plan_id}")
        
    except Exception as e:
        logger.error(f"Error handling unified existing domain: {e}")
        await safe_edit_message(query, t('errors.existing_domain_processing_failed', user_lang))

async def handle_unified_hosting_only(query, context, plan_id: str):
    """Handle hosting-only (no domain) flow"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        plan_price = plan.get('period_price', plan.get('monthly_price', 0))
        display_price = plan.get('display_price', f"${plan_price}")
        
        # Translate plan name
        translated_plan_name = t(f"hosting.plan_name_{plan_name.lower().replace(' ', '_')}", user_lang, fallback=plan_name)
        
        message = f"""
<b>🏠 {translated_plan_name}</b>

📦 <b>{plan.get('disk_space_gb', 0)}{t("common_labels.gb", user_lang)} • {plan.get('databases', 0)} {t("common_labels.databases_short", user_lang)} • ∞ {t("common_labels.domains", user_lang)}</b>

💰 <b>${plan_price:.2f}/{plan.get('billing_cycle', '7days')}</b>
"""
        
        keyboard = [
            [InlineKeyboardButton(btn_t("get_hosting_with_price", user_lang, price=f"{plan_price:.2f}"), callback_data=f"unified_checkout_only_{plan_id}")],
            [InlineKeyboardButton(t("buttons.back_to_options", user_lang), callback_data=f"unified_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error handling unified hosting only: {e}")
        await safe_edit_message(query, "❌ Error processing hosting-only option. Please try again.")

async def process_unified_wallet_payment(query, subscription_id: str, price: str):
    """Process wallet payment for unified hosting order with financial safety checks"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Convert price to float
        amount = float(price)
        
        # CRITICAL: Financial safety validation before any operations
        from database import (
            get_or_create_user, get_user_wallet_balance, debit_wallet_balance,
            verify_financial_operation_safety
        )
        
        # Verify financial operation safety
        safety_check = verify_financial_operation_safety(
            f"Unified hosting wallet payment (User: {user.id}, Amount: ${amount:.2f})", 
            amount
        )
        if not safety_check:
            logger.error(f"🚫 Financial safety check failed for user {user.id} payment ${amount:.2f}")
            await safe_edit_message(query, "❌ Payment system temporarily unavailable. Please try again later.")
            return
        
        logger.info(f"✅ Financial safety check passed for unified wallet payment: User {user.id}, ${amount:.2f}")
        
        # Get user wallet balance (use telegram_id, not internal user_id)
        db_user = await get_or_create_user(telegram_id=user.id)
        balance = await get_user_wallet_balance(user.id)
        
        if balance < amount:
            message = f"""
❌ <b>Insufficient Balance</b>

<b>Required:</b> ${amount:.2f}
<b>Your balance:</b> ${balance:.2f}
<b>Shortage:</b> ${Decimal(str(amount)) - balance:.2f}

Please add funds to your wallet first.
"""
            keyboard = [
                [InlineKeyboardButton(btn_t("add_funds", user_lang), callback_data="wallet_main")],
                [InlineKeyboardButton(t("buttons.back_to_payment", user_lang), callback_data=f"unified_checkout_review_{subscription_id}")]
            ]
        else:
            # 🔒 REVENUE PROTECTION: Reserve wallet balance instead of immediate debit
            logger.info(f"💳 Processing unified hosting payment: User {user.id}, Amount ${amount:.2f}, Subscription #{subscription_id}")
            
            from database import reserve_wallet_balance, finalize_wallet_reservation
            
            # Reserve wallet balance first 
            hold_id = await reserve_wallet_balance(
                db_user['id'], 
                Decimal(str(amount)), 
                f"Unified hosting hold #{subscription_id}"
            )
            
            if not hold_id:
                message = f"""
❌ <b>Payment Hold Failed</b>

There was an error reserving funds from your wallet. Please try again or contact support.

<b>Order ID:</b> #{subscription_id}
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"unified_wallet_{subscription_id}:{price}")],
                    [InlineKeyboardButton(t("buttons.contact_support", user_lang), callback_data="contact_support")]
                ]
            else:
                # Try hosting account creation with hold protection
                hosting_success = False
                hosting_error = None
                
                try:
                    # Create hosting account with hold protection
                    await create_unified_hosting_account_after_payment(int(subscription_id))
                    hosting_success = True
                    logger.info(f"✅ Unified hosting account created successfully for subscription {subscription_id}")
                    
                except Exception as hosting_exc:
                    hosting_success = False
                    hosting_error = str(hosting_exc)
                    logger.error(f"❌ Unified hosting account creation failed for subscription {subscription_id}: {hosting_error}")
                
                # 🔒 CRITICAL: Finalize wallet payment based on hosting outcome
                finalization_success = await finalize_wallet_reservation(hold_id, success=hosting_success)
                
                if hosting_success and finalization_success:
                    # Success path - both hosting and payment worked
                    logger.info(f"✅ REVENUE PROTECTION: Unified hosting subscription {subscription_id} completed with successful wallet charge")
                    
                    message = f"""
{t('hosting.wallet_payment.success_title', user_lang)}

<b>{t('hosting.wallet_payment.amount_charged', user_lang)}</b> ${amount:.2f}
<b>{t('hosting.wallet_payment.payment_method', user_lang)}</b> {t('wallet.balance', user_lang)}
<b>{t('hosting.wallet_payment.order_id', user_lang)}</b> #{subscription_id}

{t('hosting.wallet_payment.account_creating', user_lang)}
"""
                    keyboard = [
                        [InlineKeyboardButton(t("buttons.view_my_hosting", user_lang), callback_data="my_hosting")],
                        [InlineKeyboardButton(t("buttons.main_menu_mobile", user_lang), callback_data="main_menu")]
                    ]
                    
                elif hosting_success and not finalization_success:
                    # CRITICAL: Hosting created but wallet charge failed
                    logger.error(f"🚨 REVENUE PROTECTION: Unified hosting created but wallet settlement failed for subscription {subscription_id}")
                    
                    # TODO: Send critical alert to admins when alert system is implemented
                    logger.error(f"ADMIN ALERT: UnifiedHostingWalletSettlementFailure - subscription {subscription_id} needs manual intervention")
                    logger.error(f"Settlement failure context: subscription_id={subscription_id}, user_id={db_user['id']}, telegram_id={user.id}")
                    
                    message = f"""
{t('hosting.wallet_payment.settlement_issue_title', user_lang)}

{t('hosting.wallet_payment.settlement_issue_message', user_lang)}

<b>{t('hosting.wallet_payment.amount_charged', user_lang)}</b> ${amount:.2f}
<b>{t('hosting.wallet_payment.order_id', user_lang)}</b> #{subscription_id}
"""
                    keyboard = [
                        [InlineKeyboardButton(t("buttons.contact_support", user_lang), callback_data="contact_support")],
                        [InlineKeyboardButton(t("buttons.wallet", user_lang), callback_data="wallet_main")]
                    ]
                    
                else:
                    # Hosting creation failed - wallet hold refunded
                    logger.info(f"💰 REVENUE PROTECTION: Unified hosting creation failed, wallet refunded for subscription {subscription_id}")
                    
                    message = f"""
{t('hosting.wallet_payment.creation_failed_title', user_lang)}

{t('hosting.wallet_payment.creation_failed_message', user_lang)}

<b>{t('hosting.wallet_payment.amount_refunded', user_lang)}</b> ${amount:.2f}
<b>{t('hosting.wallet_payment.error_label', user_lang)}</b> {hosting_error or t('errors.try_again', user_lang)}
<b>{t('hosting.wallet_payment.order_id', user_lang)}</b> #{subscription_id}
"""
                    keyboard = [
                        [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"unified_wallet_{subscription_id}:{price}")],
                        [InlineKeyboardButton(t("buttons.contact_support", user_lang), callback_data="contact_support")]
                    ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error processing unified wallet payment: {e}")
        await safe_edit_message(query, "❌ Error processing payment. Please try again.")

async def process_intent_crypto_payment(query, intent_id: str, crypto: str, price: str):
    """Process cryptocurrency payment for hosting provision intent - FIXED to create hosting_orders"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        from database import get_hosting_intent_by_id, get_or_create_user, create_hosting_order_crypto
        from services.payment_provider import PaymentProviderFactory
        
        db_user = await get_or_create_user(telegram_id=user.id)
        user_id = db_user['id']
        
        intent = await get_hosting_intent_by_id(int(intent_id))
        if not intent:
            await safe_edit_message(query, "❌ Hosting order not found or expired.")
            return
        
        if intent['user_id'] != user_id:
            logger.error(f"🚫 Security: User {user_id} tried to pay for intent {intent_id} belonging to user {intent['user_id']}")
            await safe_edit_message(query, "❌ Invalid order access.")
            return
        
        if not crypto_config.is_supported(crypto):
            await safe_edit_message(query, f"❌ Unsupported cryptocurrency: {crypto}")
            return
        
        amount = float(intent.get('quote_price', price))
        if amount <= 0:
            logger.error(f"🚫 Security: Invalid intent price for {intent_id}: {amount}")
            await safe_edit_message(query, "❌ Invalid order pricing. Please try again.")
            return
        
        domain_name = intent.get('domain_name', '')
        hosting_plan_id = intent.get('hosting_plan_id', 1)
        
        progress_msg = f"₿ <b>Setting up {crypto.upper()} Payment...</b>\n\n"
        progress_msg += f"🏠 Domain: <code>{domain_name}</code>\n"
        progress_msg += f"💰 Amount: ${amount:.2f}\n"
        progress_msg += f"🔄 Connecting to payment provider...\n"
        progress_msg += "⏳ This may take a few seconds..."
        await safe_edit_message(query, progress_msg, parse_mode='HTML')
        
        original_amount = Decimal(str(amount))
        # Skip $2 padding for USDT (stablecoin, no volatility)
        is_stablecoin = crypto.lower() in ('usdt', 'usdt_trc20', 'usdt_erc20')
        gateway_amount = original_amount if is_stablecoin else original_amount + Decimal('2')
        
        order_id = f"hosting_{intent_id}_{user.id}_{int(time.time())}"
        
        # FIXED: Use centralized factory method which creates payment intent and passes intent_id
        payment_result = await PaymentProviderFactory.create_payment_address_with_fallback(
            currency=crypto.lower(),
            order_id=order_id,
            value=gateway_amount,
            user_id=user_id,
            base_amount=original_amount
        )
        
        if not payment_result:
            await safe_edit_message(query, "❌ Payment Error\n\nCould not generate payment address. Please try again.")
            return
        
        hosting_order_id = await create_hosting_order_crypto(
            user_id=user_id,
            hosting_plan_id=hosting_plan_id,
            domain_name=domain_name,
            expected_amount=Decimal(str(amount)),
            currency='USD',
            blockbee_order_id=order_id,
            intent_id=int(intent_id),
            subscription_id=None,
            payment_address=payment_result['address'],
            status='pending_payment'
        )
        
        if not hosting_order_id:
            await safe_edit_message(query, "❌ Error creating order. Please try again.")
            return
        
        logger.info(f"✅ Created hosting_orders entry {hosting_order_id} for intent {intent_id} with expected_amount=${amount:.2f}")
        
        crypto_amount_display = payment_result.get('crypto_amount', 'TBD')
        payment_message, copy_keyboard = render_crypto_payment(
            address=payment_result['address'],
            crypto_name=f"{crypto.upper()}",
            usd_amount=float(amount),
            crypto_amount=crypto_amount_display if crypto_amount_display != 'TBD' else None,
            order_id=str(hosting_order_id),
            expires_minutes=15
        )
        
        payment_message += f"\n📦 <b>Hosting Order</b>: {escape_html(domain_name)}\n\n{t('payment.bundle_auto_provision_message', user_lang)}"
        
        additional_buttons = [
            [InlineKeyboardButton(t("buttons.cancel_order", user_lang), callback_data="unified_hosting_plans")],
            [InlineKeyboardButton(t("buttons.back_to_hosting", user_lang), callback_data="my_hosting")]
        ]
        
        combined_keyboard = list(copy_keyboard.inline_keyboard) + additional_buttons
        final_keyboard = InlineKeyboardMarkup(combined_keyboard)
        
        await safe_edit_message(query, payment_message, reply_markup=final_keyboard, parse_mode='HTML')
        
        logger.info(f"🏠 Hosting crypto payment generated: {crypto.upper()} for intent {intent_id}, order {hosting_order_id}")
        
    except Exception as e:
        logger.error(f"Error processing intent crypto payment: {e}")
        await safe_edit_message(query, "❌ Error processing payment. Please try again.")

async def process_intent_wallet_payment(query, intent_id: str, price: str):
    """Process wallet payment for hosting provision intent"""
    user = query.from_user
    
    # 🎯 INSTANT FEEDBACK: Show immediate payment processing message
    processing_msg = f"💳 <b>Wallet Payment</b> • ${price}\n📋 Order #{intent_id}\n⏳ Verifying balance..."
    
    await safe_edit_message(query, processing_msg, parse_mode='HTML')
    
    try:
        # Convert IDs
        intent_id_int = int(intent_id)
        
        # CRITICAL: Get server-side authoritative data FIRST
        from database import (
            get_or_create_user, get_user_wallet_balance, debit_wallet_balance,
            verify_financial_operation_safety, get_hosting_intent_by_id,
            finalize_hosting_provisioning, credit_user_wallet
        )
        
        # Get user 
        db_user = await get_or_create_user(telegram_id=user.id)
        user_id = db_user['id']
        
        # Get hosting provision intent with security checks
        intent = await get_hosting_intent_by_id(intent_id_int)
        if not intent:
            await safe_edit_message(query, "❌ Hosting order not found or expired.")
            return
        
        # Verify intent belongs to user
        if intent['user_id'] != user_id:
            logger.error(f"🚫 Security: User {user_id} tried to pay for intent {intent_id} belonging to user {intent['user_id']}")
            await safe_edit_message(query, "❌ Invalid order access.")
            return
        
        # SECURITY: Check intent status to prevent double-payments (accept legacy statuses)
        payable_statuses = {'pending_payment', 'pending', 'awaiting_payment', 'draft', 'pending_checkout'}
        current_status = intent.get('status')
        if current_status not in payable_statuses:
            logger.error(f"🚫 Security: Intent {intent_id} is not in payable state: {current_status}")
            await safe_edit_message(query, "❌ This order is no longer available for payment.")
            return
        
        # Auto-upgrade legacy status to standard pending_payment
        if current_status in {'pending', 'awaiting_payment', 'draft', 'pending_checkout'}:
            logger.info(f"🔄 Auto-upgrading intent {intent_id} status: {current_status} → pending_payment")
            await update_hosting_intent_status(intent_id_int, 'pending_payment')
        
        # SECURITY: Use ONLY server-side authoritative price - ignore client input completely
        amount = float(intent.get('quote_price', 0))
        if amount <= 0:
            logger.error(f"🚫 Security: Invalid intent price for {intent_id}: {amount}")
            await safe_edit_message(query, "❌ Invalid order pricing. Please try again.")
            return
        
        # SECURITY: Financial safety validation using authoritative amount
        safety_check = verify_financial_operation_safety(
            f"Intent wallet payment (User: {user.id}, Intent: {intent_id}, Amount: ${amount:.2f})", 
            amount
        )
        if not safety_check:
            logger.error(f"🚫 Financial safety check failed for user {user.id} intent payment ${amount:.2f}")
            await safe_edit_message(query, "❌ Payment system temporarily unavailable. Please try again later.")
            return
        
        logger.info(f"✅ Financial safety check passed for intent wallet payment: User {user.id}, ${amount:.2f}")
        
        # Check wallet balance against authoritative amount
        balance = await get_user_wallet_balance(user.id)
        if balance < amount:
            await safe_edit_message(query, f"❌ Insufficient wallet balance. You have ${balance:.2f}, but need ${amount:.2f}.")
            return
        
        # Debit wallet balance first (before routing to orchestrator)
        debit_success = await debit_wallet_balance(
            user_id, 
            Decimal(str(amount)), 
            f"Hosting + Domain Payment - Intent {intent_id}"
        )
        
        if not debit_success:
            await safe_edit_message(query, "❌ Payment processing failed. Please try again.")
            return
        
        logger.info(f"✅ Wallet payment successful: User {user.id} paid ${amount:.2f} for intent {intent_id}")
        
        # Create payment details for wallet payments to show correct amount in success message (matching registration fix)
        wallet_payment_details = {
            'amount_usd': amount,
            'currency': 'USD',
            'payment_method': 'wallet'
        }
        
        # Create a query adapter for the orchestrator (similar to webhook adapter)
        class HandlerQueryAdapter:
            def __init__(self, query):
                self.query = query
                self.user_id = user_id
                
            async def send_message_to_user(self, text, reply_markup=None, parse_mode='HTML'):
                """Send message via telegram query interface with HTML formatting"""
                await safe_edit_message(self.query, text, reply_markup)
        
        query_adapter = HandlerQueryAdapter(query)
        
        # Show immediate processing message
        processing_msg = f"🚀 <b>Processing your hosting order...</b>\n\n"
        processing_msg += f"✅ Payment processed: ${amount:.2f}\n"
        processing_msg += f"🔄 Starting provisioning workflow...\n"
        processing_msg += f"⏳ This may take 30-60 seconds..."
        await safe_edit_message(query, processing_msg, parse_mode='HTML')
        
        # Get user language for error messages
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Route through centralized orchestrator (matching registration fix pattern)
        try:
            from services.hosting_orchestrator import HostingBundleOrchestrator
            orchestrator = HostingBundleOrchestrator()
            
            # Create order_id from intent_id for orchestrator compatibility
            orchestrator_result = await orchestrator.start_hosting_bundle(
                order_id=intent_id_int,  # Use intent_id as order_id
                user_id=user_id,
                domain_name=intent.get('domain_name', ''),
                payment_details=wallet_payment_details,  # Include wallet payment details for success message
                query_adapter=query_adapter
            )
            
            # Handle orchestrator results
            if orchestrator_result.get('status') == 'already_processed':
                logger.info(f"🚫 HANDLERS: Hosting bundle already processed for intent {intent_id}")
                await safe_edit_message(query, f"ℹ️ Order Already Complete\n\nHosting order has already been processed.")
                return
            
            elif orchestrator_result.get('status') == 'duplicate_prevented':
                logger.info(f"🚫 HANDLERS: Duplicate hosting bundle prevented for intent {intent_id}")
                await safe_edit_message(query, f"ℹ️ Order In Progress\n\nHosting order is already being processed.")
                return
            
            elif orchestrator_result.get('status') == 'error':
                logger.error(f"❌ HANDLERS: Orchestrator error for intent {intent_id}: {orchestrator_result.get('error', 'Unknown error')}")
                await safe_edit_message(query, f"{t('hosting.errors.provisioning_error_title', user_lang)}\n\n{t('hosting.errors.provisioning_error_message', user_lang)}")
                return
            
            elif orchestrator_result.get('success'):
                logger.info(f"✅ HANDLERS: Hosting bundle completed via orchestrator: intent {intent_id}")
                # Orchestrator already sent success notification with buttons
            else:
                logger.warning(f"⚠️ HANDLERS: Unexpected orchestrator result for intent {intent_id}: {orchestrator_result}")
                await safe_edit_message(query, f"⚠️ Order Status Unknown\n\nPlease check your hosting dashboard.")
                
        except Exception as orchestrator_error:
            logger.error(f"❌ HANDLERS: Error during orchestrated hosting provisioning for intent {intent_id}: {orchestrator_error}")
            await safe_edit_message(query, f"{t('hosting.errors.provisioning_error_title', user_lang)}\n\n{t('hosting.errors.provisioning_error_contact', user_lang)}")
            
    except Exception as e:
        logger.error(f"Error in intent wallet payment: {e}")
        # Try to rollback intent status if possible
        try:
            # Only try to rollback if intent_id_int was successfully defined
            if 'intent_id' in locals() and intent_id:
                intent_id_int = int(intent_id)
                await update_hosting_intent_status(intent_id_int, 'pending_payment')
        except:
            pass
        await safe_edit_message(query, "❌ Payment processing error. Please try again.")

async def process_unified_crypto_payment(query, crypto_type: str, subscription_id: str, price: str):
    """Process crypto payment for unified hosting order with financial safety checks"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # 🎯 INSTANT FEEDBACK: Show immediate crypto payment processing message
    crypto_name = crypto_type.upper()
    processing_msg = f"₿ <b>Setting up {crypto_name} Payment...</b>\n\n"
    processing_msg += f"💰 Amount: ${float(price):.2f}\n"
    processing_msg += f"📋 Order: #{subscription_id}\n"
    processing_msg += f"⏳ Generating payment address..."
    
    await safe_edit_message(query, processing_msg, parse_mode='HTML')
    
    try:
        # Convert price to float
        amount = float(price)
        
        # CRITICAL: Financial safety validation before any operations
        from database import verify_financial_operation_safety
        
        # Verify financial operation safety
        safety_check = verify_financial_operation_safety(
            f"Unified hosting crypto payment (User: {user.id}, Amount: ${amount:.2f}, Type: {crypto_type})", 
            amount
        )
        if not safety_check:
            logger.error(f"🚫 Financial safety check failed for user {user.id} crypto payment ${amount:.2f} ({crypto_type})")
            await safe_edit_message(query, "❌ Payment system temporarily unavailable. Please try again later.")
            return
        
        logger.info(f"✅ Financial safety check passed for unified crypto payment: User {user.id}, ${amount:.2f} ({crypto_type})")
        
        # Get user record for database ID
        from database import get_or_create_user
        user_record = await get_or_create_user(telegram_id=user.id)
        
        # Skip $2 padding for USDT (stablecoin, no volatility)
        original_amount = Decimal(str(amount))
        is_stablecoin = crypto_type.lower() in ('usdt', 'usdt_trc20', 'usdt_erc20')
        gateway_amount = original_amount if is_stablecoin else original_amount + Decimal('2')
        
        # Generate payment address
        logger.info(f"💰 Generating {crypto_type.upper()} payment address for unified hosting: User {user.id}, Amount ${amount:.2f}, Subscription #{subscription_id}")
        payment_result = await create_payment_address(
            currency=crypto_type,
            order_id=f"UH{subscription_id}",
            value=gateway_amount,
            user_id=user_record['id']
        )
        
        if not payment_result:
            await safe_edit_message(query, "❌ Error generating payment address. Please try again.")
            return
        
        payment_address = payment_result['address']
        order_id = payment_result.get('order_id', f"UH{subscription_id}")
        
        # Create QR code for payment
        qr = QRCode(version=1, box_size=10, border=5)
        qr.add_data(payment_address)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_buffer = BytesIO()
        qr_img.save(qr_buffer, format='PNG')
        qr_buffer.seek(0)
        
        # Crypto display names
        crypto_names = {
            'btc': 'Bitcoin (BTC)',
            'usdt': 'USDT (TRC20)',
            'eth': 'Ethereum (ETH)',
            'ltc': 'Litecoin (LTC)',
            'doge': 'Dogecoin (DOGE)'
        }
        
        crypto_name = crypto_names.get(crypto_type, crypto_type.upper())
        
        # Get crypto amount from provider response
        crypto_amount_display = payment_result.get('crypto_amount', '')
        crypto_line = f"\n<b>Crypto:</b> <code>{crypto_amount_display}</code>" if crypto_amount_display else ""
        
        message = f"""
💰 <b>{crypto_name} Payment</b>

<b>Amount:</b> ${amount:.2f}{crypto_line} • <b>Order:</b> #{order_id}

<b>📱 Address:</b>
<pre>{payment_address}</pre>

Send exact amount to address above.
Payment confirms automatically.

<i>💡 Tap the address above to copy it</i>
<i>⚠️ Send only {crypto_name}!</i>
"""
        
        keyboard = [
            [InlineKeyboardButton(btn_t("change_payment", user_lang), callback_data=f"unified_checkout_review_{subscription_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send QR code with payment details
        await query.message.reply_photo(
            photo=qr_buffer,
            caption=message,
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        
        # Edit original message to show payment initiated
        await safe_edit_message(query, "💰 Crypto payment initiated. Check the QR code below ⬇️")
        
    except Exception as e:
        logger.error(f"Error processing unified crypto payment: {e}")
        await safe_edit_message(query, "❌ Error processing crypto payment. Please try again.")

async def create_unified_hosting_account_after_payment(subscription_id: int):
    """Create hosting account AND domain (if needed) after successful payment in unified flow"""
    try:
        # Get subscription details
        from database import get_hosting_subscription_details_admin, update_hosting_subscription_status
        
        subscription = await get_hosting_subscription_details_admin(subscription_id)  # Admin context
        if not subscription:
            logger.error(f"Subscription {subscription_id} not found for account creation")
            return
        
        domain_name = subscription.get('domain_name', '')
        plan_name = subscription.get('plan_name', 'Unknown')
        service_type = subscription.get('service_type', 'hosting_only')
        user_id = subscription.get('user_id')
        
        logger.info(f"🚀 Starting unified provisioning for subscription {subscription_id}: {service_type}, domain: {domain_name}")
        
        # Step 1: Handle domain registration for new domain bundles
        domain_registration_success = True
        if service_type == 'hosting_domain_bundle' and domain_name and '.' in domain_name:
            if not user_id:
                logger.error(f"❌ Missing user_id for subscription {subscription_id}, cannot register domain {domain_name}")
                await update_hosting_subscription_status(subscription_id, 'failed')
                return
                
            logger.info(f"📝 Registering new domain: {domain_name}")
            domain_registration_success = await register_unified_domain(
                domain_name=domain_name,
                user_id=user_id,
                subscription_id=subscription_id
            )
            
            if not domain_registration_success:
                logger.error(f"❌ Domain registration failed for {domain_name}, aborting provisioning")
                await update_hosting_subscription_status(subscription_id, 'failed')
                return
        
        # Step 2: Create hosting account via cPanel  
        from services.cpanel import CPanelService
        cpanel = CPanelService()
        from utils.email_config import get_admin_email_for_domain
        
        logger.info(f"🏠 Creating hosting account for domain: {domain_name}")
        account_details = await cpanel.create_hosting_account(
            domain=domain_name,
            plan=plan_name,
            email=get_admin_email_for_domain(domain_name)
        )
        
        if account_details:
            # Step 3: Save cPanel account details
            from database import create_cpanel_account
            await create_cpanel_account(
                subscription_id=subscription_id,
                username=account_details['username'],
                domain=account_details['domain'],
                server_name=account_details.get('server_name', 'hostbay-server-01'),
                ip_address=account_details.get('server_ip', account_details.get('ip_address', ''))
            )
            
            # Step 4: Configure DNS for domains to point to hosting server
            if domain_name and '.' in domain_name:
                if not user_id:
                    logger.error(f"❌ Missing user_id for subscription {subscription_id}, cannot configure DNS for domain {domain_name}")
                else:
                    logger.info(f"🌐 Configuring DNS for domain: {domain_name}")
                    await configure_unified_domain_dns(domain_name, account_details, user_id)
            
            # Step 5: Update subscription status
            from database import update_hosting_subscription_status
            await update_hosting_subscription_status(subscription_id, 'active')
            
            # Step 6: Send notification to user
            await send_unified_hosting_notification(subscription, account_details, service_type)
            
            logger.info(f"✅ Unified provisioning completed successfully for subscription {subscription_id}")
        else:
            logger.error(f"❌ Failed to create hosting account for subscription {subscription_id}")
            await update_hosting_subscription_status(subscription_id, 'failed')
            
    except Exception as e:
        logger.error(f"Error in unified provisioning for subscription {subscription_id}: {e}")
        # Update status to failed
        try:
            from database import update_hosting_subscription_status
            await update_hosting_subscription_status(subscription_id, 'failed')
        except:
            pass

async def register_unified_domain(domain_name: str, user_id: int, subscription_id: int) -> bool:
    """Register a new domain as part of unified hosting provisioning - FIXED: Create Cloudflare zone FIRST for nameservers"""
    try:
        logger.info(f"🌐 Starting domain registration: {domain_name} for user {user_id}")
        
        # Step 1: Create Cloudflare DNS zone FIRST to get nameservers
        cloudflare = CloudflareService()
        
        # Create a temporary domain entry first for zone creation
        # This is needed because cloudflare.create_zone expects a domain_id
        intent_id = await create_registration_intent(
            user_id=user_id,
            domain_name=domain_name,
            estimated_price=0.0,
            payment_data={'type': 'hosting_bundle', 'status': 'pending_zone_creation'}
        )
        
        if not intent_id:
            logger.error(f"❌ Failed to create registration intent: {domain_name}")
            return False
        
        logger.info(f"🌐 Creating Cloudflare zone first to obtain nameservers for {domain_name}")
        zone_result = await cloudflare.create_zone(domain_name, standalone=True)
        
        nameservers = None
        if zone_result and zone_result.get('success'):
            nameservers = zone_result['result'].get('name_servers', [])
            logger.info(f"✅ Cloudflare zone created with nameservers: {nameservers}")
            
            # Save Cloudflare zone to database
            from database import save_cloudflare_zone
            await save_cloudflare_zone(
                domain_name=domain_name,
                cf_zone_id=zone_result['result']['id'],
                nameservers=nameservers,
                status='active'
            )
        else:
            logger.error(f"❌ Failed to create Cloudflare zone for {domain_name}")
            # Clean up intent and return failure
            await update_intent_status(intent_id, 'failed')
            return False
        
        # Step 2: Register domain via OpenProvider WITH the Cloudflare nameservers
        # Use the account manager to get the default OpenProvider account
        from services.openprovider_manager import get_openprovider_service_for_account, get_default_account_id
        
        provider_account_id = get_default_account_id()
        openprovider = get_openprovider_service_for_account(provider_account_id)
        
        # Verify method availability
        if not hasattr(openprovider, 'register_domain'):
            logger.error(f"❌ OpenProvider service missing register_domain method")
            logger.error(f"   Instance type: {type(openprovider)}")
            logger.error(f"   Available methods: {[method for method in dir(openprovider) if not method.startswith('_')]}")
            await update_intent_status(intent_id, 'failed')
            return False
        
        logger.info(f"🌐 Registering domain {domain_name} with nameservers: {nameservers} (account: {provider_account_id})")
        
        # Get or create a valid contact handle
        contact_handle = await openprovider.get_or_create_contact_handle()
        if not contact_handle:
            logger.error(f"❌ Failed to get valid contact handle for domain registration: {domain_name}")
            return False
        
        logger.info(f"✅ Using contact handle: {contact_handle}")
        registration_result = await openprovider.register_domain(
            domain_name=domain_name,
            contact_handle=contact_handle,
            nameservers=nameservers  # Now using actual Cloudflare nameservers!
        )
        
        if not registration_result or not registration_result.get('success'):
            logger.error(f"❌ Domain registration failed via OpenProvider: {domain_name}")
            await update_intent_status(intent_id, 'failed')
            return False
        
        # Step 3: Finalize domain registration in database
        provider_domain_id = registration_result.get('domain_id')
        
        if provider_domain_id:
            # CRITICAL FIX: Call finalize_domain_registration FIRST - it sets both status='completed' AND provider_domain_id atomically
            # This prevents database constraint violation: check_completed_has_provider_id
            domain_saved = await finalize_domain_registration(
                intent_id=intent_id,
                provider_domain_id=str(provider_domain_id),
                provider_account_id=provider_account_id  # Track which account registered this domain
            )
            
            if not domain_saved:
                logger.error(f"❌ Failed to finalize domain registration: {domain_name}")
                await update_intent_status(intent_id, 'failed')
                return False
        else:
            logger.error(f"❌ No provider domain ID returned for {domain_name}")
            await update_intent_status(intent_id, 'failed')
            return False
        
        logger.info(f"✅ Domain registration completed successfully: {domain_name} with proper nameservers")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error registering unified domain {domain_name}: {e}")
        return False

async def configure_unified_domain_dns(domain_name: str, account_details: Dict, user_id: int):
    """Configure DNS for domains to point to our hosting server"""
    try:
        logger.info(f"🔧 Configuring DNS for domain: {domain_name}")
        
        # Check if domain uses Cloudflare and is accessible
        domain_status = await analyze_domain_status(domain_name, user_id)
        
        if domain_status.get('has_cloudflare') and domain_status.get('auto_dns_possible'):
            # Domain uses Cloudflare and we can manage it
            cloudflare = CloudflareService()
            cf_zone = await get_cloudflare_zone(domain_name)
            
            if cf_zone:
                zone_id = cf_zone['cf_zone_id']
                server_ip = account_details.get('server_ip')
                
                if server_ip:
                    # Get existing A records to update them instead of creating duplicates
                    existing_records = await cloudflare.list_dns_records(zone_id, record_type='A')
                    records_updated = 0
                    
                    # Process root domain '@' A record
                    root_record = None
                    www_record = None
                    
                    for record in existing_records:
                        record_name = record.get('name', '')
                        # Handle both '@' and the full domain name for root records
                        if record_name == '@' or record_name == domain_name:
                            root_record = record
                        elif record_name == f'www.{domain_name}' or record_name == 'www':
                            www_record = record
                    
                    # Update or create root domain A record
                    if root_record:
                        # Update existing root A record
                        result = await cloudflare.update_dns_record(
                            zone_id=zone_id,
                            record_id=root_record['id'],
                            record_type='A',
                            name='@',
                            content=server_ip,
                            ttl=300
                        )
                        if result.get('success'):
                            old_ip = root_record.get('content', 'unknown')
                            logger.info(f"✅ Updated root A record: {old_ip} -> {server_ip}")
                            records_updated += 1
                        else:
                            logger.warning(f"⚠️ Failed to update root A record: {result.get('errors', [])}")
                    else:
                        # Create new root A record
                        result = await cloudflare.create_dns_record(
                            zone_id=zone_id,
                            record_type='A',
                            name='@',
                            content=server_ip,
                            ttl=300
                        )
                        if result.get('success'):
                            logger.info(f"✅ Created root A record -> {server_ip}")
                            records_updated += 1
                        else:
                            logger.warning(f"⚠️ Failed to create root A record: {result.get('errors', [])}")
                    
                    # Update or create www subdomain A record  
                    if www_record:
                        # Update existing www A record
                        result = await cloudflare.update_dns_record(
                            zone_id=zone_id,
                            record_id=www_record['id'],
                            record_type='A',
                            name='www',
                            content=server_ip,
                            ttl=300
                        )
                        if result.get('success'):
                            old_ip = www_record.get('content', 'unknown')
                            logger.info(f"✅ Updated www A record: {old_ip} -> {server_ip}")
                            records_updated += 1
                        else:
                            logger.warning(f"⚠️ Failed to update www A record: {result.get('errors', [])}")
                    else:
                        # Create new www A record
                        result = await cloudflare.create_dns_record(
                            zone_id=zone_id,
                            record_type='A',
                            name='www',
                            content=server_ip,
                            ttl=300
                        )
                        if result.get('success'):
                            logger.info(f"✅ Created www A record -> {server_ip}")
                            records_updated += 1
                        else:
                            logger.warning(f"⚠️ Failed to create www A record: {result.get('errors', [])}")
                    
                    logger.info(f"✅ DNS configuration completed for {domain_name}: {records_updated} A records updated/created -> {server_ip}")
                    
                    # CRITICAL: Sync all DNS records to database for dashboard display
                    try:
                        from database import save_dns_records_to_db
                        all_records = await cloudflare.list_dns_records(zone_id)
                        if all_records:
                            await save_dns_records_to_db(domain_name, all_records)
                            logger.info(f"💾 Synced {len(all_records)} DNS records to database for {domain_name}")
                    except Exception as sync_error:
                        logger.warning(f"⚠️ DNS sync to database failed (non-blocking): {sync_error}")
                else:
                    logger.warning(f"⚠️ No server IP available for DNS configuration of {domain_name}")
            else:
                logger.warning(f"⚠️ Cloudflare zone not found for {domain_name}")
        else:
            logger.info(f"ℹ️ Domain {domain_name} requires manual DNS configuration (not using Cloudflare or not accessible)")
        
    except Exception as e:
        logger.error(f"❌ Error configuring DNS for {domain_name}: {e}")

async def send_unified_hosting_notification(subscription: Dict, account_details: Dict, service_type: str = 'hosting_only'):
    """Send hosting account notification for unified flow"""
    try:
        user_id = subscription.get('user_id')
        domain_name = subscription.get('domain_name', '')
        plan_name = subscription.get('plan_name', 'Unknown')
        
        if not user_id:
            logger.error("No user_id in subscription for notification")
            return
        
        # Get user's Telegram ID
        from database import execute_query
        user_records = await execute_query("SELECT telegram_id FROM users WHERE id = %s", (user_id,))
        
        if not user_records:
            logger.error(f"User {user_id} not found for notification")
            return
        
        telegram_id = user_records[0]['telegram_id']
        user_lang = await resolve_user_language(telegram_id, None)
        
        message = f"""🎉 <b>{t("hosting.account_ready_title", user_lang)}</b>

<b>{t("hosting.plan_label", user_lang)}</b> {plan_name}
<b>{t("hosting.domain_label", user_lang)}</b> {domain_name}
<b>{t("hosting.status_label", user_lang)}</b> ✅ Active

<b>🔐 {t("hosting.cpanel_access_label", user_lang)}</b>
<b>{t("hosting.username_label", user_lang)}</b> <code>{account_details['username']}</code>
<b>{t("hosting.password_label", user_lang)}</b> <code>{account_details['password']}</code>
<b>{t("hosting.login_url_label", user_lang)}</b> https://{domain_name}:2083

<b>🌐 {t("hosting.nameservers_label", user_lang)}</b>
{chr(10).join([f'• {ns}' for ns in account_details.get('nameservers', [])])}

<b>🚀 {t("hosting.next_steps_title", user_lang)}</b>
1. {t("hosting.next_step_update_ns", user_lang)}
2. {t("hosting.next_step_wait_dns", user_lang)}
3. {t("hosting.next_step_access_cpanel", user_lang)}

Welcome to professional hosting! 🏠"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.manage_hosting", user_lang), callback_data=f"manage_hosting_{subscription['id']}")],
            [InlineKeyboardButton(t("buttons.my_hosting", user_lang), callback_data="my_hosting")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send notification via Telegram bot
        from telegram import Bot
        bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not bot_token:
            logger.error("TELEGRAM_BOT_TOKEN not found in environment")
            return
        bot = Bot(token=bot_token)
        await bot.send_message(
            chat_id=telegram_id,
            text=message,
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        
        logger.info(f"✅ Hosting notification sent to user {telegram_id}")
        
    except Exception as e:
        logger.error(f"Error sending unified hosting notification: {e}")

# HOSTING BUNDLE CONTEXT UTILITIES
# ================================================================

async def is_hosting_bundle_context(user_id: int, domain_name: str) -> bool:
    """
    Check if the current operation is within a hosting bundle context by examining
    the database-backed hosting intent. This ensures context persistence across
    callbacks, restarts, and multi-step operations.
    
    Returns:
        True if hosting bundle context exists (domain + hosting purchase)
        False if regular domain registration should be used
    """
    try:
        # Get user from database
        db_user = await get_or_create_user_with_status(user_id)
        if not db_user:
            return False
        
        # Check for active hosting intent for this domain
        hosting_intent = await get_active_hosting_intent(db_user['id'], domain_name)
        
        if hosting_intent:
            service_type = hosting_intent.get('service_type', '')
            # Return True if this is a hosting bundle service type
            return service_type in ['hosting_with_domain_bundle', 'hosting_with_existing_domain']
        
        return False
        
    except Exception as e:
        logger.error(f"❌ Error checking hosting bundle context for {domain_name}: {e}")
        return False

# TEXT INPUT HANDLING FOR UNIFIED FLOW
# ================================================================

async def handle_unified_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_text: str):
    """Handle text input for unified hosting flow"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        return
    
    # Check if context.user_data exists
    if not hasattr(context, 'user_data') or context.user_data is None:
        return
        
    unified_flow = context.user_data.get('unified_flow')
    plan_id = context.user_data.get('unified_plan_id')
    
    if not unified_flow or not plan_id:
        return  # Not in unified flow
    
    # Define DummyQuery class at function scope for both flows to access
    class DummyQuery:
        def __init__(self, user, message):
            self.from_user = user
            self.message = message
            self.data = None
            self.id = None  # Add query id for compatibility
            self.inline_message_id = None  # Add inline message id for compatibility
            self.chat_instance = None  # Add chat instance for compatibility
        
        async def edit_message_text(self, text, reply_markup=None, parse_mode='HTML'):
            """Send new message for text input compatibility (user messages can't be edited)"""
            await self.message.reply_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
        
        async def answer(self, text=None, show_alert=False, url=None, cache_time=0):
            """Compatibility method for query.answer() calls"""
            pass  # No-op for text message context
    
    try:
        domain_name = domain_text.lower().strip()
        
        # Basic validation
        if not is_valid_domain(domain_name):
            await message.reply_text(
                f"❌ Invalid domain format: {domain_name}\n\n"
                "Please enter a valid domain name (e.g., mywebsite.com)",
                parse_mode=ParseMode.HTML
            )
            return
        
        if unified_flow == 'awaiting_new_domain':
            # Handle new domain registration with immediate feedback
            analyzing_msg = await message.reply_text(
                f"🔄 Checking {domain_name}...",
                parse_mode=ParseMode.HTML
            )
            
            plans = cpanel.get_hosting_plans()
            plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
            
            if plan:
                # Create hosting intent with bundle service type for database-backed context persistence
                db_user = await get_or_create_user_with_status(user.id) 
                
                # Check for existing hosting intent for this user and plan
                existing_intent = await get_active_hosting_intent(db_user['id'], domain_name)
                
                if not existing_intent:
                    # Create new hosting intent with bundle service type for context persistence
                    intent_id = await create_hosting_intent(
                        user_id=db_user['id'],
                        domain_name=domain_name,
                        hosting_plan_id=int(plan_id),
                        estimated_price=plan.get('period_price', 0),
                        service_type=HOSTING_SERVICE_TYPES['DOMAIN_BUNDLE']  # Database-backed context
                    )
                    logger.info(f"🏠 Created hosting bundle intent {intent_id} for {domain_name}")
                
                # Use the DummyQuery class defined at function scope
                dummy_query = DummyQuery(user, message)
                await handle_new_domain_hosting(dummy_query, context, plan_id, domain_name, plan)
                
        elif unified_flow == 'awaiting_existing_domain':
            # Handle existing domain connection with immediate feedback
            analyzing_msg = await message.reply_text(
                f"🔄 <b>Analyzing {domain_name}...</b>\n\n"
                "• Checking domain status\n"
                "• Verifying DNS records\n"
                "• Getting hosting compatibility",
                parse_mode=ParseMode.HTML
            )
            
            user_record = await get_or_create_user_with_status(user.id) 
            
            # Check for existing hosting intent for this user and domain
            existing_intent = await get_active_hosting_intent(user_record['id'], domain_name)
            
            plans = cpanel.get_hosting_plans()
            plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
            
            if not existing_intent and plan:
                # Create new hosting intent with existing domain service type for context persistence
                intent_id = await create_hosting_intent(
                    user_id=user_record['id'],
                    domain_name=domain_name,
                    hosting_plan_id=int(plan_id),
                    estimated_price=plan.get('period_price', 0),
                    service_type=HOSTING_SERVICE_TYPES['EXISTING_DOMAIN']  # Database-backed context
                )
                logger.info(f"🏠 Created existing domain hosting intent {intent_id} for {domain_name}")
            
            # CRITICAL FIX: Skip OpenProvider domain analysis for existing domain hosting
            # For existing domains, we don't need to check availability - go directly to hosting
            logger.info(f"🏠 HOSTING CONTEXT: Skipping domain availability check for existing domain: {domain_name}")
            
            # Create complete domain status for existing domain hosting (no OpenProvider call)
            domain_status = {
                'hosting_bundle_context': True,
                'service_type': 'hosting_with_existing_domain',
                'domain_name': domain_name,
                'existing_domain': True,
                'skip_domain_registration': True,
                # Required fields for handle_existing_domain_hosting function
                'exists': True,
                'in_our_system': False,  # Assume external existing domain
                'ownership_state': None,
                'has_cloudflare': False,  # Will be detected later if needed
                'nameservers': None,
                'status': 'external_domain',
                'auto_dns_possible': False  # Default to manual setup for existing domains
            }
            
            # Use the DummyQuery class defined at function scope
            dummy_query = DummyQuery(user, message)
            await handle_existing_domain_hosting(dummy_query, context, plan_id, domain_name, domain_status)
        
        # Clear flow state (with safety check)
        if hasattr(context, 'user_data') and context.user_data is not None:
            context.user_data.pop('unified_flow', None)
            context.user_data.pop('unified_plan_id', None)
        
        logger.info(f"Unified flow text input processed: {domain_name} for plan {plan_id}")
        
    except Exception as e:
        logger.error(f"Error handling unified text input: {e}")
        user_lang = await resolve_user_language(user.id, user.language_code) if user else 'en'
        await message.reply_text(f"❌ {t('errors.domain_processing_error', user_lang)}")

# BACKWARDS COMPATIBILITY LAYER
# ================================================================

# Hosting interface functions
async def show_hosting_interface(query, context=None):
    """Show hosting interface - UNIFIED VERSION"""
    # Clear admin states when navigating to hosting
    from admin_handlers import clear_admin_states
    if context:
        clear_admin_states(context)
    
    # Redirect to new unified flow
    await unified_hosting_flow(query)

async def show_hosting_plans(query):
    """Show all available hosting plans"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    plans = cpanel.get_hosting_plans()
    
    message = "🏠 Plans\n\nChoose:\n\n"
    keyboard = []
    
    for plan in plans:
        period_price = plan.get('period_price', plan.get('monthly_price', 0))
        display_price = plan.get('display_price', f"{period_price}/month")
        disk = plan.get('disk_space_gb', 0)
        plan_name = plan.get('plan_name', '')
        
        # Add plan summary to message
        message += f"{plan_name} - ${display_price}\n"
        message += f"📊 {disk}GB Storage • {plan.get('databases', 0)} Databases\n\n"
        
        # Add plan selection button
        keyboard.append([InlineKeyboardButton(
            f"📋 {plan_name} Plan - ${display_price}", 
            callback_data=f"select_plan_{plan.get('id', '')}"
        )])
    
    keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data="hosting_main")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_my_hosting(query):
    """Show user's hosting subscriptions"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Import database functions
        from database import get_or_create_user, get_user_hosting_subscriptions
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get user's hosting subscriptions
        subscriptions = await get_user_hosting_subscriptions(db_user['id'])
        
        if not subscriptions:
            message = "🏠 My Hosting\n\nNo hosting yet"
            keyboard = [
                [InlineKeyboardButton(t("buttons.plans", user_lang), callback_data="hosting_plans")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="hosting_main")]
            ]
        else:
            message = f"🏠 My Hosting ({len(subscriptions)} active)\n\n"
            keyboard = []
            
            for sub in subscriptions[:10]:
                plan_name = sub.get('plan_name', 'Unknown')
                domain = sub.get('domain_name', 'No domain')
                status = sub.get('status', 'unknown')
                
                # Add status indicator
                if status == 'active':
                    indicator = "🟢"
                elif status == 'pending':
                    indicator = "🟡"
                else:
                    indicator = "🔴"
                
                message += f"{indicator} {plan_name} - {domain}\n"
                message += f"Status: {status.title()}\n\n"
                
                keyboard.append([InlineKeyboardButton(
                    f"⚙️ Manage {domain}", 
                    callback_data=f"manage_hosting_{sub['id']}"
                )])
            
            keyboard.append([InlineKeyboardButton(t("buttons.add_new_hosting", user_lang), callback_data="hosting_plans")])
            keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data="hosting_main")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing user hosting: {e}")
        await safe_edit_message(query, "❌ Error loading hosting information. Please try again.")

async def show_plan_details(query, plan_id):
    """Show detailed information about a hosting plan"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, "⏳ Loading plan details...")
        
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        message = cpanel.format_hosting_plan(plan)
        
        keyboard = [
            [InlineKeyboardButton(f"🛒 Purchase {plan.get('plan_name', '')} Plan", callback_data=f"purchase_plan_{plan_id}")],
            [InlineKeyboardButton(t("buttons.back_to_plans", user_lang), callback_data="hosting_plans")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing plan details: {e}")
        await safe_edit_message(query, "❌ Error loading plan details. Please try again.")

async def start_hosting_purchase(query, plan_id):
    """Start the hosting plan purchase process"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, "⏳ Preparing purchase...")
        
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""
🛒 Purchase {plan_name} Plan

Plan: {plan_name}
Price: ${monthly_price}/month
Setup: Instant provisioning
Payment: Cryptocurrency

Next: Choose your domain option
"""
        
        keyboard = [
            [InlineKeyboardButton(btn_t("continue_with_plan", user_lang, plan_name=plan_name), callback_data=f"collect_domain_{plan_id}")],
            [InlineKeyboardButton(t("buttons.back_to_plan_details", user_lang), callback_data=f"select_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error starting hosting purchase: {e}")
        await safe_edit_message(query, "❌ Error processing purchase. Please try again.")

async def collect_hosting_domain(query, context, plan_id):
    """Collect domain information for hosting plan purchase"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, "⏳ Loading domain options...")
        
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""
🌐 Domain for {plan_name} Plan

Choose your domain option:

🆕 Register New Domain
• Search and register a new domain
• Automatic DNS setup
• Includes domain + hosting

🔗 Use Existing Domain  
• Connect your existing domain
• Manual DNS configuration required
• Hosting only

Plan: {plan_name} (${monthly_price}/month)
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.register_new_domain", user_lang), callback_data=f"hosting_new_domain_{plan_id}")],
            [InlineKeyboardButton(t("buttons.use_existing_domain", user_lang), callback_data=f"hosting_existing_domain_{plan_id}")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"purchase_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error collecting hosting domain: {e}")
        await safe_edit_message(query, "❌ Error processing domain selection. Please try again.")

async def start_hosting_domain_search(query, context, plan_id):
    """Start domain search for hosting package"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""
🆕 Register New Domain + {plan_name} Hosting

Search for an available domain to register with your hosting package.

Domain + Hosting Bundle:
• Domain registration 
• {plan_name} hosting plan (${monthly_price}/month)
• Automatic DNS setup
• Instant provisioning

Enter domain name to search:
"""
        
        # Store plan information in context for text input handling
        context.user_data['hosting_plan_id'] = plan_id
        context.user_data['hosting_flow'] = 'awaiting_new_domain'
        context.user_data['plan_name'] = plan_name
        context.user_data['plan_price'] = monthly_price
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.back_to_domain_options", user_lang), callback_data=f"collect_domain_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        logger.info(f"User {query.from_user.id} starting domain search for hosting plan {plan_id} - awaiting text input")
        
    except Exception as e:
        logger.error(f"Error starting hosting domain search: {e}")
        await safe_edit_message(query, "❌ Error starting domain search. Please try again.")

async def request_existing_domain(query, context, plan_id):
    """Request existing domain for hosting package"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""
🔗 Connect Existing Domain + {plan_name} Hosting

Connect your existing domain to the {plan_name} hosting plan.

What you'll need:
• Your existing domain name
• Access to domain DNS settings
• Manual nameserver update required

Hosting Plan: {plan_name} (${monthly_price}/month)

Enter your existing domain name:
"""
        
        # Store plan information in context for text input handling
        context.user_data['hosting_plan_id'] = plan_id
        context.user_data['hosting_flow'] = 'awaiting_existing_domain'
        context.user_data['plan_name'] = plan_name
        context.user_data['plan_price'] = monthly_price
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.back_to_domain_options", user_lang), callback_data=f"collect_domain_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        logger.info(f"User {query.from_user.id} requesting existing domain for hosting plan {plan_id} - awaiting text input")
        
    except Exception as e:
        logger.error(f"Error requesting existing domain: {e}")
        await safe_edit_message(query, "❌ Error processing existing domain request. Please try again.")

async def handle_hosting_domain_input(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_text: str):
    """Handle domain input for hosting plan purchase"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        return
    
    try:
        # Get hosting flow context
        user_data = context.user_data or {}
        hosting_flow = user_data.get('hosting_flow')
        plan_id = user_data.get('hosting_plan_id')
        plan_name = user_data.get('plan_name', 'Unknown')
        plan_price = user_data.get('plan_price', 0)
        
        if not plan_id or not hosting_flow:
            user_lang = await resolve_user_language(user.id, user.language_code) if user else 'en'
            await message.reply_text(f"❌ {t('errors.hosting_session_expired', user_lang)}")
            return
        
        # Validate domain format
        domain_name = domain_text.lower().strip()
        if not is_valid_domain(domain_name):
            await message.reply_text(
                f"❌ Invalid domain format: {domain_text}\n\nPlease enter a valid domain name (e.g., mywebsite.com)"
            )
            return
        
        if hosting_flow == 'awaiting_new_domain':
            # Handle new domain registration with hosting
            await handle_new_domain_with_hosting(update, context, domain_name, plan_id, plan_name, plan_price)
        elif hosting_flow == 'awaiting_existing_domain':
            # Handle existing domain with hosting
            await handle_existing_domain_with_hosting(update, context, domain_name, plan_id, plan_name, plan_price)
        
        # Clear hosting flow context safely
        if context.user_data:
            context.user_data.pop('hosting_flow', None)
            context.user_data.pop('hosting_plan_id', None)
            context.user_data.pop('plan_name', None) 
            context.user_data.pop('plan_price', None)
        
    except Exception as e:
        logger.error(f"Error handling hosting domain input: {e}")
        if message:
            user_lang = await resolve_user_language(user.id, user.language_code) if user else 'en'
            await message.reply_text(f"❌ {t('errors.domain_input_error', user_lang)}")

async def handle_new_domain_with_hosting(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_name: str, plan_id: str, plan_name: str, plan_price: float):
    """Handle new domain registration with hosting bundle"""
    user = update.effective_user
    message = update.effective_message
    
    if not user:
        logger.error("No user in handle_new_domain_with_hosting")
        return
    
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Check domain availability using existing OpenProvider integration
        from services.openprovider import OpenProviderService
        openprovider = OpenProviderService()
        
        # Show searching message
        if not message:
            logger.error("No message object available for domain search")
            return
        searching_msg = await message.reply_text(f"🔄 Checking {domain_name}...")
        
        availability = await openprovider.check_domain_availability(domain_name)
        
        if availability is None:
            await searching_msg.edit_text(t('errors.service_temporarily_down', user_lang))
            return
        
        if availability.get('available'):
            # Domain is available - show bundle pricing
            price_info = availability.get('price_info', {})
            domain_price = price_info.get('create_price', 0)
            total_price = domain_price + plan_price
            
            message_text = f"""
✅ {t('domain.status.domain_available', user_lang, domain=domain_name)}

🎉 Bundle Package:
• Domain: {domain_name} - {format_money(domain_price, 'USD', include_currency=True)}/year
• Hosting: {plan_name} - ${plan_price}/month
• Total: {format_money(total_price, 'USD', include_currency=True)} + ${plan_price}/month

⚡ Instant setup with automatic DNS configuration

Ready to proceed?
"""
            
            keyboard = [
                [InlineKeyboardButton(btn_t("purchase_bundle", user_lang, price=format_money(total_price, 'USD', include_currency=True)), callback_data=f"confirm_hosting_bundle_{plan_id}:{domain_name}")],
                [InlineKeyboardButton(t("buttons.back_to_domain_options", user_lang), callback_data=f"collect_domain_{plan_id}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await searching_msg.edit_text(message_text, reply_markup=reply_markup)
        else:
            # Domain not available
            await searching_msg.edit_text(t('hosting.domain_unavailable', user_lang, domain=domain_name))
    
    except Exception as e:
        logger.error(f"Error handling new domain with hosting: {e}")
        if message:
            await message.reply_text(t('errors.domain_availability_check_failed', user_lang))

async def handle_existing_domain_with_hosting(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_name: str, plan_id: str, plan_name: str, plan_price: float):
    """Handle existing domain with hosting plan including nameserver automation"""
    user = update.effective_user
    message = update.effective_message
    
    if not user:
        logger.error("No user in handle_existing_domain_with_hosting")
        return
    
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        checking_msg = None
        # Show checking message
        if message:
            checking_msg = await message.reply_text(t('hosting.analyzing_nameservers', user_lang, domain=domain_name))
        
        # Detect current nameserver configuration
        nameserver_analysis = await analyze_domain_nameservers(domain_name)
        
        # Generate nameserver setup guidance
        setup_guidance = await generate_hosting_nameserver_guidance(domain_name, nameserver_analysis, plan_name)
        
        message_text = t('hosting.connect_existing_domain_message', user_lang,
                        domain=domain_name,
                        plan_name=plan_name,
                        price=plan_price,
                        setup_guidance=setup_guidance)
        
        keyboard = [
            [InlineKeyboardButton(btn_t("purchase_hosting", user_lang, price=plan_price), callback_data=f"confirm_hosting_existing_{plan_id}:{domain_name}")],
            [InlineKeyboardButton(t("buttons.check_nameservers_again", user_lang), callback_data=f"recheck_ns_{plan_id}:{domain_name}")],
            [InlineKeyboardButton(t("buttons.back_to_domain_options", user_lang), callback_data=f"collect_domain_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if message and checking_msg:
            # Edit the checking message with results
            await checking_msg.edit_text(message_text, reply_markup=reply_markup)
    
    except Exception as e:
        logger.error(f"Error handling existing domain with hosting: {e}")
        if message:
            await message.reply_text(t('errors.existing_domain_processing_failed', user_lang))

async def confirm_hosting_purchase(query, plan_id, domain_name=None):
    """Handle hosting plan purchase confirmation using intent system to prevent duplicates"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get user and plan details
        db_user = await get_or_create_user(telegram_id=user.id)
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        monthly_price = plan.get('monthly_price', 0)
        
        # Use provided domain or fallback to pending
        hosting_domain = domain_name if domain_name else 'pending-domain'
        
        # Check for existing active hosting intent for this domain
        existing_intent = await get_active_hosting_intent(db_user['id'], hosting_domain)
        if existing_intent:
            logger.info(f"⚠️ Active hosting intent {existing_intent['id']} already exists for {hosting_domain}")
            
            # Check if this is the same plan
            if existing_intent['hosting_plan_id'] == plan.get('id'):
                # Show payment options for existing intent
                intent_id = existing_intent['id']
                await show_hosting_payment_options_with_intent(query, intent_id, monthly_price, plan_name, hosting_domain)
                return
            else:
                # Different plan requested - inform user
                await safe_edit_message(query, t('hosting.order_already_in_progress', user_lang, domain=hosting_domain))
                return
        
        # Create hosting provision intent to prevent duplicate accounts
        intent_id = await create_hosting_intent(
            user_id=db_user['id'],
            domain_name=hosting_domain,
            hosting_plan_id=plan.get('id'),
            estimated_price=monthly_price,
            service_type='hosting_only'  # Single hosting plan without domain bundle
        )
        
        if intent_id:
            # Show payment options for the new intent
            await show_hosting_payment_options_with_intent(query, intent_id, monthly_price, plan_name, hosting_domain)
            logger.info(f"✅ Hosting provision intent {intent_id} created: User {user.id}, Plan {plan_name}, Domain {hosting_domain}")
            return
        else:
            # Intent creation failed
            message = t('hosting.order_creation_failed', user_lang, 
                      plan_name=plan_name, 
                      price=monthly_price, 
                      domain=hosting_domain,
                      support_contact=BrandConfig().support_contact)
            keyboard = [
                [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"confirm_purchase_{plan_id}")],
                [InlineKeyboardButton(t("buttons.back_to_plans", user_lang), callback_data="hosting_plans")]
            ]
            
            logger.error(f"❌ Failed to create hosting provision intent: User {user.id}, Plan {plan_name}, Domain {hosting_domain}")
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error confirming hosting purchase: {e}")
        await safe_edit_message(query, t('errors.purchase_confirmation_failed', user_lang))

async def handle_notify_ready(query, plan_id):
    """Handle notification request when payment is ready"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        
        message = t('hosting.notification_registered', user_lang, plan_name=plan_name)
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.view_my_orders", user_lang), callback_data="my_hosting")],
            [InlineKeyboardButton(t("buttons.browse_plans", user_lang), callback_data="hosting_plans")],
            [InlineKeyboardButton(t("buttons.main_menu_mobile", user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Log notification request
        logger.info(f"📧 Notification requested: User {user.id} for plan {plan_name}")
        
    except Exception as e:
        logger.error(f"Error handling notify ready: {e}")
        await safe_edit_message(query, "❌ Error registering notification. Please try again.")

# Placeholder functions for missing handlers
async def start_domain_registration(query, domain_name):
    """Phase 2: User Profile Management & Payment Processing"""
    user = query.from_user
    
    try:
        # Get or create user in database
        user_record = await get_or_create_user(
            telegram_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        # Double-check domain availability 
        await safe_edit_message(query, f"🔄 Checking {domain_name}...")
        
        # Get user language for error messages
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        availability = await openprovider.check_domain_availability(domain_name)
        if not availability or not availability.get('available'):
            await safe_edit_message(query, t('hosting.domain_unavailable', user_lang, domain=domain_name))
            return
        
        # Get pricing
        price_info = availability.get('price_info', {})
        create_price = price_info.get('create_price', 0)
        currency = price_info.get('currency', 'USD')
        
        if create_price <= 0:
            await safe_edit_message(query, t('hosting.pricing_error', user_lang, domain=domain_name))
            return
        
        # Phase 2: Use shared contact system (no user input needed)
        # Skip individual contact collection, go straight to payment
        
        # Phase 3: Payment Processing - Show crypto options
        await show_payment_options(query, domain_name, create_price, currency)
        
    except Exception as e:
        logger.error(f"Error starting domain registration for {domain_name}: {e}")
        await safe_edit_message(query, f"❌ Error\n\nAn error occurred. Please try again.")

async def show_payment_options(query, domain_name, price, currency):
    """Phase 3: Payment Processing - Show all payment options"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        wallet_balance = await get_user_wallet_balance(user.id)
        
        # Check if user has sufficient wallet balance
        has_sufficient_balance = wallet_balance >= float(price)
        
        message = f"""
💰 Payment Required

Domain: {domain_name}
Price: ${price:.2f} {currency}
{t('wallet.your_wallet_balance', user_lang)} {format_money(wallet_balance, 'USD', include_currency=True)}

Choose your payment method:
"""
        
        keyboard = []
        
        # Wallet balance payment option (only if sufficient balance)
        if has_sufficient_balance:
            keyboard.append([InlineKeyboardButton(btn_t("pay_with_wallet", user_lang, price=f"{price:.2f}"), callback_data=f"pay_wallet_{domain_name}_{price}_{currency}")])
        else:
            keyboard.append([InlineKeyboardButton(t("buttons.insufficient_balance", user_lang), callback_data="wallet_deposit")])
        
        # Cryptocurrency payment options using unified config
        for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
            keyboard.append([InlineKeyboardButton(
                f"{display_text}", 
                callback_data=f"pay_{callback_suffix}_{domain_name}_{price}_{currency}"
            )])
        
        keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data="search_domains")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing payment options: {e}")
        
        # Enhanced error handling for network timeouts vs other errors
        if "ReadError" in str(e) or "NetworkError" in str(e) or "httpx" in str(e):
            logger.info("🔄 Network timeout in payment options - retrying...")
            try:
                # Retry payment options with simplified message on network timeout
                simplified_message = f"""
Payment Required

Domain: {domain_name}
Price: ${price:.2f} {currency}

Payment options available. Retrying...
"""
                keyboard = [[InlineKeyboardButton(btn_t("retry_payment", user_lang), callback_data=f"register_{domain_name}")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await safe_edit_message(query, simplified_message, reply_markup=reply_markup)
                return
            except Exception as retry_error:
                logger.debug(f"Retry also failed: {retry_error}")
        
        await safe_edit_message(query, "Error\n\nCould not load payment options.\n\nPlease try again.")

async def process_crypto_payment(query, crypto_type, domain_name, price, currency):
    """Generate BlockBee payment invoice - OPTIMIZED with parallel DB queries"""
    user = query.from_user
    
    try:
        # 🎯 ENHANCED PROGRESS: Show detailed crypto payment setup
        progress_msg = f"₿ <b>Setting up {crypto_type.upper()} Payment...</b>\n\n"
        progress_msg += f"🌐 Domain: <code>{domain_name}</code>\n"
        progress_msg += f"💰 Amount: ${float(price):.2f}\n"
        progress_msg += f"🔄 Connecting to payment provider...\n"
        progress_msg += "⏳ This may take a few seconds..."
        
        await safe_edit_message(query, progress_msg, parse_mode='HTML')
        
        # PERFORMANCE OPTIMIZATION: Get user record and language in parallel
        user_lang_code = user.language_code if hasattr(user, 'language_code') else None
        user_record, user_lang = await asyncio.gather(
            get_or_create_user(user.id),
            resolve_user_language(user.id, user_lang_code)
        )
        
        # Skip $2 padding for USDT (stablecoin, no volatility)
        original_price = Decimal(str(float(price)))
        is_stablecoin = crypto_type.lower() in ('usdt', 'usdt_trc20', 'usdt_erc20')
        gateway_price = original_price if is_stablecoin else original_price + Decimal('2')
        
        # Generate payment with configured provider (DynoPay/BlockBee)
        order_id = f"domain_{domain_name}_{user.id}_{int(time.time())}"
        payment_result = await create_payment_address(
            currency=crypto_type.lower(),
            order_id=order_id,
            value=gateway_price,
            user_id=user_record['id'],
            base_amount=original_price
        )
        
        if not payment_result:
            await safe_edit_message(query, "Payment Error\n\nCould not generate payment address. Please try again.")
            return
        intent_id = await create_registration_intent(
            user_id=user_record['id'],
            domain_name=domain_name,
            estimated_price=float(price),
            payment_data={
                'order_id': order_id,
                'payment_address': payment_result['address'],
                'currency': currency,
                'crypto_type': crypto_type,
                'provider': payment_result.get('provider', 'unknown')
            }
        )
        
        if not intent_id:
            await safe_edit_message(query, "Registration Error\n\nCould not create registration intent. Please try again.")
            return
        
        # Step 2: Save domain order using single-table consolidation (domain_orders only)
        # This replaces the dual-table system (orders + domain_orders) to eliminate bugs and complexity
        integer_order_id = await create_domain_order_crypto(
            user_id=user_record['id'],
            domain_name=domain_name,
            expected_amount=Decimal(str(price)),
            currency=currency,
            blockbee_order_id=order_id,
            intent_id=intent_id,
            payment_address=payment_result['address']
        )
        
        if not integer_order_id:
            await safe_edit_message(query, "Order Error\n\nCould not create domain order. Please try again.")
            return
        
        logger.info(f"✅ Created domain order with ID: {integer_order_id} in domain_orders table (tracking ID: {order_id})")
        
        # Step 3: Update intent status to payment_pending
        await update_intent_status(intent_id, 'payment_pending', {
            'payment_address': payment_result['address'],
            'order_id': integer_order_id,  # Use integer order ID, not string tracking ID
            'tracking_id': order_id  # Keep string for tracking purposes
        })
        
        # Show payment instructions with copy functionality
        crypto_amount_display = payment_result.get('crypto_amount', 'TBD')
        
        # FIXED: Use proper usd_amount and crypto_amount parameters instead of legacy amount string
        # This allows render_crypto_payment to format the display correctly with both USD and crypto amounts
        payment_message, copy_keyboard = render_crypto_payment(
            address=payment_result['address'],
            crypto_name=f"{crypto_type.upper()}",
            usd_amount=float(price),  # Pass USD amount as number
            crypto_amount=crypto_amount_display if crypto_amount_display != 'TBD' else None,  # Pass crypto amount or None
            order_id=str(integer_order_id),  # Convert integer order ID to string for render_crypto_payment
            expires_minutes=15
        )
        
        # Add domain context and additional action buttons
        # Check if this is a hosting bundle order
        from database import get_active_hosting_intent
        hosting_intent = await get_active_hosting_intent(user_record['id'], domain_name)
        
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        if hosting_intent:
            # This is a hosting bundle - domain + hosting
            domain_info = f"\n📦 <b>{t('payment.hosting_domain_bundle', user_lang)}</b> {escape_html(domain_name)}\n\n{t('payment.bundle_auto_provision_message', user_lang)}"
        else:
            # This is domain-only registration
            domain_info = f"\n🌐 <b>{t('common_labels.domain', user_lang)}</b> {escape_html(domain_name)}\n\n{t('payment.domain_auto_register_message', user_lang)}"
        
        payment_message += domain_info
        
        additional_buttons = [
            [InlineKeyboardButton(btn_t("change_payment_method", user_lang), callback_data=f"register_{domain_name}")],
            [InlineKeyboardButton(t("buttons.cancel_order", user_lang), callback_data="search_domains")],
            [InlineKeyboardButton(t("buttons.back_to_domains", user_lang), callback_data="my_domains")]
        ]
        
        # Combine copy buttons with action buttons
        combined_keyboard = list(copy_keyboard.inline_keyboard) + additional_buttons
        final_keyboard = InlineKeyboardMarkup(combined_keyboard)
        
        await safe_edit_message(query, payment_message, reply_markup=final_keyboard, parse_mode='HTML')
        
        logger.info(f"Payment invoice generated for {domain_name}: {payment_result['address']}")
        
    except Exception as e:
        logger.error(f"Error processing crypto payment: {e}")
        await safe_edit_message(query, "Payment Error\n\nCould not process payment. Please try again.")

# Removed check_payment_status function - payments are now processed automatically via webhooks

async def process_domain_registration(query, domain_name, order):
    """Phase 5-7: Complete domain registration after payment confirmation - ORCHESTRATOR VERSION"""
    try:
        logger.info(f"🎯 HANDLERS: Routing domain registration through orchestrator for {domain_name}")
        
        # Get user record for orchestrator
        user_record = await get_or_create_user(query.from_user.id)
        
        # Create a query adapter for the orchestrator (similar to webhook adapter)
        class HandlerQueryAdapter:
            def __init__(self, query):
                self.query = query
                self.user_id = user_record['id']
                
            async def send_message_to_user(self, text, reply_markup=None, parse_mode='HTML'):
                """Send message via telegram query interface with HTML formatting"""
                await safe_edit_message(self.query, text, reply_markup)
        
        query_adapter = HandlerQueryAdapter(query)
        
        # Create payment details for wallet payments to show correct amount in success message
        wallet_payment_details = {
            'amount_usd': order.get('expected_amount', 0),
            'currency': 'USD',
            'payment_method': 'wallet'
        }
        
        # Route through centralized orchestrator
        orchestrator_result = await orchestrator_start_registration(
            order_id=order.get('id'),
            user_id=user_record['id'],
            domain_name=domain_name,
            payment_details=wallet_payment_details,  # Include wallet payment details for success message
            query_adapter=query_adapter
        )
        
        # Handle orchestrator results
        if orchestrator_result.get('status') == 'already_processed':
            logger.info(f"🚫 HANDLERS: Domain registration already processed for {domain_name}")
            await safe_edit_message(query, f"ℹ️ Registration Already Complete\n\nDomain {domain_name} has already been processed.")
            return
        
        elif orchestrator_result.get('status') == 'duplicate_prevented':
            logger.info(f"🚫 HANDLERS: Duplicate domain registration prevented for {domain_name}")
            await safe_edit_message(query, f"ℹ️ Registration In Progress\n\nDomain {domain_name} is already being processed.")
            return
        
        elif orchestrator_result.get('status') == 'error':
            logger.error(f"❌ HANDLERS: Orchestrator error for {domain_name}: {orchestrator_result.get('error', 'Unknown error')}")
            await safe_edit_message(query, f"❌ Registration Error\n\nAn error occurred during registration.")
            # Trigger automatic refund if this was a wallet payment
            await handle_registration_failure(order)
            return
        
        elif orchestrator_result.get('success'):
            logger.info(f"✅ HANDLERS: Domain registration completed via orchestrator: {domain_name}")
            # Orchestrator already sent success notification with buttons
        else:
            logger.warning(f"⚠️ HANDLERS: Unexpected orchestrator result for {domain_name}: {orchestrator_result}")
            await safe_edit_message(query, f"⚠️ Registration Status Unknown\n\nPlease check your domains list.")
        
    except Exception as e:
        logger.error(f"❌ HANDLERS: Error during orchestrated domain registration for {domain_name}: {e}")
        await safe_edit_message(query, f"❌ Registration Error\n\nAn error occurred during registration.")
        
        # Update order status and trigger refund on exception
        try:
            await execute_update("UPDATE domain_orders SET status = 'failed' WHERE id = %s", (order['id'],))
            await handle_registration_failure(order)
        except Exception as cleanup_error:
            logger.error(f"❌ HANDLERS: Error during cleanup for {domain_name}: {cleanup_error}")

async def handle_registration_failure(order):
    """Handle automatic refund for failed domain registrations"""
    try:
        # Check if this order has a hold transaction (wallet payment)
        hold_transaction_id = order.get('hold_transaction_id')
        if hold_transaction_id:
            logger.info(f"🔄 Triggering automatic refund for failed order: {order['domain_name']}")
            success = await finalize_wallet_reservation(hold_transaction_id, success=False)
            if success:
                logger.info(f"✅ Automatic refund processed for domain: {order['domain_name']}")
            else:
                logger.error(f"❌ Automatic refund failed for domain: {order['domain_name']}")
        else:
            logger.info(f"ℹ️ No wallet payment to refund for order: {order['domain_name']}")
            
    except Exception as e:
        logger.error(f"Error handling registration failure refund: {e}")

async def process_wallet_payment(query, domain_name, price, currency):
    """Process payment using wallet balance - OPTIMIZED with parallel DB queries"""
    user = query.from_user
    
    try:
        price_float = float(price)
        
        # PERFORMANCE OPTIMIZATION: Fetch user data, wallet balance, and language in parallel
        user_lang_code = user.language_code if hasattr(user, 'language_code') else None
        user_record, wallet_balance, user_lang = await asyncio.gather(
            get_or_create_user(user.id),
            get_user_wallet_balance(user.id),
            resolve_user_language(user.id, user_lang_code)
        )
        
        # Check if user has sufficient balance
        if wallet_balance < price_float:
            await safe_edit_message(query, 
                f"❌ Insufficient Balance\n\n"
                f"Required: ${price_float:.2f}\n"
                f"{t('wallet.your_balance', user_lang)} ${wallet_balance:.2f}\n\n"
                f"Please add funds to your wallet first."
            )
            return
        
        # Check if this is a hosting bundle order
        from database import get_active_hosting_intent
        hosting_intent = await get_active_hosting_intent(user_record['id'], domain_name)
        
        if hosting_intent:
            # This is a hosting bundle - domain + hosting
            payment_msg = f"💳 <b>{t('payment.wallet_payment', user_lang)}</b> • ${price_float:.2f}\n📦 <b>{t('payment.hosting_domain_bundle', user_lang)}</b> {escape_html(domain_name)}\n⏳ {t('payment.processing', user_lang)}"
            description = f"{t('payment.hosting_domain_bundle', user_lang)}: {domain_name}"
        else:
            # This is domain-only registration  
            payment_msg = f"💳 <b>{t('payment.wallet_payment', user_lang)}</b> • ${price_float:.2f}\n🌐 <b>{t('common_labels.domain', user_lang)}</b> {escape_html(domain_name)}\n⏳ {t('payment.processing', user_lang)}"
            description = f"{t('payment.domain_registration', user_lang)}: {domain_name}"
        
        await safe_edit_message(query, payment_msg, parse_mode='HTML')
        
        # Reserve wallet balance for the order
        hold_transaction_id = await reserve_wallet_balance(
            user_record['id'], 
            Decimal(str(price_float)), 
            description
        )
        
        if not hold_transaction_id:
            await safe_edit_message(query, 
                "❌ Payment Failed\n\nCould not reserve wallet balance. Please try again."
            )
            return
        
        # Create domain order with wallet payment and hold transaction ID
        await execute_update(
            "INSERT INTO domain_orders (user_id, domain_name, status, expected_amount, currency, contact_handle, hold_transaction_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (user_record['id'], domain_name, 'paid', price_float, currency, 'wallet_payment', hold_transaction_id)
        )
        
        # Get the order we just created
        orders = await execute_query(
            "SELECT * FROM domain_orders WHERE user_id = %s AND domain_name = %s ORDER BY created_at DESC LIMIT 1",
            (user_record['id'], domain_name)
        )
        
        if orders:
            order = orders[0]
            
            # ✅ FIXED: Do not finalize yet - let orchestrator handle it after success/failure
            # Start domain registration process immediately (orchestrator will finalize wallet)
            await process_domain_registration(query, domain_name, order)
        else:
            await safe_edit_message(query, 
                f"❌ Payment Error\n\nOrder creation failed. Please contact {BrandConfig().support_contact}."
            )
            # Refund the reservation
            await finalize_wallet_reservation(hold_transaction_id, success=False)
        
    except Exception as e:
        logger.error(f"Error processing wallet payment: {e}")
        await safe_edit_message(query, 
            "❌ Payment Error\n\nAn error occurred processing your payment. Please try again."
        )

async def show_wallet_deposit_options(query):
    """Show deposit amount selection (first step of wallet deposit flow)"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = """
💰 Add Funds

Select deposit amount:

*Minimum deposit: $10 USD*
"""
    
    # Preset amount options
    keyboard = [
        [
            InlineKeyboardButton("$10", callback_data="deposit_amount_10"),
            InlineKeyboardButton("$25", callback_data="deposit_amount_25")
        ],
        [
            InlineKeyboardButton("$50", callback_data="deposit_amount_50"),
            InlineKeyboardButton("$100", callback_data="deposit_amount_100")
        ],
        [InlineKeyboardButton("💵 Custom Amount", callback_data="deposit_amount_custom")],
        [InlineKeyboardButton(t("buttons.back_to_wallet", user_lang), callback_data="wallet_main")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_crypto_selection_for_deposit(query, amount_usd):
    """Show cryptocurrency selection for a specific deposit amount (step 2)"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"""
💰 Deposit ${amount_usd:.2f} USD

Select your cryptocurrency:
"""
    
    # Build keyboard using unified crypto configuration
    # Use colon separator for better parsing: deposit_{crypto}:{amount}
    keyboard = []
    for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
        keyboard.append([InlineKeyboardButton(
            f"{icon} {display_text}", 
            callback_data=f"deposit_{callback_suffix}:{amount_usd}"
        )])
    
    keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data="wallet_deposit")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_wallet_transaction_history(query):
    """Show detailed wallet transaction history"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        transactions = await get_user_wallet_transactions(user_record['id'], 20)
        balance = await get_user_wallet_balance(user.id)
        
        if not transactions:
            message = f"""
📊 History

{t('wallet.balance_label', user_lang)} {format_money(balance, 'USD', include_currency=True)}

{t('wallet.no_transactions', user_lang)}
"""
        else:
            message = f"""
📊 History

{t('wallet.balance_label', user_lang)} {format_money(balance, 'USD', include_currency=True)}

"""
            for tx in transactions:
                amount = float(tx['amount'])
                date = tx['created_at'].strftime('%m/%d')
                emoji = "➕" if amount > 0 else "➖"
                tx_type = tx['transaction_type'] or 'transaction'
                
                # Extract simple type from verbose descriptions
                if 'domain' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.domain', user_lang)
                elif 'deposit' in tx_type.lower() or 'crypto' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.deposit', user_lang)
                elif 'credit' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.credit', user_lang)
                elif 'refund' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.refund', user_lang)
                elif 'debit' in tx_type.lower():
                    simple_type = t('wallet.transaction_type.debit', user_lang)
                else:
                    # Fallback to generic transaction label
                    simple_type = t('wallet.transaction_type.transaction', user_lang)
                
                message += f"{emoji} ${abs(amount):.2f} - {simple_type} ({date})\n"
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.add_funds", user_lang), callback_data="wallet_deposit")],
            [InlineKeyboardButton(t("buttons.back_to_wallet", user_lang), callback_data="wallet_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing transaction history: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load transaction history.")

async def process_wallet_crypto_deposit(query, crypto_type, amount_usd=None):
    """Process cryptocurrency deposit to wallet with optional fixed amount"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Convert amount to Decimal if provided
        deposit_amount = Decimal(str(amount_usd)) if amount_usd else Decimal('0')
        
        await safe_edit_message(query, f"💱 Calculating {crypto_type.upper()} amount...")
        
        # Get or create user
        user_record = await get_or_create_user(user.id)
        
        # Calculate crypto amount - no buffer
        crypto_amount_to_request = None
        crypto_display = None
        
        if deposit_amount > 0:
            from services.fastforex import fastforex_service
            
            # Get exchange rate and convert to crypto
            base_crypto_amount, base_formatted = await fastforex_service.get_usd_to_crypto_amount(
                float(deposit_amount), crypto_type
            )
            
            # No buffer - use exact amount
            base_crypto_decimal = Decimal(str(base_crypto_amount))
            crypto_amount_to_request = base_crypto_decimal
            
            # Format crypto amount for display (strip trailing zeros)
            from pricing_utils import format_crypto_amount
            crypto_display = format_crypto_amount(crypto_amount_to_request, crypto_type.upper())
        
        # Create order using UUID-based function
        order_uuid = await create_order_with_uuid(
            user_id=user_record['id'],
            order_type='wallet',
            total_amount=float(deposit_amount),
            currency='USD',
            metadata=f'{{"crypto_type": "{crypto_type}", "deposit_type": "wallet", "requested_usd": "{deposit_amount}"}}'
        )
        
        if not order_uuid:
            await safe_edit_message(query, "❌ Order Error\n\nCould not create payment order. Please try again.")
            return
            
        # Get the serial ID for backward compatibility with payment providers
        from database import get_order_by_uuid
        order_record = await get_order_by_uuid(order_uuid)
        db_order_id = str(order_record['id']) if order_record else order_uuid
        
        # CRITICAL: Prefix order_id with 'wallet_fund_' for proper webhook routing
        # The webhook handler routes to _process_wallet_deposit based on this prefix
        order_id = f"wallet_fund_{db_order_id}"
        
        # Generate payment with configured provider (DynoPay/BlockBee)
        # Skip $2 padding for USDT (stablecoin, no volatility)
        is_stablecoin = crypto_type.lower() in ('usdt', 'usdt_trc20', 'usdt_erc20')
        gateway_amount = deposit_amount if is_stablecoin else deposit_amount + Decimal('2')
        payment_result = await create_payment_address(
            currency=crypto_type.lower(),
            order_id=order_id,
            value=gateway_amount,  # Padded amount for crypto calculation
            user_id=user_record['id']
        )
        
        if not payment_result:
            await safe_edit_message(query, "❌ Payment Error\n\nCould not generate payment address. Please try again.")
            return
        
        # Use crypto amount from payment provider (DynoPay/BlockBee) instead of local calculation
        provider_crypto_amount = payment_result.get('crypto_amount')
        if provider_crypto_amount:
            crypto_display = provider_crypto_amount
        
        # Save wallet deposit to database
        await create_wallet_deposit_with_uuid(
            user_id=user_record['id'],
            crypto_currency=crypto_type.upper(),
            usd_amount=deposit_amount,
            payment_address=payment_result['address'],
            blockbee_order_id=order_id,
            status='pending_payment'
        )
        
        # Show payment instructions with copy functionality
        crypto_name = {
            'btc': 'Bitcoin',
            'ltc': 'Litecoin', 
            'doge': 'Dogecoin',
            'eth': 'Ethereum',
            'usdt_trc20': 'USDT (TRC20)',
            'usdt_erc20': 'USDT (ERC20)'
        }.get(crypto_type, crypto_type.upper())
        
        from message_utils import format_inline_code
        
        # Build payment message with crypto amount from provider
        if deposit_amount > 0 and crypto_display:
            payment_message = f"""💰 {crypto_name} Deposit

Send exactly: <code>{crypto_display}</code>

Address: {format_inline_code(payment_result['address'])}

✅ You will receive: ${deposit_amount:.2f} USD
💡 Tap address to copy"""
        else:
            # Fallback for flexible amount (shouldn't happen with new flow)
            payment_message = f"""💰 {crypto_name} Deposit

Address: {format_inline_code(payment_result['address'])}

💰 Send any amount → Auto-credited to wallet
💡 Tap address to copy"""
        
        # Build keyboard with actions (address is tappable in message)
        keyboard = [
            [InlineKeyboardButton("📱 QR Code", callback_data=f"show_wallet_qr:{order_id}")],
            [InlineKeyboardButton(t("buttons.cancel_funding", user_lang), callback_data=f"cancel_wallet_deposit:{order_id}")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="wallet_deposit")]
        ]
        final_keyboard = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, payment_message, reply_markup=final_keyboard, parse_mode='HTML')
        
        logger.info(f"💰 Wallet deposit payment generated for user {user.id}: ${deposit_amount} USD = {crypto_display}")
        
    except Exception as e:
        logger.error(f"Error processing wallet crypto deposit: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not process deposit request.")


async def handle_copy_address(query, address):
    """Handle copy address button - provide feedback to user"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Note: query.answer() is already called by main callback router
    # Show confirmation message with address highlighted
    text = f"""📋 Address Copied!

{address}

Use this address for your crypto payment.

💡 The address has been copied to your clipboard."""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="wallet_deposit")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)


async def handle_copy_memo(query, memo):
    """Handle copy memo button - provide feedback to user"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Note: query.answer() is already called by main callback router
    # Show confirmation message with memo highlighted
    text = f"""📋 Memo Copied!

{memo}

Include this memo/tag with your payment.

💡 The memo has been copied to your clipboard."""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="wallet_deposit")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)


async def handle_copy_hosting_credential(query, credential, credential_type):
    """Handle copy hosting credential button - provide feedback to user"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Note: query.answer() is already called by main callback router
    # Show confirmation message with credential highlighted
    text = f"""📋 {credential_type} Copied!

{credential}

Your hosting credential has been copied to clipboard.
💾 Save all credentials securely for future access."""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="my_hosting")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)


async def show_wallet_qr_code(query, order_id):
    """Show QR code for wallet deposit payment or domain payment"""
    user = query.from_user
    
    try:
        # Get user record
        user_record = await get_or_create_user(user.id)
        
        # First try to find wallet deposit
        deposits = await execute_query(
            "SELECT * FROM wallet_deposits WHERE blockbee_order_id = %s AND user_id = %s",
            (order_id, user_record['id'])
        )
        
        if deposits:
            # Handle wallet deposit QR code
            await _show_wallet_deposit_qr(query, order_id, deposits[0])
            return
        
        # CRITICAL FIX: Check for RDP orders FIRST before generic payment_intents
        # RDP orders use UUID format and need special handling
        # Must join payment_intents to get payment_address
        rdp_orders = await execute_query("""
            SELECT o.*, ro.rdp_server_id, pi.payment_address, pi.crypto_currency
            FROM orders o
            INNER JOIN rdp_orders ro ON ro.order_id = o.id
            LEFT JOIN payment_intents pi ON pi.order_id = o.uuid_id::text AND pi.status = 'address_created'
            WHERE o.uuid_id = %s AND o.user_id = %s
        """, (order_id, user_record['id']))
        
        logger.info(f"🔍 QR: RDP query returned {len(rdp_orders) if rdp_orders else 0} orders for UUID: {order_id}")
        if rdp_orders:
            logger.info(f"🔍 QR: RDP order details - payment_address: {rdp_orders[0].get('payment_address')}, has crypto_currency: {bool(rdp_orders[0].get('crypto_currency'))}")
        
        if rdp_orders and rdp_orders[0].get('payment_address'):
            # Handle RDP payment QR code (only if payment address exists)
            logger.info(f"✅ QR: Found RDP order with payment address for UUID: {order_id}")
            await _show_rdp_payment_qr(query, order_id, rdp_orders[0])
            return
        
        # Try domain payment - check by order_id string first
        payment_intents = await execute_query(
            "SELECT * FROM payment_intents WHERE order_id = %s AND user_id = %s",
            (order_id, user_record['id'])
        )
        
        if payment_intents:
            # Handle domain payment QR code
            await _show_domain_payment_qr(query, order_id, payment_intents[0])
            return
        
        # CRITICAL FIX: If not found by direct order_id, try to find via domain_orders table
        # This handles the case where QR button passes integer domain order ID but payment_intent uses tracking ID
        try:
            domain_order_id_int = int(order_id)
            # Look up the tracking ID from domain_orders table
            domain_orders = await execute_query(
                "SELECT blockbee_order_id FROM domain_orders WHERE id = %s AND user_id = %s",
                (domain_order_id_int, user_record['id'])
            )
            
            if domain_orders:
                tracking_id = domain_orders[0]['blockbee_order_id']
                logger.info(f"🔍 QR: Looking up payment intent using tracking ID: {tracking_id}")
                
                # Try to find payment intent using the tracking ID
                payment_intents = await execute_query(
                    "SELECT * FROM payment_intents WHERE order_id = %s AND user_id = %s",
                    (tracking_id, user_record['id'])
                )
                
                if payment_intents:
                    logger.info(f"✅ QR: Found payment intent via tracking ID lookup")
                    await _show_domain_payment_qr(query, tracking_id, payment_intents[0])
                    return
                    
        except ValueError:
            # order_id is not an integer, continue with normal flow
            pass
        
        logger.warning(f"❌ QR: Payment not found for order_id: {order_id}, user: {user_record['id']}")
        await safe_edit_message(query, "❌ Payment Not Found\n\nPayment order not found.")
        
    except Exception as e:
        logger.error(f"Error showing QR code: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not generate QR code.")

async def _show_wallet_deposit_qr(query, order_id, deposit):
    """Show QR code for wallet deposit"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    usd_amount = float(deposit['usd_amount'])
    crypto_currency = deposit['crypto_currency']
    payment_address = deposit['payment_address']
    
    # Calculate crypto amount - no buffer, use exact rate
    crypto_display = None
    if usd_amount > 0:
        try:
            from services.fastforex import fastforex_service
            base_crypto_amount, _ = await fastforex_service.get_usd_to_crypto_amount(usd_amount, crypto_currency)
            
            # No buffer - use exact amount
            crypto_amount = Decimal(str(base_crypto_amount))
            
            # Format crypto amount
            from pricing_utils import format_crypto_amount
            crypto_display = format_crypto_amount(crypto_amount, crypto_currency)
        except Exception as e:
            logger.warning(f"Could not calculate crypto amount for QR: {e}")
    
    # Generate QR code for the payment address
    qr = QRCode(version=1, box_size=10, border=5)
    qr.add_data(payment_address)
    qr.make(fit=True)
    
    qr_image = qr.make_image(fill_color="black", back_color="white")
    bio = BytesIO()
    qr_image.save(bio, format='PNG')
    bio.seek(0)
    
    # Handle flexible amount display with proper HTML formatting for tap-and-copy
    from message_utils import format_inline_code
    
    if usd_amount == 0:
        message = f"""📱 {crypto_currency} Payment

Address: {format_inline_code(payment_address)}

💰 Send any amount → Auto-credited to wallet
💡 Tap address to copy"""
    elif crypto_display:
        message = f"""📱 {crypto_currency} Payment

Send exactly: <code>{crypto_display}</code>
Amount: {format_money(Decimal(str(usd_amount)), 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Tap address to copy"""
    else:
        message = f"""📱 {crypto_currency} Payment

Amount: {format_money(Decimal(str(usd_amount)), 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Tap address to copy"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.back_to_crypto_selection", user_lang), callback_data="wallet_deposit_from_qr")],
        [InlineKeyboardButton(t("buttons.cancel_funding", user_lang), callback_data=f"cancel_deposit:{order_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        # Send QR code image with timeout protection
        qr_message = await asyncio.wait_for(
            query.message.reply_photo(
                photo=bio,
                caption=message,
                reply_markup=reply_markup,
                parse_mode='HTML'
            ),
            timeout=30.0  # 30 second timeout
        )
        
        # Only delete original message AFTER successful QR send
        try:
            await query.message.delete()
        except Exception as delete_error:
            logger.warning(f"Could not delete original wallet QR message: {delete_error}")
            # Continue - QR was sent successfully, deletion failure is not critical
            
    except asyncio.TimeoutError:
        logger.warning(f"Wallet QR code upload timed out for order {order_id}")
        # Fallback: Edit original message with text-only payment info
        if usd_amount == 0:
            fallback_message = f"""⚠️ QR Code Loading...

📱 {crypto_currency} Payment Details

Address: {format_inline_code(payment_address)}

💰 Send any amount → Auto-credited to wallet
💡 Copy address above to send payment

QR code generation timed out, but you can still copy the address above."""
        elif crypto_display:
            fallback_message = f"""⚠️ QR Code Loading...

📱 {crypto_currency} Payment Details

Send exactly: <code>{crypto_display}</code>
Amount: {format_money(Decimal(str(usd_amount)), 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Copy address above to send payment

QR code generation timed out, but you can still copy the address above."""
        else:
            fallback_message = f"""⚠️ QR Code Loading...

📱 {crypto_currency} Payment Details

Amount: {format_money(Decimal(str(usd_amount)), 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Copy address above to send payment

QR code generation timed out, but you can still copy the address above."""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error generating wallet QR code for order {order_id}: {e}")
        # Fallback: Edit original message with text-only payment info
        if usd_amount == 0:
            fallback_message = f"""❌ QR Code Unavailable

📱 {crypto_currency} Payment Details

Address: {format_inline_code(payment_address)}

💰 Send any amount → Auto-credited to wallet
💡 Copy address above to send payment"""
        elif crypto_display:
            fallback_message = f"""❌ QR Code Unavailable

📱 {crypto_currency} Payment Details

Send exactly: <code>{crypto_display}</code>
Amount: {format_money(Decimal(str(usd_amount)), 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Copy address above to send payment"""
        else:
            fallback_message = f"""❌ QR Code Unavailable

📱 {crypto_currency} Payment Details

Amount: {format_money(Decimal(str(usd_amount)), 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Copy address above to send payment"""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)

async def _show_domain_payment_qr(query, order_id, payment_intent):
    """Show QR code for domain payment with timeout handling"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    payment_address = payment_intent['payment_address']
    crypto_currency = payment_intent['crypto_currency']
    usd_amount = float(payment_intent.get('amount', 0))
    
    # Extract domain name from order_id
    domain_name = "domain"
    if order_id.startswith("domain_"):
        parts = order_id.split("_")
        if len(parts) >= 2:
            domain_name = parts[1]
    
    # Format message for domain payment
    from message_utils import format_inline_code
    
    message = f"""📱 {crypto_currency.upper()} Payment QR Code

💰 Amount: ${usd_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🌐 Domain: {domain_name}

💡 Scan QR code with your crypto wallet
⏰ Payment expires in 15 minutes"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.cancel_order", user_lang), callback_data="qr_cancel_order")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        # Generate QR code for the payment address
        qr = QRCode(version=1, box_size=10, border=5)
        qr.add_data(payment_address)
        qr.make(fit=True)
        
        qr_image = qr.make_image(fill_color="black", back_color="white")
        bio = BytesIO()
        qr_image.save(bio, format='PNG')
        bio.seek(0)
        
        # Send QR code image with timeout protection
        qr_message = await asyncio.wait_for(
            query.message.reply_photo(
                photo=bio,
                caption=message,
                reply_markup=reply_markup,
                parse_mode='HTML'
            ),
            timeout=30.0  # 30 second timeout
        )
        
        # Only delete original message AFTER successful QR send
        try:
            await query.message.delete()
        except Exception as delete_error:
            logger.warning(f"Could not delete original QR message: {delete_error}")
            # Continue - QR was sent successfully, deletion failure is not critical
            
    except asyncio.TimeoutError:
        logger.warning(f"QR code upload timed out for order {order_id}")
        # Fallback: Edit original message with text-only payment info
        fallback_message = f"""⚠️ QR Code Loading...

📱 {crypto_currency.upper()} Payment Details

💰 Amount: ${usd_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🌐 Domain: {domain_name}

💡 Copy address above to your crypto wallet
⏰ Payment expires in 15 minutes

QR code generation timed out, but you can still copy the address above."""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error generating QR code for order {order_id}: {e}")
        # Fallback: Edit original message with text-only payment info
        fallback_message = f"""❌ QR Code Unavailable

📱 {crypto_currency.upper()} Payment Details

💰 Amount: ${usd_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🌐 Domain: {domain_name}

💡 Copy address above to your crypto wallet
⏰ Payment expires in 15 minutes"""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)

async def _show_rdp_payment_qr(query, order_id, rdp_order):
    """Show QR code for RDP server payment with timeout handling"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Get payment details from rdp_order
    payment_address = rdp_order['payment_address']
    total_amount = float(rdp_order['total_amount'])
    metadata = rdp_order['metadata']
    
    # Get plan details
    plan_id = metadata.get('plan_id')
    billing_cycle = metadata.get('billing_cycle', 'monthly')
    # Get crypto currency from payment_intents join (not from payment_method)
    crypto_currency = rdp_order.get('crypto_currency', 'ETH').upper()
    
    # Get plan name
    plan = await execute_query("SELECT plan_name FROM rdp_plans WHERE id = %s", (plan_id,))
    plan_name = plan[0]['plan_name'] if plan else "Windows RDP Server"
    
    # Format billing display
    if billing_cycle == 'monthly':
        billing_display = "Monthly"
    elif billing_cycle == 'quarterly':
        billing_display = "Quarterly (3 months)"
    elif billing_cycle == 'yearly':
        billing_display = "Yearly (12 months)"
    else:
        billing_display = billing_cycle.capitalize()
    
    # Format message for RDP payment
    from message_utils import format_inline_code
    
    message = f"""📱 {crypto_currency} Payment QR Code

💰 Amount: ${total_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🖥️ Server: {plan_name}
📅 Billing: {billing_display}

💡 Scan QR code with your crypto wallet
⏰ Payment expires in 45 minutes"""
    
    cancel_btn = await t_for_user('rdp.buttons.cancel', user.id)
    
    keyboard = [
        [InlineKeyboardButton(cancel_btn, callback_data=f"rdp_cancel_order:{order_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        # Generate QR code for the payment address
        qr = QRCode(version=1, box_size=10, border=5)
        qr.add_data(payment_address)
        qr.make(fit=True)
        
        qr_image = qr.make_image(fill_color="black", back_color="white")
        bio = BytesIO()
        qr_image.save(bio, format='PNG')
        bio.seek(0)
        
        # Send QR code image with timeout protection
        qr_message = await asyncio.wait_for(
            query.message.reply_photo(
                photo=bio,
                caption=message,
                reply_markup=reply_markup,
                parse_mode='HTML'
            ),
            timeout=30.0  # 30 second timeout
        )
        
        # Only delete original message AFTER successful QR send
        try:
            await query.message.delete()
        except Exception as delete_error:
            logger.warning(f"Could not delete original RDP QR message: {delete_error}")
            # Continue - QR was sent successfully, deletion failure is not critical
            
    except asyncio.TimeoutError:
        logger.warning(f"RDP QR code upload timed out for order {order_id}")
        # Fallback: Edit original message with text-only payment info
        fallback_message = f"""⚠️ QR Code Loading...

📱 {crypto_currency} Payment Details

💰 Amount: ${total_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🖥️ Server: {plan_name}
📅 Billing: {billing_display}

💡 Copy address above to your crypto wallet
⏰ Payment expires in 45 minutes

QR code generation timed out, but you can still copy the address above."""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error generating RDP QR code for order {order_id}: {e}")
        # Fallback: Edit original message with text-only payment info
        fallback_message = f"""❌ QR Code Unavailable

📱 {crypto_currency} Payment Details

💰 Amount: ${total_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🖥️ Server: {plan_name}
📅 Billing: {billing_display}

💡 Copy address above to your crypto wallet
⏰ Payment expires in 45 minutes"""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)

async def cancel_wallet_deposit(query, order_id):
    """Cancel a wallet deposit"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get user record
        user_record = await get_or_create_user(user.id)
        
        # Update deposit status to cancelled
        await execute_update(
            "UPDATE wallet_deposits SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE blockbee_order_id = %s AND user_id = %s",
            ('cancelled', order_id, user_record['id'])
        )
        
        message = """
❌ Funding Cancelled

Your wallet deposit has been cancelled. No payment is required.

You can start a new deposit anytime from your wallet.
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.start_new_deposit", user_lang), callback_data="wallet_deposit")],
            [InlineKeyboardButton(t("buttons.back_to_wallet", user_lang), callback_data="wallet_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        logger.info(f"💰 Wallet deposit cancelled by user {user.id}: {order_id}")
        
    except Exception as e:
        logger.error(f"Error cancelling wallet deposit: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not cancel deposit.")

async def handle_wallet_deposit_from_qr(query):
    """Handle navigation from QR code photo to amount selection"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Send amount selection message (updated flow)
        message = """
💰 Add Funds

Select deposit amount:

<b>Minimum deposit: $10 USD</b>
"""
        
        # Preset amount options
        keyboard = [
            [
                InlineKeyboardButton("$10", callback_data="deposit_amount_10"),
                InlineKeyboardButton("$25", callback_data="deposit_amount_25")
            ],
            [
                InlineKeyboardButton("$50", callback_data="deposit_amount_50"),
                InlineKeyboardButton("$100", callback_data="deposit_amount_100")
            ],
            [InlineKeyboardButton("💵 Custom Amount", callback_data="deposit_amount_custom")],
            [InlineKeyboardButton(t("buttons.back_to_wallet", user_lang), callback_data="wallet_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send new message instead of editing
        await query.message.reply_text(message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error handling wallet deposit from QR: {e}")
        # Fallback: just send a simple message
        await query.message.reply_text("❌ Error loading deposit options. Please try again.")

async def handle_cancel_wallet_deposit_from_qr(query, order_id):
    """Handle cancel deposit from QR code photo"""
    user = query.from_user
    
    if not user:
        logger.error("No user in handle_cancel_wallet_deposit_from_qr")
        return
    
    # Get user language
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Get user record
        user_record = await get_or_create_user(user.id)
        
        # Update deposit status to cancelled
        await execute_update(
            "UPDATE wallet_deposits SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE blockbee_order_id = %s AND user_id = %s",
            ('cancelled', order_id, user_record['id'])
        )
        
        message = """
❌ Funding Cancelled

Your wallet deposit has been cancelled. No payment is required.

You can start a new deposit anytime from your wallet.
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.start_new_deposit", user_lang), callback_data="wallet_deposit")],
            [InlineKeyboardButton(t("buttons.back_to_wallet", user_lang), callback_data="wallet_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send new message instead of editing
        await query.message.reply_text(message, reply_markup=reply_markup)
        
        logger.info(f"💰 Wallet deposit cancelled by user {user.id}: {order_id}")
        
    except Exception as e:
        logger.error(f"Error cancelling wallet deposit from QR: {e}")
        # Fallback: just send a simple message
        user_lang = await resolve_user_language(user.id, user.language_code) if user else 'en'
        await query.message.reply_text(f"❌ {t('errors.deposit_cancel_error', user_lang)}")

async def back_to_wallet_payment(query, order_id):
    """Return to wallet payment details from QR code"""
    user = query.from_user
    
    try:
        # Simply redirect to crypto selection instead of showing payment details
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Show the crypto selection page where users can choose different cryptocurrencies
        await show_wallet_deposit_options(query)
        
    except Exception as e:
        logger.error(f"Error returning to wallet payment: {e}")
        # Delete QR and show crypto selection on error too
        try:
            await query.message.delete()
            await show_wallet_deposit_options(query)
        except:
            pass  # If everything fails, just let it be

async def handle_qr_back_to_payment(query, domain_name):
    """Handle back to payment from domain QR code photo message"""
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Check if user has an active hosting intent for this domain (unified flow)
        try:
            user_record = await get_or_create_user(query.from_user.id)
            active_intent = await get_active_hosting_intent(user_record['id'], domain_name)
            
            if active_intent:
                # Back to hosting intent payment options (unified flow)
                intent_id = active_intent['id']
                price = float(active_intent['estimated_price'])
                plan_name = active_intent.get('plan_name', 'Hosting Plan')
                service_type = active_intent.get('service_type', 'hosting_new_domain')
                
                if service_type in ['hosting_new_domain', 'domain_hosting_bundle']:
                    items = [f"Register domain: {domain_name}", f"{plan_name} hosting"]
                else:
                    items = [f"{plan_name} hosting"]
                
                await show_unified_payment_options_with_intent(
                    query,
                    intent_id,
                    price,
                    plan_name,
                    domain_name,
                    items,
                    service_type
                )
                return
        except Exception as intent_error:
            logger.warning(f"Could not check hosting intent for {domain_name}: {intent_error}")
        
        # Fallback to domain-only registration flow
        await start_domain_registration(query, domain_name)
        
    except Exception as e:
        logger.error(f"Error handling QR back to payment for {domain_name}: {e}")
        # If deletion fails, try to continue anyway
        try:
            await start_domain_registration(query, domain_name)
        except:
            pass  # If everything fails, just let it be

async def handle_qr_cancel_order(query):
    """Handle cancel order from domain QR code photo message"""
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Call the original search domains function
        await show_search_interface(query)
        
    except Exception as e:
        logger.error(f"Error handling QR cancel order: {e}")
        # If deletion fails, try to continue anyway
        try:
            await show_search_interface(query)
        except:
            pass  # If everything fails, just let it be

async def check_wallet_deposit_status(query, order_id):
    """Check the status of a wallet deposit"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get user record
        user_record = await get_or_create_user(user.id)
        
        # Check wallet deposit status
        deposits = await execute_query(
            "SELECT * FROM wallet_deposits WHERE blockbee_order_id = %s AND user_id = %s",
            (order_id, user_record['id'])
        )
        
        if not deposits:
            await safe_edit_message(query, "❌ Deposit Not Found\n\nDeposit order not found.")
            return
            
        deposit = deposits[0]
        status = deposit['status']
        usd_amount = float(deposit['usd_amount'])
        crypto_currency = deposit['crypto_currency']
        
        if status == 'pending_payment':
            if usd_amount == 0:
                message = f"⏳ Pending\n\n{crypto_currency}:\n{deposit['payment_address']}\n\nSend any amount\n💡 Tap the address above to copy it"
            else:
                message = f"⏳ Pending\n\n{crypto_currency}:\n{deposit['payment_address']}\n\nSend ${usd_amount:.2f} USD\n💡 Tap the address above to copy it"
        elif status == 'confirming':
            message = f"🔄 Confirming\n\n${usd_amount:.2f} USD ({crypto_currency})\n\nWaiting for confirmations"
        elif status == 'completed':
            message = f"✅ Completed\n\n${usd_amount:.2f} USD credited"
        else:
            config = BrandConfig()
            message = f"❌ {status.title()}\n\nContact {config.support_contact}"
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.wallet", user_lang), callback_data="wallet_main")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="wallet_deposit")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error checking wallet deposit status: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not check deposit status.")

async def show_domain_management(query, domain_id):
    """Placeholder for domain management"""
    await safe_edit_message(query, f"⚙️ Domain management for ID {domain_id} coming soon...")

async def show_dns_management(query, domain_id):
    """Placeholder for DNS management"""
    await safe_edit_message(query, f"⚙️ Domain management for ID {domain_id} coming soon...")

async def handle_dns_callback(query, context, callback_data):
    """
    Handle DNS callbacks with standardized routing: dns:{domain}:{action}[:type][:id][:page]
    
    Actions:
    - view: Show DNS dashboard
    - add: Add new record (requires type)
    - edit: Edit existing record (requires id)
    - delete: Delete record (requires id)
    - list: List all records
    """
    try:
        # Enhanced logging for debugging
        user = query.from_user
        logger.info(f"DNS callback processing for user {user.id if user else 'unknown'}: {callback_data}")
        
        # Parse callback: dns:{domain}:{action}[:type][:id][:page]
        parts = callback_data.split(':')
        logger.info(f"DNS callback parts: {parts}")
        
        if len(parts) < 3:
            logger.warning(f"Invalid DNS callback - insufficient parts: {callback_data}")
            await safe_edit_message(query, "❌ Invalid DNS Action\n\nPlease try again.")
            return
        
        domain = parts[1]
        action = parts[2]
        logger.info(f"DNS action parsed - domain: {domain}, action: {action}")
        
        # Route to appropriate handler
        if action == "view":
            # Clear ALL DNS wizard state when navigating to dashboard (exit point)
            # This prevents cross-contamination between DNS operations and nameserver management
            clear_all_dns_wizard_state(context)
            await show_dns_dashboard(query, domain)
        elif action == "add" and len(parts) >= 4:
            record_type = parts[3]
            await start_dns_add_wizard(query, context, domain, record_type)
        elif action == "add":
            await show_dns_add_type_picker(query, domain)
        elif action == "list":
            page = int(parts[3]) if len(parts) >= 4 and parts[3].isdigit() else 1
            await show_dns_record_list(query, domain, page)
        elif action == "record" and len(parts) >= 4:
            record_id = parts[3]
            await show_dns_record_detail(query, domain, record_id)
        elif action == "edit" and len(parts) >= 4:
            record_id = parts[3]
            # Store edit context for simplified callback routing
            context.user_data['edit_context'] = {
                'domain': domain,
                'record_id': record_id
            }
            await start_dns_edit_wizard(query, context, domain, record_id)
        elif action == "delete" and len(parts) >= 4:
            record_id = parts[3]
            if len(parts) >= 5 and parts[4] == "confirm":
                await execute_dns_delete(query, context, domain, record_id)
            else:
                await confirm_dns_delete(query, context, domain, record_id)
        elif action == "nameservers":
            # Clear ALL DNS wizard state when entering nameserver management
            clear_all_dns_wizard_state(context)
            await show_nameserver_management(query, domain, context)
        elif action == "security":
            if len(parts) >= 4:
                setting_action = parts[3]
                if setting_action == "js_challenge" and len(parts) >= 5:
                    action = parts[4]
                    if action == "confirm_proxy" and len(parts) >= 6 and parts[5] == "on":
                        # User confirmed proxy enablement for JavaScript Challenge
                        await force_enable_proxy_and_feature(query, domain, "js_challenge")
                    else:
                        await toggle_javascript_challenge(query, domain, action)
                elif setting_action == "force_https" and len(parts) >= 5:
                    action_type = parts[4]  # This will be "on", "off", "toggle", or "confirm_proxy"
                    if action_type == "confirm_proxy" and len(parts) >= 6 and parts[5] == "on":
                        # User confirmed proxy enablement for Force HTTPS
                        await force_enable_proxy_and_feature(query, domain, "force_https")
                    else:
                        await toggle_force_https_setting(query, domain, action_type)
                elif setting_action == "auto_proxy" and len(parts) >= 5:
                    action_type = parts[4]  # This will be "on", "off", or "toggle"
                    await toggle_auto_proxy_setting(query, domain, action_type)
                else:
                    await show_security_settings(query, domain)
            else:
                await show_security_settings(query, domain)
        elif action == "ns_to_cloudflare":
            if len(parts) >= 4 and parts[3] == "confirm":
                await execute_switch_to_cloudflare_ns(query, context, domain)
            else:
                await confirm_switch_to_cloudflare_ns(query, domain)
        elif action == "ns_update" and len(parts) >= 4:
            ns_data = parts[3]  # This will be a compressed callback token
            await execute_nameserver_update(query, context, domain, ns_data)
        else:
            logger.warning(f"Unknown DNS action '{action}' for domain '{domain}' in callback: {callback_data}")
            await safe_edit_message(query, "❌ Unknown DNS Action\n\nPlease try again.")
            
    except Exception as e:
        logger.error(f"Error handling DNS callback {callback_data}: {e}")
        await safe_edit_message(query, "❌ DNS Error\n\nCould not process action. Please try again.")

async def handle_setup_dns_zone(query, context, domain_name):
    """Handle DNS zone setup for domains missing Cloudflare zones"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Show progress message
    await safe_edit_message(query, t('domain.setup_dns_progress', user_lang, domain=domain_name))
    
    try:
        # Verify user owns the domain
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Create Cloudflare zone
        from services.cloudflare import CloudflareService
        cloudflare = CloudflareService()
        
        zone_result = await cloudflare.create_zone(domain_name, standalone=True)
        
        if zone_result and zone_result.get('success'):
            zone_data = zone_result['result']
            nameservers = zone_data.get('name_servers', [])
            ns_display = '\n'.join(nameservers)
            
            # Show success message with nameservers
            message = t('domain.setup_dns_success', user_lang, domain=domain_name, nameservers=ns_display)
            keyboard = [
                [InlineKeyboardButton(t("buttons.manage_dns", user_lang), callback_data=f"dns:{domain_name}:view")],
                [InlineKeyboardButton(t("buttons.my_domains", user_lang), callback_data="my_domains")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
        else:
            # Zone creation failed
            message = t('domain.setup_dns_failed', user_lang, domain=domain_name)
            keyboard = [
                [InlineKeyboardButton(t("buttons.contact_support", user_lang), callback_data="contact_support")],
                [InlineKeyboardButton(t("buttons.my_domains", user_lang), callback_data="my_domains")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
    except Exception as e:
        logger.error(f"Error setting up DNS zone for {domain_name}: {e}")
        import traceback
        traceback.print_exc()
        
        message = t('domain.setup_dns_failed', user_lang, domain=domain_name)
        keyboard = [
            [InlineKeyboardButton(t("buttons.contact_support", user_lang), callback_data="contact_support")],
            [InlineKeyboardButton(t("buttons.my_domains", user_lang), callback_data="my_domains")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_dns_dashboard(query, domain_name):
    """Show enhanced DNS dashboard with record counts and clear actions"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Immediate response for better UX with unique identifier
    await safe_edit_message(query, t('dns.dashboard_loading', user_lang, domain=domain_name))
    
    try:
        user_record = await get_or_create_user(user.id)
        
        # Check if user owns this domain
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            message = t('domain.dns_unavailable', user_lang, domain=domain_name)
            message += f"\n\n{t('domain.setup_dns_prompt', user_lang)}"
            keyboard = [
                [InlineKeyboardButton(t("buttons.setup_dns_zone", user_lang), callback_data=f"setup_dns_{domain_name}")],
                [InlineKeyboardButton(t("buttons.my_domains", user_lang), callback_data="my_domains")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            return
        
        # Get current DNS records and nameserver info
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        # Get nameservers from database first (reflects actual registrar config)
        nameservers = await get_domain_nameservers(domain_name)
        
        # Fallback to Cloudflare API if no stored nameservers exist
        if not nameservers:
            zone_info = await cloudflare.get_zone_info(zone_id)
            nameservers = zone_info.get('name_servers', []) if zone_info else []
            logger.info(f"Using Cloudflare API nameservers for {domain_name} (no stored nameservers found)")
        else:
            logger.info(f"Using stored nameservers for {domain_name}: {nameservers}")
        
        # Detect nameserver provider and format display
        provider_type, provider_name = detect_nameserver_provider(nameservers)
        nameserver_display = format_nameserver_display(nameservers, max_display=2)
        
        # Provider status indicator - simplified
        if provider_type == "cloudflare":
            provider_status = "Cloudflare"
        elif provider_type == "external":
            provider_status = f"{provider_name}"
        else:
            provider_status = "Unknown Provider"
        
        # Only fetch and display DNS records if using Cloudflare nameservers
        record_counts = {}
        preview_records = []
        dns_records = []
        
        if provider_type == "cloudflare":
            # DATABASE-FIRST PATTERN: Check database before calling Cloudflare API
            # CRITICAL FIX: Fetch from database instead of always calling API
            # Database stores the DNS records and prevents stale data display
            from database import get_dns_records_from_db, save_dns_records_to_db
            
            # Step 1: Try to get DNS records from database first (source of truth)
            db_records = await get_dns_records_from_db(domain_name)
            
            if db_records:
                # Database hit - convert database format to API format for display
                dns_records = []
                for db_record in db_records:
                    dns_records.append({
                        'type': db_record.get('record_type', 'Unknown'),
                        'name': db_record.get('name', 'Unknown'),
                        'content': db_record.get('content', 'Unknown'),
                        'ttl': db_record.get('ttl', 300),
                        'priority': db_record.get('priority'),
                        'id': db_record.get('cloudflare_record_id', ''),
                        'proxied': False  # Default, can be enhanced later
                    })
                logger.info(f"📦 DNS DASHBOARD: Using {len(dns_records)} records from database for {domain_name}")
            else:
                # Database miss - fall back to Cloudflare API
                logger.info(f"🔄 DNS DASHBOARD: Database empty, fetching from Cloudflare API for {domain_name}")
                dns_records = await cloudflare.list_dns_records(zone_id)
                
                # Step 3: Save API data to database for future lookups
                if dns_records:
                    await save_dns_records_to_db(domain_name, dns_records)
                    logger.info(f"💾 DNS DASHBOARD: Saved {len(dns_records)} records to database for {domain_name}")
            
            # Count records by type and show ALL records (not just preview)
            for record in dns_records:
                record_type = record.get('type', 'Unknown')
                record_counts[record_type] = record_counts.get(record_type, 0) + 1
                name = record.get('name', 'Unknown')
                content = record.get('content', 'Unknown')
                # Show all records in dashboard
                preview_records.append(f"• {record_type}: {name} → {content}")
        
        # Format record summary based on nameserver provider - simplified
        if provider_type == "cloudflare":
            if record_counts:
                # Clean summary without "Records:" prefix
                counts_text = ", ".join([f"{count} {rtype}" for rtype, count in record_counts.items()])
                records_summary = counts_text
                if preview_records:
                    records_summary += "\n\n" + "\n".join(preview_records)
            else:
                records_summary = t('dns.dashboard_no_records', user_lang)
        else:
            records_summary = t('dns.dashboard_managed_by', user_lang, provider=provider_name)
        
        message = f"""{t('dns.dashboard_title', user_lang, domain=domain_name)}

{t('dns.dashboard_status', user_lang)}
{t('dns.dashboard_provider', user_lang, provider=provider_status)}

{t('dns.dashboard_nameservers', user_lang)}
{nameserver_display}

{records_summary}"""
        
        # Build keyboard with conditional DNS record management options
        keyboard = []
        
        # Only show Add Record and List All buttons if using Cloudflare nameservers
        if provider_type == "cloudflare":
            keyboard.append([
                InlineKeyboardButton(t("buttons.add_record", user_lang), callback_data=f"dns:{domain_name}:add"),
                InlineKeyboardButton(t("buttons.list_all", user_lang), callback_data=f"dns:{domain_name}:list")
            ])
            keyboard.append([
                InlineKeyboardButton(t("buttons.security_settings", user_lang), callback_data=f"dns:{domain_name}:security")
            ])
        
        # Always show nameserver management
        keyboard.append([InlineKeyboardButton(t("buttons.manage_nameservers", user_lang), callback_data=f"dns:{domain_name}:nameservers")])
        
        # Add conditional nameserver options based on current provider
        if provider_type != "cloudflare":
            keyboard.append([InlineKeyboardButton(t("buttons.switch_to_cloudflare_ns", user_lang), callback_data=f"dns:{domain_name}:ns_to_cloudflare")])
        
        keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data="my_domains")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing DNS dashboard for {domain_name}: {e}")
        error_message = t('dns.dashboard_error', user_lang, domain=domain_name, error=str(e)[:100])
        await safe_edit_message(query, error_message)

async def show_dns_add_type_picker(query, domain):
    """Show record type picker for adding new DNS records"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"{t('dns.add_record_title', user_lang, domain=domain)}\n\n{t('dns.add_record_prompt', user_lang)}"
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.a_record", user_lang), callback_data=smart_dns_callback(domain, "add:A")),
         InlineKeyboardButton(t("buttons.cname", user_lang), callback_data=smart_dns_callback(domain, "add:CNAME"))],
        [InlineKeyboardButton(t("buttons.txt_record", user_lang), callback_data=smart_dns_callback(domain, "add:TXT")),
         InlineKeyboardButton(t("buttons.mx_record", user_lang), callback_data=smart_dns_callback(domain, "add:MX"))],
        [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=smart_dns_callback(domain, "view"))]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def start_dns_add_wizard(query, context, domain, record_type):
    """Start the DNS record addition wizard"""
    user = query.from_user
    
    # Initialize wizard state in context.user_data
    wizard_state = {
        'domain': domain,
        'action': 'add',
        'type': record_type,
        'step': 1,
        'data': {}
    }
    
    # Store wizard state for this user
    context.user_data['dns_wizard'] = wizard_state
    
    if record_type == "A":
        await continue_a_record_wizard(query, context, wizard_state)
    elif record_type == "CNAME":
        await continue_cname_record_wizard(query, context, wizard_state)
    elif record_type == "TXT":
        await continue_txt_record_wizard(query, context, wizard_state)
    elif record_type == "MX":
        await continue_mx_record_wizard(query, context, wizard_state)
    else:
        await safe_edit_message(query, f"🚧 {record_type} Wizard\n\nComing soon!")

async def continue_dns_add_wizard(query, domain, record_type, step):
    """Continue the DNS addition wizard at specified step"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    flow_id = f"{user.id}_{domain}_{record_type}"
    
    # Initialize default values to prevent LSP "possibly unbound" warnings
    message = f"🚧 {record_type} Record Wizard\n\nComing soon!"
    keyboard = [[InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add")]]
    
    if record_type == "A":
        if step == 1:
            message = f"""
🅰️ Add A Record (1/4): {domain}

Enter the name/host for this A record.

Current: Root domain (@)
"""
            keyboard = [
                [InlineKeyboardButton(t("buttons.use_root", user_lang), callback_data=f"dns_wizard:{domain}:A:name:@")],
                [InlineKeyboardButton(t("buttons.use_www", user_lang), callback_data=f"dns_wizard:{domain}:A:name:www")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add")]
            ]
        elif step == 2:
            message = f"""
🅰️ Add A Record (2/4): {domain}

Enter the IPv4 address this record should point to.

Please type the IP address:
"""
            keyboard = [
                [InlineKeyboardButton(t("buttons.use_8_8_8_8", user_lang), callback_data=f"dns_wizard:{domain}:A:ip:8.8.8.8")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add:A")]
            ]
    # Add more record types here...
    else:
        message = t('dns.wizard_coming_soon', user_lang, type=record_type)
        keyboard = [[InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add")]]
    
    # Ensure variables are always defined (remove problematic locals() checks)
    # Variables are already defined in all code paths above
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def show_dns_record_list(query, domain, page=1):
    """Show paginated list of DNS records"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Immediate response for better UX
    await safe_edit_message(query, t('dns.loading_records', user_lang))
    
    try:
        user_record = await get_or_create_user(user.id)
        
        # Check domain ownership
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, t('dns.access_denied', user_lang))
            return
        
        # Get DNS records using DATABASE-FIRST PATTERN
        # CRITICAL FIX: Check database before calling Cloudflare API
        # Database stores the DNS records and prevents stale data display
        from database import get_dns_records_from_db, save_dns_records_to_db
        
        # Step 1: Try to get DNS records from database first (source of truth)
        db_records = await get_dns_records_from_db(domain)
        
        if db_records:
            # Database hit - convert database format to API format for display
            all_records = []
            for db_record in db_records:
                all_records.append({
                    'type': db_record.get('record_type', 'Unknown'),
                    'name': db_record.get('name', 'Unknown'),
                    'content': db_record.get('content', 'Unknown'),
                    'ttl': db_record.get('ttl', 300),
                    'priority': db_record.get('priority'),
                    'id': db_record.get('cloudflare_record_id', ''),
                    'proxied': False  # Default, can be enhanced later
                })
            logger.info(f"📦 DNS RECORD LIST: Using {len(all_records)} records from database for {domain}")
        else:
            # Database miss - fall back to Cloudflare API
            cf_zone = await get_cloudflare_zone(domain)
            if not cf_zone:
                await safe_edit_message(query, t('domain.dns_unavailable', user_lang, domain=domain))
                return
            
            logger.info(f"🔄 DNS RECORD LIST: Database empty, fetching from Cloudflare API for {domain}")
            cloudflare = CloudflareService()
            all_records = await cloudflare.list_dns_records(cf_zone['cf_zone_id'])
            
            # Step 3: Save API data to database for future lookups
            if all_records:
                await save_dns_records_to_db(domain, all_records)
                logger.info(f"💾 DNS RECORD LIST: Saved {len(all_records)} records to database for {domain}")
        
        # Paginate records (8 per page)
        per_page = 8
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        records = all_records[start_idx:end_idx]
        total_pages = (len(all_records) + per_page - 1) // per_page
        
        if not all_records:
            message = f"""{t('dns.records_list_title', user_lang, domain=domain)}

{t('dns.no_records_found', user_lang)}

{t('dns.get_started_add_record', user_lang)}
"""
            keyboard = [
                [InlineKeyboardButton(t("buttons.add_record", user_lang), callback_data=smart_dns_callback(domain, "add"))],
                [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=smart_dns_callback(domain, "view"))]
            ]
        else:
            message = f"""{t('dns.records_list_title_paginated', user_lang, domain=domain, page=page, total_pages=total_pages)}

{t('dns.total_records', user_lang, count=len(all_records))}

"""
            keyboard = []
            
            for record in records:
                record_type = record.get('type', 'Unknown')
                name = record.get('name', 'Unknown')
                content = record.get('content', 'Unknown')[:30]  # Truncate long content
                if len(record.get('content', '')) > 30:
                    content += "..."
                proxied = "🟠" if record.get('proxied') else "⚪"
                
                message += f"• {record_type} {name} → {content} {proxied}\n"
                
                # Add record button with short callback to avoid Telegram's 64-byte limit
                record_id = record.get('id', '')
                short_callback = create_short_dns_callback(domain, record_id)
                keyboard.append([InlineKeyboardButton(f"⚙️ {record_type}: {name}", callback_data=short_callback)])
            
            # Navigation buttons
            nav_buttons = []
            if page > 1:
                nav_buttons.append(InlineKeyboardButton(t("buttons.previous", user_lang), callback_data=smart_dns_callback(domain, f"list:{page-1}")))
            if page < total_pages:
                nav_buttons.append(InlineKeyboardButton(t("buttons.next", user_lang), callback_data=smart_dns_callback(domain, f"list:{page+1}")))
            
            if nav_buttons:
                keyboard.append(nav_buttons)
            
            keyboard.extend([
                [InlineKeyboardButton(t("buttons.add_record", user_lang), callback_data=smart_dns_callback(domain, "add"))],
                [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=smart_dns_callback(domain, "view"))]
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing DNS record list: {e}")
        await safe_edit_message(query, t('dns.load_records_error', user_lang))

async def show_dns_record_detail(query, domain, record_id):
    """Show details for a specific DNS record with edit/delete options"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # Immediate response for better UX with unique identifier  
    await safe_edit_message(query, t('dns.record_detail_loading', user_lang, domain=domain, id=record_id[:8]))
    
    try:
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, t('dns.access_denied', user_lang))
            return
        
        # Get the specific DNS record using DATABASE-FIRST PATTERN
        # CRITICAL FIX: Check database before calling Cloudflare API
        # Database stores the DNS records and prevents stale data display
        from database import get_dns_record_from_db, get_dns_records_from_db, save_dns_records_to_db
        
        # Step 1: Try to get DNS record from database first (source of truth)
        db_record = await get_dns_record_from_db(record_id)
        
        if db_record:
            # Database hit - convert database format to API format for display
            record = {
                'type': db_record.get('record_type', 'Unknown'),
                'name': db_record.get('name', 'Unknown'),
                'content': db_record.get('content', 'Unknown'),
                'ttl': db_record.get('ttl', 300),
                'priority': db_record.get('priority'),
                'id': db_record.get('cloudflare_record_id', ''),
                'proxied': False  # Default, can be enhanced later
            }
            logger.info(f"📦 DNS RECORD DETAIL: Using record {record_id[:8]}... from database for {domain}")
        else:
            # Database miss - fall back to Cloudflare API
            cf_zone = await get_cloudflare_zone(domain)
            if not cf_zone:
                await safe_edit_message(query, t('domain.dns_unavailable', user_lang, domain=domain))
                return
            
            logger.info(f"🔄 DNS RECORD DETAIL: Database miss, fetching from Cloudflare API for {domain}")
            cloudflare = CloudflareService()
            zone_id = cf_zone['cf_zone_id']
            record = await cloudflare.get_dns_record(zone_id, record_id)
            
            if not record:
                await safe_edit_message(query, "❌ Record Not Found\n\nThe DNS record could not be found.")
                return
            
            # Step 3: Save this single record to database for future lookups
            # We save it as part of a full refresh to maintain consistency
            all_records = await cloudflare.list_dns_records(zone_id)
            if all_records:
                await save_dns_records_to_db(domain, all_records)
                logger.info(f"💾 DNS RECORD DETAIL: Saved {len(all_records)} records to database for {domain}")
        
        # Format record details
        record_type = record.get('type', 'Unknown')
        name = record.get('name', 'Unknown')
        content = record.get('content', 'Unknown')
        ttl = record.get('ttl', 'Auto')
        proxied = record.get('proxied', False)
        priority = record.get('priority', None)
        
        # Display TTL nicely
        if ttl == 1:
            ttl_display = t('dns.record_detail.ttl_auto', user_lang)
        elif ttl < 3600:
            ttl_display = t('dns.record_detail.ttl_seconds', user_lang, value=ttl)
        elif ttl < 86400:
            ttl_display = t('dns.record_detail.ttl_hours', user_lang, value=ttl // 3600)
        else:
            ttl_display = t('dns.record_detail.ttl_days', user_lang, value=ttl // 86400)
        
        proxy_display = t('dns.record_detail.proxy_on', user_lang) if proxied else t('dns.record_detail.proxy_off', user_lang)
        
        message = f"""{t('dns.record_detail.title', user_lang)}

{t('dns.record_detail.domain', user_lang)} {domain}
{t('dns.record_detail.type', user_lang)} {record_type}
{t('dns.record_detail.name', user_lang)} {name}
{t('dns.record_detail.content', user_lang)} {content}
{t('dns.record_detail.ttl', user_lang)} {ttl_display}
{t('dns.record_detail.proxy', user_lang)} {proxy_display}
"""
        
        # Add priority for MX records
        if record_type == 'MX' and priority:
            message += f"{t('dns.record_detail.priority', user_lang)} {priority}\n"
        
        message += f"""
{t('dns.record_detail.record_id', user_lang)} {record_id}

{t('dns.record_detail.actions', user_lang)}
"""
        
        # Use short callbacks to avoid Telegram's 64-byte limit
        edit_callback = create_short_dns_callback(domain, record_id, "edit")
        delete_callback = create_short_dns_callback(domain, record_id, "delete")
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.edit_record", user_lang), callback_data=edit_callback),
             InlineKeyboardButton(t("buttons.delete_record", user_lang), callback_data=delete_callback)],
            [InlineKeyboardButton(t("buttons.records_label", user_lang), callback_data=smart_dns_callback(domain, "list"))],
            [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=smart_dns_callback(domain, "view"))]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing DNS record detail for {domain}/{record_id}: {e}")
        error_message = t('dns.record_load_error', user_lang, id=f"<code>{escape_html(record_id[:8])}...</code>", domain=f"<code>{escape_html(domain)}</code>", error=escape_html(str(e)[:100]))
        await safe_edit_message(query, error_message)

async def start_dns_edit_wizard(query, context, domain, record_id):
    """Start DNS record editing wizard with pre-filled values"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone and record
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        record = await cloudflare.get_dns_record(zone_id, record_id)
        
        if not record:
            await safe_edit_message(query, t('dns.record_not_found', user_lang))
            return
        
        # Initialize edit wizard state with current values
        record_type = record.get('type', '').upper()
        current_name = record.get('name', '')
        current_content = record.get('content', '')
        current_ttl = record.get('ttl', 300)  # Keep as integer for proper type comparison
        current_proxied = 'true' if record.get('proxied', False) else 'false'
        current_priority = record.get('priority', 10) if record_type == 'MX' else None
        
        # Store edit wizard state
        context.user_data['dns_wizard'] = {
            'domain': domain,
            'action': 'edit',
            'type': record_type,
            'record_id': record_id,
            'step': 1,
            'data': {
                'name': current_name,
                'content': current_content,
                'ttl': current_ttl,
                'proxied': current_proxied,
                'priority': current_priority
            },
            'original_data': {
                'name': current_name,
                'content': current_content,
                'ttl': current_ttl,
                'proxied': current_proxied,
                'priority': current_priority
            }
        }
        
        # Add timestamp to prevent caching issues
        context.user_data['dns_wizard']['timestamp'] = int(time.time())
        
        # Start edit wizard for the specific record type
        if record_type == "A":
            await continue_a_record_edit_wizard(query, context, context.user_data['dns_wizard'])
        elif record_type == "CNAME":
            await continue_cname_record_edit_wizard(query, context.user_data['dns_wizard'])
        elif record_type == "TXT":
            await continue_txt_record_edit_wizard(query, context.user_data['dns_wizard'])
        elif record_type == "MX":
            await continue_mx_record_edit_wizard(query, context.user_data['dns_wizard'])
        else:
            await safe_edit_message(query, f"✏️ <b>Edit {escape_html(record_type)} Record</b>\n\nEditing {escape_html(record_type)} records is not yet supported. You can delete and recreate the record instead.")
            
    except Exception as e:
        logger.error(f"Error starting DNS edit wizard: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not start edit wizard.")

async def confirm_dns_delete(query, context, domain, record_id):
    """Confirm DNS record deletion with safety checks"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone and record details
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        record = await cloudflare.get_dns_record(zone_id, record_id)
        
        if not record:
            await safe_edit_message(query, t('dns.record_not_found', user_lang))
            return
        
        # Format record details for confirmation
        record_type = record.get('type', 'Unknown')
        name = record.get('name', 'Unknown')
        content = record.get('content', 'Unknown')
        
        message = f"""{t('dns.delete_confirmation.title', user_lang)}

{t('dns.delete_confirmation.warning', user_lang)}

{t('dns.delete_confirmation.domain', user_lang)} {domain}
{t('dns.delete_confirmation.type', user_lang)} {record_type}
{t('dns.delete_confirmation.name', user_lang)} {name}
{t('dns.delete_confirmation.content', user_lang)} {content}

{t('dns.delete_confirmation.question', user_lang)}

{t('dns.delete_confirmation.immediate_removal', user_lang)}
"""
        
        # Store domain context for delete callback to avoid Telegram's 64-byte limit
        context.user_data['delete_context'] = {'domain': domain, 'record_id': record_id}
        
        # Use short callbacks to avoid Telegram's 64-byte limit
        cancel_callback = create_short_dns_callback(domain, record_id, "record")
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=cancel_callback)],
            [InlineKeyboardButton(t("buttons.yes_delete_record", user_lang), callback_data=f"del:{record_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error confirming DNS record deletion: {e}")
        await safe_edit_message(query, t('dns.load_record_error', user_lang))

async def execute_dns_delete(query, context, domain, record_id):
    """Execute DNS record deletion"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, t('dns.access_denied', user_lang))
            return
        
        # Get Cloudflare zone
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, t('dns.dns_unavailable', user_lang, domain=domain))
            return
        
        # Show deleting message
        await safe_edit_message(query, t('dns.deleting_record', user_lang))
        
        # Get record info before deletion for confirmation message
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        record = await cloudflare.get_dns_record(zone_id, record_id)
        
        if not record:
            await safe_edit_message(query, t('dns.record_not_found', user_lang))
            return
        
        record_type = record.get('type', 'Unknown')
        name = record.get('name', 'Unknown')
        
        # Delete the DNS record
        success = await cloudflare.delete_dns_record(zone_id, record_id)
        
        if success:
            # Remove the specific record from database (no race conditions)
            try:
                from database import delete_single_dns_record_from_db
                await delete_single_dns_record_from_db(record_id)
                logger.debug(f"✅ DNS record removed from database: {record_id}")
            except Exception as db_err:
                logger.warning(f"Failed to remove DNS record from database: {db_err}")
                # Don't fail - Cloudflare deletion succeeded
            
            # Success message
            message = t('dns.delete_success', user_lang, domain=domain, type=record_type, name=name)
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.view_remaining_records", user_lang), callback_data=f"dns:{domain}:list")],
                [InlineKeyboardButton(t("buttons.add_new_record", user_lang), callback_data=f"dns:{domain}:add")],
                [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=f"dns:{domain}:view")]
            ]
        else:
            # Error message
            message = t('dns.delete_failed', user_lang, domain=domain, type=record_type, name=name)
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"dns:{domain}:delete:{record_id}")],
                [InlineKeyboardButton(t("buttons.back_to_record", user_lang), callback_data=f"dns:{domain}:record:{record_id}")],
                [InlineKeyboardButton(t("buttons.dashboard", user_lang), callback_data=f"dns:{domain}:view")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error executing DNS record deletion: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not delete DNS record. Please try again.")

def clear_dns_wizard_custom_subdomain_state(context):
    """
    Clear custom subdomain input flags to prevent text handler interference.
    
    This is called at ALL exit points from the DNS wizard to ensure no orphaned flags remain:
    - Wizard completion (success/error)
    - Dashboard/view navigation
    - Back navigation
    - Cancel buttons
    """
    if 'expecting_custom_subdomain' in context.user_data:
        del context.user_data['expecting_custom_subdomain']
    if 'expecting_custom_subdomain_a' in context.user_data:
        del context.user_data['expecting_custom_subdomain_a']
    if 'expecting_custom_subdomain_txt' in context.user_data:
        del context.user_data['expecting_custom_subdomain_txt']

def clear_all_dns_wizard_state(context):
    """
    Clear ALL DNS wizard and nameserver management state to prevent cross-contamination.
    
    CRITICAL: This prevents the nameserver update "invalid IP address" bug that occurs when:
    1. User deletes an A record (dns_wizard state with record_type='A' remains)
    2. User navigates to nameserver management (expecting_nameserver_input is set)
    3. User enters nameservers (e.g., ns1.example.com)
    4. Text handler incorrectly processes nameserver input through A record wizard
    5. Nameserver domains fail IP validation → "Invalid IP address" error
    
    This function ensures complete state cleanup on:
    - /start command
    - Back button navigation to DNS dashboard
    - Entering nameserver management
    - DNS record deletion
    - Any other DNS navigation
    """
    # Clear DNS wizard state
    if 'dns_wizard' in context.user_data:
        del context.user_data['dns_wizard']
    
    # Clear custom subdomain flags
    if 'expecting_custom_subdomain' in context.user_data:
        del context.user_data['expecting_custom_subdomain']
    if 'expecting_custom_subdomain_a' in context.user_data:
        del context.user_data['expecting_custom_subdomain_a']
    if 'expecting_custom_subdomain_txt' in context.user_data:
        del context.user_data['expecting_custom_subdomain_txt']
    
    # Clear nameserver input flag
    if 'expecting_nameserver_input' in context.user_data:
        del context.user_data['expecting_nameserver_input']
    
    # CRITICAL: This prevents the nameserver update "invalid IP address" bug
    if context and context.user_data:
        # Clear custom subdomain flag for MX
        if 'expecting_custom_subdomain_mx' in context.user_data:
            del context.user_data['expecting_custom_subdomain_mx']
    
    # Clear edit input context
    if 'edit_input' in context.user_data:
        del context.user_data['edit_input']

async def handle_dns_wizard_callback(query, context, callback_data):
    """Handle DNS wizard step callbacks: dns_wizard:{domain}:{type}:{field}:{value}"""
    user = query.from_user
    
    try:
        # Parse: dns_wizard:{domain}:{type}:{field}:{value}
        parts = callback_data.split(':', 4)
        if len(parts) < 5:
            await safe_edit_message(query, create_error_message("Invalid wizard step"))
            return
        
        domain = parts[1]
        record_type = parts[2]
        field = parts[3]
        value = parts[4]
        
        # Get or initialize wizard state from context
        wizard_state = context.user_data.get('dns_wizard', {
            'domain': domain,
            'action': 'add',
            'type': record_type,
            'step': 1,
            'data': {}
        })
        
        # Update wizard data with new field value
        if field == "create" and value == "confirm":
            # Final step - create the DNS record
            await create_dns_record_from_wizard(query, context, wizard_state)
            return
        elif value == "back":
            # Handle back navigation by removing the last field
            # A Record back navigation
            if field == "name" and record_type == "A":
                # Going back from A name step - clear wizard completely
                wizard_state['data'] = {}
            elif field == "ip" and 'name' in wizard_state['data']:
                del wizard_state['data']['name']
            elif field == "ttl" and 'ip' in wizard_state['data']:
                del wizard_state['data']['ip']
            elif field == "proxied" and 'ttl' in wizard_state['data']:
                del wizard_state['data']['ttl']
            # TXT Record back navigation
            elif field == "name" and record_type == "TXT":
                # Going back from TXT name step - clear wizard completely
                wizard_state['data'] = {}
            elif field == "content" and 'name' in wizard_state['data']:
                del wizard_state['data']['name']
            elif field == "ttl" and 'content' in wizard_state['data']:
                del wizard_state['data']['content']
            # CNAME Record back navigation  
            elif field == "name" and record_type == "CNAME":
                # Going back from CNAME name step - clear wizard completely
                wizard_state['data'] = {}
            elif field == "target" and 'name' in wizard_state['data']:
                del wizard_state['data']['name']
            elif field == "ttl" and 'target' in wizard_state['data']:
                del wizard_state['data']['target']
            # MX Record back navigation
            elif field == "name" and record_type == "MX":
                # Going back from MX name step - clear wizard completely  
                wizard_state['data'] = {}
                # Clear custom subdomain flag
                if 'expecting_custom_subdomain_mx' in context.user_data:
                    del context.user_data['expecting_custom_subdomain_mx']
            elif field == "server" and 'name' in wizard_state['data']:
                del wizard_state['data']['name']
            elif field == "priority" and 'server' in wizard_state['data']:
                del wizard_state['data']['server']
            elif field == "ttl" and 'priority' in wizard_state['data']:
                del wizard_state['data']['priority']
            elif field == "create" and 'ttl' in wizard_state['data']:
                del wizard_state['data']['ttl']
            
            # Clear custom subdomain input flags on back navigation
            clear_dns_wizard_custom_subdomain_state(context)
        else:
            # Initialize data if missing
            if 'data' not in wizard_state:
                wizard_state['data'] = {}
            
            # CRITICAL: Store the field value directly in the source object
            wizard_state['data'][field] = value
            
            # Log exact assignment
            logger.info(f"DNS Wizard: Set {field} = {value} in wizard_state['data']")
            
            # Ensure bot_message_id is preserved for editing
            if hasattr(query, 'message') and query.message:
                wizard_state['bot_message_id'] = query.message.message_id
            
            # CRITICAL FIX: Force update the reference in context.user_data
            context.user_data['dns_wizard'] = wizard_state
            
            # Log state update for debugging
            logger.info(f"Wizard state persisted to user_data: {context.user_data['dns_wizard'].get('data')}")
            
            # Ensure local record_type is updated from the state
            record_type = wizard_state.get('type', record_type)
        
        # Continue to next step based on record type
        logger.info(f"DNS Wizard: Moving to continuation for {record_type} with data {wizard_state.get('data')}")
        
        if record_type == "A":
            await continue_a_record_wizard(query, context, wizard_state)
        elif record_type == "CNAME":
            await continue_cname_record_wizard(query, context, wizard_state)
        elif record_type == "TXT":
            await continue_txt_record_wizard(query, context, wizard_state)
        elif record_type == "MX":
            # For MX priority field, we need to handle it before continuing
            if field == "priority":
                try:
                    wizard_state['data']['priority'] = int(value)
                    context.user_data['dns_wizard'] = wizard_state
                except (ValueError, TypeError):
                    logger.warning(f"Invalid priority value in MX wizard: {value}")
            
            # Pass the most current state directly
            current_state = context.user_data.get('dns_wizard', wizard_state)
            logger.info(f"MX Wizard transition - data: {current_state.get('data')}")
            await continue_mx_record_wizard(query, context, current_state)
        else:
            await safe_edit_message(query, create_error_message(f"Unknown record type: {record_type}"))
            
    except Exception as e:
        logger.error(f"Error in DNS wizard callback: {e}")
        await safe_edit_message(query, "❌ <b>Wizard error</b>\n\nPlease try again.")

async def continue_a_record_wizard(query, context, wizard_state):
    """Continue A record wizard based on current data"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    # Handle custom subdomain input prompt
    if data.get('name') == 'custom':
        message = f"""
✏️ <b>Custom Subdomain for {domain}</b>

Examples: www, api, server-1
(Use @ for root domain)

Letters/numbers/hyphens only, 1-63 chars
Cannot start/end with hyphen

Type your subdomain:
"""
        keyboard = [
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:name:back")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context to expect custom subdomain input
        context.user_data['expecting_custom_subdomain_a'] = {
            'domain': domain,
            'wizard_state': wizard_state
        }
        return
    
    if 'name' not in data:
        # Step 1: Dynamic Name Selection for A Record
        # Get Cloudflare zone to check existing records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ {t('dns.dns_unavailable_title', user_lang)}\n\n{t('dns.no_zone_for', user_lang, domain=domain)}")
            return
            
        # Get available names for A records
        available_names = await get_available_names_for_record_type(domain, 'A', cf_zone['cf_zone_id'])
        
        if not available_names:
            await safe_edit_message(query, 
                f"❌ <b>{t('domain.sections.no_available_names', user_lang)}</b>\n\n"
                f"{t('domain.sections.all_cname_conflict', user_lang)}\n\n"
                f"{t('domain.sections.delete_cname_or_use_different', user_lang)}"
            )
            return
            
        message = f"🅰️ {t('dns_wizard.a_record_title', user_lang, step=1, domain=domain)}\n\n{t('dns_wizard.choose_name', user_lang)}"
        
        # Create dynamic buttons
        keyboard = []
        row = []
        for name_info in available_names[:6]:  # Limit to first 6 options
            button_text = f"{name_info['display']}"
            row.append(InlineKeyboardButton(button_text, callback_data=f"dns_wizard:{domain}:A:name:{name_info['name']}"))
            if len(row) == 2:  # 2 buttons per row
                keyboard.append(row)
                row = []
        if row:  # Add remaining buttons
            keyboard.append(row)
        
        # Add custom subdomain option
        keyboard.append([InlineKeyboardButton(t("buttons.custom_subdomain", user_lang), callback_data=f"dns_wizard:{domain}:A:name:custom")])
        keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add")])
    elif 'ip' not in data:
        # Step 2: IP Address
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"🅰️ {t('dns_wizard.a_record_title', user_lang, step=2, domain=domain)}\n\n" \
                  f"{t('common_labels.name', user_lang)}: {name_display}\n\n" \
                  f"{t('dns_wizard.enter_ipv4', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(t("buttons.use_8_8_8_8", user_lang), callback_data=f"dns_wizard:{domain}:A:ip:8.8.8.8")],
            [InlineKeyboardButton(t("buttons.use_1_1_1_1", user_lang), callback_data=f"dns_wizard:{domain}:A:ip:1.1.1.1")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:name:back")]
        ]
    elif 'ttl' not in data:
        # Step 3: TTL
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"🅰️ {t('dns_wizard.a_record_title', user_lang, step=3, domain=domain)}\n\n" \
                  f"{t('common_labels.name', user_lang)}: {name_display}\n" \
                  f"IP: {data['ip']}\n\n" \
                  f"{t('dns_wizard.select_ttl', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(t("buttons.auto_recommended_label", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:1")],
            [InlineKeyboardButton(t("buttons.5_minutes_label", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:300")],
            [InlineKeyboardButton(t("buttons.1_hour_label", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:3600"),
             InlineKeyboardButton(t("buttons.1_day", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:86400")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:ip:back")]
        ]
    elif 'proxied' not in data:
        # Step 4: Proxy Setting with IP Validation
        name_display = data['name'] if data['name'] != '@' else domain
        ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
        ip_address = data['ip']
        
        # Check if IP can be proxied
        can_proxy = is_ip_proxyable(ip_address)
        
        if can_proxy:
            # Public IP - show both options
            message = f"🅰️ {t('dns_wizard.a_record_title', user_lang, step=4, domain=domain)}\n\n" \
                      f"{t('common_labels.name', user_lang)}: {name_display}\n" \
                      f"IP: {data['ip']}\n" \
                      f"TTL: {ttl_display}\n\n" \
                      f"{t('dns_wizard.proxy_setting', user_lang)}\n\n" \
                      f"{t('dns_wizard.proxy_explanation', user_lang)}"
            keyboard = [
                [InlineKeyboardButton(t("buttons.proxied_recommended", user_lang), callback_data=f"dns_wizard:{domain}:A:proxied:true")],
                [InlineKeyboardButton(t("buttons.direct", user_lang), callback_data=f"dns_wizard:{domain}:A:proxied:false")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:back")]
            ]
        else:
            # Private/Reserved IP - only show direct option with explanation
            message = f"🅰️ {t('dns_wizard.a_record_title', user_lang, step=4, domain=domain)}\n\n" \
                      f"{t('common_labels.name', user_lang)}: {name_display}\n" \
                      f"IP: {data['ip']}\n" \
                      f"TTL: {ttl_display}\n\n" \
                      f"{t('dns_wizard.proxy_not_available', user_lang)}"
            keyboard = [
                [InlineKeyboardButton(t("buttons.direct_only_option", user_lang), callback_data=f"dns_wizard:{domain}:A:proxied:false")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:back")]
            ]
    else:
        # Step 5: Confirmation
        await show_a_record_confirmation(query, wizard_state)
        return
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def create_dns_record_from_wizard(query, context, wizard_state):
    """Create DNS record from wizard state with proper validation"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    record_type = wizard_state['type']
    data = wizard_state['data']
    
    try:
        # Special validation for CNAME records
        if record_type == "CNAME":
            record_name = data['name'] if data['name'] != '@' else domain
            cf_zone = await get_cloudflare_zone(domain)
            if cf_zone:
                cloudflare = CloudflareService()
                zone_id = cf_zone['cf_zone_id']
                
                # Check for existing records at the same name
                existing_records = await cloudflare.list_dns_records(zone_id)
                if existing_records:
                    conflicting_records = [r for r in existing_records if r.get('name') == record_name and r.get('type') != 'CNAME']
                    
                    if conflicting_records:
                        conflict_types = [str(r.get('type', 'Unknown')) for r in conflicting_records if r.get('type')]
                        await safe_edit_message(query, 
                            f"❌ CNAME Conflict\n\n"
                            f"Cannot create CNAME for {data['name']} due to existing {', '.join(conflict_types)} records.\n\n"
                            f"Use different subdomain or delete conflicting records."
                        )
                        return
        # Validate required data
        if record_type == "A":
            if not all(k in data for k in ['name', 'ip', 'ttl', 'proxied']):
                await safe_edit_message(query, t('dns.incomplete_data', user_lang))
                return
        elif record_type == "TXT":
            if not all(k in data for k in ['name', 'content', 'ttl']):
                await safe_edit_message(query, t('dns.incomplete_data', user_lang))
                return
        elif record_type == "CNAME":
            if not all(k in data for k in ['name', 'target', 'ttl']):
                await safe_edit_message(query, t('dns.incomplete_data', user_lang))
                return
        elif record_type == "MX":
            if not all(k in data for k in ['name', 'server', 'priority', 'ttl']):
                await safe_edit_message(query, t('dns.incomplete_data', user_lang))
                return
        
        # Get user record and verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, t('dns.access_denied', user_lang))
            return
        
        # Get Cloudflare zone
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, t('dns.dns_unavailable', user_lang, domain=domain))
            return
        
        # Show creating message
        await safe_edit_message(query, t('dns.creating_record', user_lang))
        
        # Create DNS record using CloudflareService
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        
        # Prepare record data based on type
        record_name = data['name'] if data['name'] != '@' else domain
        record_proxied = False  # Default for non-A records
        record_priority = None  # Initialize for MX records
        
        if record_type == "A":
            record_content = data['ip']
            record_proxied = data['proxied'] == 'true'
            # For proxied A records, force TTL to Auto (1) as recommended by Cloudflare
            if record_proxied:
                record_ttl = 1  # Auto TTL for proxied records
            else:
                record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1
        elif record_type == "TXT":
            record_content = data['content']
            # For non-A records, use the selected TTL
            record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        elif record_type == "CNAME":
            record_content = data['target']
            # For non-A records, use the selected TTL
            record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        elif record_type == "MX":
            # MX records need special handling for priority
            record_content = data['server']
            record_priority = int(data['priority'])
            # For non-A records, use the selected TTL
            record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        else:
            # Fallback for unknown record types
            record_content = data.get('content', '')
            record_priority = None  # Initialize for LSP
            # For non-A records, use the selected TTL
            record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        
        # Create the record (proxy parameter only for A records, priority for MX records)
        if record_type == "A":
            result = await cloudflare.create_dns_record(
                zone_id=zone_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl,
                proxied=record_proxied
            )
        elif record_type == "MX":
            result = await cloudflare.create_dns_record(
                zone_id=zone_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl,
                priority=record_priority
            )
        else:
            result = await cloudflare.create_dns_record(
                zone_id=zone_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl
            )
        
        if result and result.get('success'):
            # Success - clear wizard state and custom subdomain flags
            if 'dns_wizard' in context.user_data:
                del context.user_data['dns_wizard']
            clear_dns_wizard_custom_subdomain_state(context)
            
            record_info = result.get('result', {})
            name_display = record_info.get('name', record_name)
            content_display = record_info.get('content', record_content)
            
            # CRITICAL FIX: Save newly created record to database
            # This ensures the record appears in DNS dashboard immediately
            try:
                from database import update_single_dns_record_in_db
                await update_single_dns_record_in_db(domain, record_info)
                logger.info(f"✅ DNS record saved to database: {record_type} {name_display}")
            except Exception as db_err:
                logger.warning(f"Failed to save DNS record to database: {db_err}")
                # Don't fail the operation - Cloudflare creation succeeded
            
            if record_type == "A":
                proxy_display = "🟠 Proxied" if record_proxied else "⚪ Direct"
                message = f"✅ {t('dns_wizard.record_created_title', user_lang, type=record_type)}\n" \
                          f"{proxy_display}\n" \
                          f"{name_display} → {content_display}"
            elif record_type == "TXT":
                content_preview = content_display[:80] + "..." if len(content_display) > 80 else content_display
                message = f"✅ {t('dns_wizard.record_created_title', user_lang, type=record_type)}\n" \
                          f"{name_display}: {content_preview}"
            elif record_type == "CNAME":
                message = f"✅ {t('dns_wizard.record_created_title', user_lang, type=record_type)}\n" \
                          f"{name_display} → {content_display}"
            elif record_type == "MX":
                message = f"✅ {t('dns_wizard.record_created_title', user_lang, type=record_type)}\n" \
                          f"{name_display} → {content_display} ({t('common_labels.priority', user_lang)}: {data['priority']})"
            else:
                # Default message for other record types
                message = f"✅ {t('dns_wizard.record_created_title', user_lang, type=record_type)}\n" \
                          f"{name_display}: {content_display}"
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.view_dns_dashboard", user_lang), callback_data=f"dns:{domain}:view")],
                [InlineKeyboardButton(t("buttons.add_another_record", user_lang), callback_data=f"dns:{domain}:add")],
                [InlineKeyboardButton(t("buttons.back_to_domains", user_lang), callback_data="my_domains")]
            ]
        else:
            # Failed - show error with user-friendly details
            error_msg = "Unknown error occurred"
            error_code = None
            
            if result and result.get('errors'):
                errors = result.get('errors', [])
                if errors:
                    error_msg = errors[0].get('message', error_msg)
                    error_code = errors[0].get('code')
            
            # Provide user-friendly messages for common Cloudflare error codes
            if error_code == 81058 or "identical record already exists" in error_msg.lower():
                message = f"""
❌ Record Already Exists

This {record_type} record already exists in your DNS.
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.view_all", user_lang), callback_data=f"dns:{domain}:view")],
                    [InlineKeyboardButton(t("buttons.add_different", user_lang), callback_data=f"dns:{domain}:add")]
                ]
            else:
                # Generic error message for other errors
                message = t('dns.record_creation_failed', user_lang, error=error_msg)
                keyboard = [
                    [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"dns:{domain}:add:{record_type}")],
                    [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=f"dns:{domain}:view")]
                ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error creating DNS record: {e}")
        # Clear wizard state and custom subdomain flags on error
        if 'dns_wizard' in context.user_data:
            del context.user_data['dns_wizard']
        clear_dns_wizard_custom_subdomain_state(context)
        
        message = t('dns.record_creation_error', user_lang, support_contact=BrandConfig().support_contact)
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"dns:{domain}:add")],
            [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=f"dns:{domain}:view")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_a_record_confirmation(query, wizard_state):
    """Show A record confirmation before creation"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    name_display = data['name'] if data['name'] != '@' else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    proxy_display = "🟠 Proxied" if data['proxied'] == "true" else "⚪ Direct"
    
    message = f"✅ {t('dns_wizard.confirm_a_record_creation', user_lang)}\n\n" \
              f"Domain: {domain}\n" \
              f"{t('common_labels.name', user_lang)}: {name_display}\n" \
              f"IP: {data['ip']}\n" \
              f"TTL: {ttl_display}\n" \
              f"Proxy: {proxy_display}\n\n" \
              f"{t('dns_wizard.this_will_create', user_lang)}\n" \
              f"{name_display} → {data['ip']}\n\n" \
              f"{t('dns_wizard.ready_to_create', user_lang)}"
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.create_record", user_lang), callback_data=f"dns_wizard:{domain}:A:create:confirm")],
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:proxied:back"),
         InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:view")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def show_txt_record_confirmation(query, wizard_state):
    """Show TXT record confirmation before creation"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    name_display = data['name'] if data['name'] != '@' else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    content_display, parse_mode = escape_content_for_display(data['content'], mode="full")
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"✅ {t('dns_wizard.confirm_txt_record_creation', user_lang)}\n\n" \
              f"Domain: {domain}\n" \
              f"Type: TXT\n" \
              f"{t('common_labels.name', user_lang)}: {name_summary}\n" \
              f"{t('common_labels.content', user_lang)}: {content_display}\n" \
              f"TTL: {ttl_display}\n\n" \
              f"{t('dns_wizard.ready_to_create', user_lang)}"
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.create_record", user_lang), callback_data=f"dns_wizard:{domain}:TXT:create:confirm")],
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:TXT:ttl:back"),
         InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:view")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def show_cname_record_confirmation(query, wizard_state):
    """Show CNAME record confirmation before creation"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    name_display = data['name'] if data['name'] != '@' else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    target_display, parse_mode = escape_content_for_display(data['target'], mode="full")
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"✅ {t('dns_wizard.confirm_cname_record_creation', user_lang)}\n\n" \
              f"Domain: {domain}\n" \
              f"Type: CNAME\n" \
              f"{t('common_labels.name', user_lang)}: {name_summary}\n" \
              f"{t('common_labels.target', user_lang)}: {target_display}\n" \
              f"TTL: {ttl_display}\n\n" \
              f"{t('dns_wizard.ready_to_create', user_lang)}"
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.create_record", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:create:confirm")],
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:ttl:back"),
         InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:view")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def show_mx_record_confirmation(query, wizard_state):
    """Show MX record confirmation before creation"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    name_display = data['name'] if data['name'] != '@' else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    server_display, parse_mode = escape_content_for_display(data['server'], mode="full")
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"✅ {t('dns_wizard.confirm_mx_record_creation', user_lang)}\n\n" \
              f"Domain: {domain}\n" \
              f"Type: MX\n" \
              f"{t('common_labels.name', user_lang)}: {name_summary}\n" \
              f"{t('common_labels.server', user_lang)}: {server_display}\n" \
              f"{t('common_labels.priority', user_lang)}: {data['priority']}\n" \
              f"TTL: {ttl_display}\n\n" \
              f"{t('dns_wizard.ready_to_create', user_lang)}"
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.create_record", user_lang), callback_data=f"dns_wizard:{domain}:MX:create:confirm")],
        [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:MX:ttl:back"),
         InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:view")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def continue_cname_record_wizard(query, context, wizard_state):
    """Continue CNAME record wizard based on current data"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    # Handle custom subdomain input prompt
    if data.get('name') == 'custom':
        message = f"""
✏️ <b>Custom Subdomain for {domain}</b>

Examples: shop, staging, api-v2
(Use @ for root domain)

Letters/numbers/hyphens only, 1-63 chars
Cannot start/end with hyphen

Type your subdomain:
"""
        keyboard = [
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:name:back")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context to expect custom subdomain input
        context.user_data['expecting_custom_subdomain'] = {
            'domain': domain,
            'wizard_state': wizard_state
        }
        return
    
    if 'name' not in data:
        # Step 1: Dynamic Name Selection
        # Get Cloudflare zone to check existing records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
            
        # Get available names for CNAME
        available_names = await get_available_names_for_record_type(domain, 'CNAME', cf_zone['cf_zone_id'])
        
        if not available_names:
            await safe_edit_message(query, 
                f"❌ <b>{t('domain.sections.no_available_names', user_lang)}</b>\n\n"
                f"{t('domain.sections.all_subdomain_conflict', user_lang)}\n\n"
                f"{t('domain.sections.delete_existing_or_custom', user_lang)}"
            )
            return
            
        message = f"🔗 CNAME Record - {domain}\n\nChoose available subdomain:"
        
        # Create dynamic buttons (max 3 per row)
        keyboard = []
        row = []
        for name_info in available_names[:6]:  # Limit to first 6 options
            button_text = f"{name_info['display']}"
            row.append(InlineKeyboardButton(button_text, callback_data=f"dns_wizard:{domain}:CNAME:name:{name_info['name']}"))
            if len(row) == 2:  # 2 buttons per row
                keyboard.append(row)
                row = []
        if row:  # Add remaining buttons
            keyboard.append(row)
        
        # Add "Custom" button to allow user-defined subdomains
        keyboard.append([InlineKeyboardButton(t("buttons.custom_subdomain", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:name:custom")])
        keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add")])
    elif 'target' not in data:
        # Step 2: CNAME Target
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"🔗 {t('dns_wizard.cname_record_title', user_lang, step=2, domain=domain)}\n\n" \
                  f"{t('common_labels.name', user_lang)}: {escape_content_for_display(name_display, mode='summary')[0]}\n\n" \
                  f"{t('dns_wizard.enter_cname_target', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:name:back")]
        ]
    elif 'ttl' not in data:
        # Step 3: TTL
        name_display = data['name'] if data['name'] != '@' else domain
        target_preview = escape_content_for_display(data['target'], mode="summary")
        message = f"🔗 {t('dns_wizard.cname_record_title', user_lang, step=3, domain=domain)}\n\n" \
                  f"{t('common_labels.name', user_lang)}: {escape_content_for_display(name_display, mode='summary')[0]}\n" \
                  f"{t('common_labels.target', user_lang)}: {target_preview[0] if isinstance(target_preview, tuple) else target_preview}\n\n" \
                  f"{t('dns_wizard.select_ttl', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(t("buttons.auto_recommended_label", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:ttl:1")],
            [InlineKeyboardButton(t("buttons.5_minutes_label", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:ttl:300")],
            [InlineKeyboardButton(t("buttons.1_hour_label", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:ttl:3600"),
             InlineKeyboardButton(t("buttons.1_day", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:ttl:86400")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:CNAME:target:back")]
        ]
    else:
        # Step 4: Confirmation
        await show_cname_record_confirmation(query, wizard_state)
        return
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def continue_txt_record_wizard(query, context, wizard_state):
    """Continue TXT record wizard based on current data"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    # Handle custom subdomain input prompt
    if data.get('name') == 'custom':
        message = f"""
✏️ <b>Custom Subdomain for {domain}</b>

Examples: _dmarc, mail, verification-code
(Use @ for root domain)

Letters/numbers/hyphens/underscores only, 1-63 chars
Cannot start/end with hyphen

Type your subdomain:
"""
        keyboard = [
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:TXT:name:back")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context to expect custom subdomain input
        context.user_data['expecting_custom_subdomain_txt'] = {
            'domain': domain,
            'wizard_state': wizard_state
        }
        return
    
    if 'name' not in data:
        # Step 1: Dynamic Name Selection for TXT Record
        # Get Cloudflare zone to check existing records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
            
        # Get available names for TXT records
        available_names = await get_available_names_for_record_type(domain, 'TXT', cf_zone['cf_zone_id'])
        
        if not available_names:
            await safe_edit_message(query, 
                f"❌ <b>{t('domain.sections.no_available_names', user_lang)}</b>\n\n"
                f"{t('domain.sections.all_cname_conflict', user_lang)}\n\n"
                f"{t('domain.sections.delete_cname_or_use_different', user_lang)}"
            )
            return
            
        message = f"📝 TXT Record - {domain}\n\nChoose available name:"
        
        # Create dynamic buttons
        keyboard = []
        row = []
        for name_info in available_names[:6]:  # Limit to first 6 options
            button_text = f"{name_info['display']}"
            row.append(InlineKeyboardButton(button_text, callback_data=f"dns_wizard:{domain}:TXT:name:{name_info['name']}"))
            if len(row) == 2:  # 2 buttons per row
                keyboard.append(row)
                row = []
        if row:  # Add remaining buttons
            keyboard.append(row)
        
        # Add "Custom" button to allow user-defined subdomains
        keyboard.append([InlineKeyboardButton(t("buttons.custom_subdomain", user_lang), callback_data=f"dns_wizard:{domain}:TXT:name:custom")])
        keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add")])
    elif 'content' not in data:
        # Step 2: TXT Content
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"📝 {t('dns_wizard.txt_record_title', user_lang, step=2, domain=domain)}\n\n" \
                  f"{t('common_labels.name', user_lang)}: {escape_content_for_display(name_display, mode='summary')[0]}\n\n" \
                  f"{t('dns_wizard.enter_txt_content', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(t("buttons.spf_record", user_lang), callback_data=await compress_callback(f"dns_wizard:{domain}:TXT:content:v=spf1 include:_spf.google.com ~all", context))],
            [InlineKeyboardButton(t("buttons.google_verification", user_lang), callback_data=await compress_callback(f"dns_wizard:{domain}:TXT:content:google-site-verification=YOUR_CODE_HERE", context))],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:TXT:name:back")]
        ]
    elif 'ttl' not in data:
        # Step 3: TTL
        name_display = data['name'] if data['name'] != '@' else domain
        content_preview = escape_content_for_display(data['content'], mode="full")  # Use full mode for safe HTML
        name_safe = escape_content_for_display(name_display, mode="full")
        message = f"📝 {t('dns_wizard.txt_record_title', user_lang, step=3, domain=domain)}\n\n" \
                  f"{name_safe[0]} → {content_preview[0]}\n\n" \
                  f"{t('dns_wizard.select_ttl', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(t("buttons.auto_recommended_label", user_lang), callback_data=f"dns_wizard:{domain}:TXT:ttl:1")],
            [InlineKeyboardButton(t("buttons.5_minutes_label", user_lang), callback_data=f"dns_wizard:{domain}:TXT:ttl:300")],
            [InlineKeyboardButton(t("buttons.1_hour_label", user_lang), callback_data=f"dns_wizard:{domain}:TXT:ttl:3600"),
             InlineKeyboardButton(t("buttons.1_day", user_lang), callback_data=f"dns_wizard:{domain}:TXT:ttl:86400")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:TXT:content:back")]
        ]
    else:
        # Step 4: Confirmation
        await show_txt_record_confirmation(query, wizard_state)
        return
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Use HTML parse mode for TTL step to safely display user content
    parse_mode = ParseMode.HTML
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode=parse_mode)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def continue_mx_record_wizard(query, context, wizard_state):
    """Continue MX record wizard based on current data"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    # CRITICAL REFRESH: Always use the state from context.user_data if it exists
    # This prevents the local variable 'wizard_state' from being stale
    if 'dns_wizard' in context.user_data:
        context_state = context.user_data['dns_wizard']
        # Verify it's the correct wizard session
        if context_state.get('domain') == wizard_state.get('domain') and context_state.get('type') == 'MX':
            wizard_state = context_state
            logger.info(f"MX Wizard: Refreshed state from context.user_data. Data now: {wizard_state.get('data')}")

    domain = wizard_state['domain']
    data = wizard_state.get('data', {})
    
    logger.info(f"Entering continue_mx_record_wizard for domain {domain}, data: {data}")
    
    # Step 1: Dynamic Name Selection for MX Record
    # Check if 'name' is in data and not empty
    has_name = 'name' in data and data.get('name') is not None and str(data.get('name', '')).strip() != ''
    
    if not has_name:
        logger.info(f"MX Wizard: Step 1 (Name Selection) - Data: {data}")
        # Get Cloudflare zone to check existing records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
            
        # Get available names for MX records
        available_names = await get_available_names_for_record_type(domain, 'MX', cf_zone['cf_zone_id'])
        
        if not available_names:
            await safe_edit_message(query, 
                f"❌ <b>{t('domain.sections.no_available_names', user_lang)}</b>\n\n"
                f"{t('domain.sections.all_cname_conflict', user_lang)}\n\n"
                f"{t('domain.sections.delete_cname_or_use_different', user_lang)}"
            )
            return
            
        message = f"📧 {t('dns_wizard.mx_record_title', user_lang, step=1, domain=domain)}\n\n{t('dns_wizard.choose_name', user_lang)}"
        
        # Create dynamic buttons
        keyboard = []
        row = []
        for name_info in available_names[:6]:  # Limit to first 6 options
            button_text = f"{name_info['display']}"
            row.append(InlineKeyboardButton(button_text, callback_data=f"dns_wizard:{domain}:MX:name:{name_info['name']}"))
            if len(row) == 2:  # 2 buttons per row
                keyboard.append(row)
                row = []
        if row:  # Add remaining buttons
            keyboard.append(row)
            
        # Add "Custom" button to allow user-defined subdomains for MX
        keyboard.append([InlineKeyboardButton(t("buttons.custom_subdomain", user_lang), callback_data=f"dns_wizard:{domain}:MX:name:custom")])
        keyboard.append([InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add")])
    elif data.get('name') == 'custom' and not data.get('custom_name_entered'):
        # Custom subdomain input prompt for MX
        message = f"""
✏️ <b>{t('dns_wizard.custom_subdomain_title', user_lang, domain=domain)}</b>

{t('dns_wizard.custom_subdomain_examples', user_lang)}
{t('dns_wizard.custom_subdomain_root_tip', user_lang)}

{t('dns_wizard.custom_subdomain_rules', user_lang)}

{t('dns_wizard.type_your_subdomain', user_lang)}
"""
        keyboard = [
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:MX:name:back")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context to expect custom subdomain input
        context.user_data['expecting_custom_subdomain_mx'] = {
            'domain': domain,
            'wizard_state': wizard_state
        }
        logger.info(f"MX Wizard: Prompted for custom subdomain for user {user.id}")
        return
    elif 'server' not in data:
        # Step 2: Mail Server
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"📧 {t('dns_wizard.mx_record_title', user_lang, step=2, domain=domain)}\n\n" \
                  f"{t('common_labels.name', user_lang)} {escape_content_for_display(name_display, mode='summary')[0]}\n\n" \
                  f"{t('dns_wizard.enter_mail_server', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(btn_t("use_mail_domain", user_lang, domain=domain), callback_data=f"dns_wizard:{domain}:MX:server:mail.{domain}")],
            [InlineKeyboardButton(t("buttons.use_google_workspace", user_lang), callback_data=f"dns_wizard:{domain}:MX:server:aspmx.l.google.com")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:MX:name:back")]
        ]
    elif 'priority' not in data:
        # Step 3: Priority
        name_display = data['name'] if data['name'] != '@' else domain
        server_preview = escape_content_for_display(data['server'], mode="summary")
        message = f"📧 {t('dns_wizard.mx_record_title', user_lang, step=3, domain=domain)}\n\n" \
                  f"{t('common_labels.name', user_lang)} {escape_content_for_display(name_display, mode='summary')[0]}\n" \
                  f"{t('common_labels.server', user_lang)} {server_preview[0] if isinstance(server_preview, tuple) else server_preview}\n\n" \
                  f"{t('dns_wizard.select_priority', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(t("buttons.priority_10", user_lang), callback_data=f"dns_wizard:{domain}:MX:priority:10")],
            [InlineKeyboardButton(t("buttons.priority_20", user_lang), callback_data=f"dns_wizard:{domain}:MX:priority:20"),
             InlineKeyboardButton(t("buttons.priority_30", user_lang), callback_data=f"dns_wizard:{domain}:MX:priority:30")],
            [InlineKeyboardButton(t("buttons.priority_0", user_lang), callback_data=f"dns_wizard:{domain}:MX:priority:0"),
             InlineKeyboardButton(t("buttons.priority_50", user_lang), callback_data=f"dns_wizard:{domain}:MX:priority:50")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:MX:server:back")]
        ]
    elif 'ttl' not in data:
        # Step 4: TTL
        name_display = data['name'] if data['name'] != '@' else domain
        server_preview = escape_content_for_display(data['server'], mode="summary")
        message = f"📧 {t('dns_wizard.mx_record_title', user_lang, step=4, domain=domain)}\n\n" \
                  f"{t('common_labels.name', user_lang)} {escape_content_for_display(name_display, mode='summary')[0]}\n" \
                  f"{t('common_labels.server', user_lang)} {server_preview[0] if isinstance(server_preview, tuple) else server_preview}\n" \
                  f"{t('common_labels.priority', user_lang)} {data['priority']}\n\n" \
                  f"{t('dns_wizard.select_ttl', user_lang)}"
        keyboard = [
            [InlineKeyboardButton(t("buttons.auto_recommended_label", user_lang), callback_data=f"dns_wizard:{domain}:MX:ttl:1")],
            [InlineKeyboardButton(t("buttons.5_minutes_label", user_lang), callback_data=f"dns_wizard:{domain}:MX:ttl:300")],
            [InlineKeyboardButton(t("buttons.1_hour_label", user_lang), callback_data=f"dns_wizard:{domain}:MX:ttl:3600"),
             InlineKeyboardButton(t("buttons.1_day", user_lang), callback_data=f"dns_wizard:{domain}:MX:ttl:86400")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:MX:priority:back")]
        ]
    else:
        # Step 5: Confirmation
        await show_mx_record_confirmation(query, wizard_state)
        return

    reply_markup = InlineKeyboardMarkup(keyboard)

    # Use HTML parse mode for better formatting
    parse_mode = ParseMode.HTML

    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode=parse_mode)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all text messages (unified handler for domain search, registration, etc.)"""
    user = update.effective_user
    effective_message = update.effective_message
    
    if not effective_message or not effective_message.text:
        return
    
    # MAINTENANCE MODE CHECK - Block non-admin users during maintenance
    if user:
        from services.maintenance_manager import MaintenanceManager
        
        is_active = await MaintenanceManager.is_maintenance_active()
        if is_active and not is_admin_user(user.id):
            user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
            maintenance_message = await MaintenanceManager.get_maintenance_message(user_lang)
            await effective_message.reply_text(
                maintenance_message,
                parse_mode=ParseMode.HTML
            )
            logger.info(f"🔧 MAINTENANCE: Blocked message from non-admin user {user.id}")
            return
    
    # Skip if domain linking is active to prevent double processing
    user_data = context.user_data or {}
    if user_data.get('awaiting_domain_for_linking'):
        return
        
    text = effective_message.text.strip()
    
    # Handle custom deposit amount input
    if user_data.get('awaiting_deposit_amount'):
        if not user or context.user_data is None:
            return
        context.user_data['awaiting_deposit_amount'] = False  # Clear state
        try:
            amount = float(text.replace('$', '').replace(',', '').strip())
            if amount < 10:
                user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
                await effective_message.reply_text(f"❌ Minimum deposit is $10 USD. Please enter a larger amount.")
                if context.user_data is not None:
                    context.user_data['awaiting_deposit_amount'] = True  # Re-enable state
                return
            if amount > 10000:
                await effective_message.reply_text(f"❌ Maximum deposit is $10,000 USD. Please enter a smaller amount.")
                if context.user_data is not None:
                    context.user_data['awaiting_deposit_amount'] = True  # Re-enable state
                return
            # Show crypto selection for the custom amount (InlineKeyboardButton imported at top of file)
            user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
            
            message = f"💰 Deposit ${amount:.2f} USD\n\nSelect cryptocurrency:"
            
            keyboard = [
                [
                    InlineKeyboardButton("₿ BTC", callback_data=f"deposit_btc:{amount}"),
                    InlineKeyboardButton("Ξ ETH", callback_data=f"deposit_eth:{amount}")
                ],
                [
                    InlineKeyboardButton("Ł LTC", callback_data=f"deposit_ltc:{amount}"),
                    InlineKeyboardButton("Ð DOGE", callback_data=f"deposit_doge:{amount}")
                ],
                [
                    InlineKeyboardButton("₮ USDT (TRC20)", callback_data=f"deposit_usdt_trc20:{amount}"),
                    InlineKeyboardButton("₮ USDT (ERC20)", callback_data=f"deposit_usdt_erc20:{amount}")
                ],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="wallet_deposit")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await effective_message.reply_text(message, reply_markup=reply_markup, parse_mode='HTML')
            return
        except ValueError:
            await effective_message.reply_text("❌ Invalid amount. Please enter a number like: 50")
            if context.user_data is not None:
                context.user_data['awaiting_deposit_amount'] = True  # Re-enable state
            return
    
    # Handle API key creation workflow
    if user_data.get('api_creation_step') == 'name':
        logger.info(f"🔄 TEXT ROUTING: Handling API key name input for user {user.id if user else 'None'}")
        await handle_api_key_name_input(update, context)
        return
    
    # CRITICAL FIX: Handle admin credit workflow first - delegate to admin handler
    if user_data.get('admin_credit_state'):
        logger.info(f"🔄 TEXT ROUTING: Delegating admin text to handle_admin_credit_text for user {user.id if user else 'None'}")
        from admin_handlers import handle_admin_credit_text
        admin_handled = await handle_admin_credit_text(update, context)
        if admin_handled:
            logger.info(f"✅ TEXT ROUTING: Admin credit handler processed message successfully")
            return
        else:
            logger.warning(f"⚠️ TEXT ROUTING: Admin credit handler declined message, continuing to generic handler")
    
    # Check for hosting domain input context
    hosting_flow = user_data.get('hosting_flow')
    if hosting_flow in ['awaiting_new_domain', 'awaiting_existing_domain']:
        await handle_hosting_domain_input(update, context, text)
        return
    
    # Check for unified hosting flow context
    unified_flow = user_data.get('unified_flow')
    if unified_flow in ['awaiting_new_domain', 'awaiting_existing_domain']:
        await handle_unified_text_input(update, context, text)
        return
    
    # Check for bundle domain search context
    bundle_context = user_data.get('bundle_domain_search')
    if bundle_context:
        plan_id = bundle_context.get('plan_id')
        if plan_id:
            # Clear the bundle context
            user_data.pop('bundle_domain_search', None)
            await process_bundle_domain_search(update, context, text.lower().strip(), str(plan_id))
            return
    
    # Check for edit input context (IP address changes and TXT content changes)
    edit_input = user_data.get('edit_input')
    if edit_input and edit_input['type'] == 'ip':
        await handle_ip_input(update, context, text, edit_input)
        return
    elif edit_input and edit_input['type'] == 'content':
        await handle_content_input(update, context, text, edit_input)
        return
    elif edit_input and edit_input['type'] == 'cname_target':
        await handle_cname_target_input(update, context, text, edit_input)
        return
    elif edit_input and edit_input['type'] == 'mx_server':
        await handle_mx_server_input(update, context, text, edit_input)
        return
    
    # Check for custom subdomain input context (CNAME)
    custom_subdomain_input = user_data.get('expecting_custom_subdomain')
    if custom_subdomain_input:
        # Defensive check: verify wizard_state exists
        dns_wizard = user_data.get('dns_wizard')
        if not dns_wizard or dns_wizard.get('action') != 'add':
            # Orphaned flag detected - clear it and continue to next handler
            logger.warning(f"⚠️ Orphaned expecting_custom_subdomain flag detected for user {user.id if user else 'unknown'} - clearing")
            clear_dns_wizard_custom_subdomain_state(context)
        else:
            await handle_custom_subdomain_input(update, context, text, custom_subdomain_input)
            return
    
    # Check for custom subdomain input context (A record)
    custom_subdomain_a_input = user_data.get('expecting_custom_subdomain_a')
    if custom_subdomain_a_input:
        # Defensive check: verify wizard_state exists
        dns_wizard = user_data.get('dns_wizard')
        if not dns_wizard or dns_wizard.get('action') != 'add':
            # Orphaned flag detected - clear it and continue to next handler
            logger.warning(f"⚠️ Orphaned expecting_custom_subdomain_a flag detected for user {user.id if user else 'unknown'} - clearing")
            clear_dns_wizard_custom_subdomain_state(context)
        else:
            await handle_custom_subdomain_a_input(update, context, text, custom_subdomain_a_input)
            return
    
    # Check for custom subdomain input context (TXT record)
    custom_subdomain_txt_input = user_data.get('expecting_custom_subdomain_txt')
    if custom_subdomain_txt_input:
        # Defensive check: verify wizard_state exists
        dns_wizard = user_data.get('dns_wizard')
        if not dns_wizard or dns_wizard.get('action') != 'add':
            # Orphaned flag detected - clear it and continue to next handler
            logger.warning(f"⚠️ Orphaned expecting_custom_subdomain_txt flag detected for user {user.id if user else 'unknown'} - clearing")
            clear_dns_wizard_custom_subdomain_state(context)
        else:
            await handle_custom_subdomain_txt_input(update, context, text, custom_subdomain_txt_input)
            return
    
    # Check for nameserver input context  
    nameserver_input = user_data.get('expecting_nameserver_input')
    if nameserver_input:
        await handle_nameserver_input(update, context, text, nameserver_input)
        return
    
    # Check if user is in DNS wizard context expecting input
    dns_wizard = user_data.get('dns_wizard')
    if dns_wizard and dns_wizard.get('action') == 'add':
        wizard_data = dns_wizard.get('data', {})
        record_type = dns_wizard.get('type')
        
        if record_type == 'A' and 'name' in wizard_data and 'ip' not in wizard_data:
            # A record expecting IP input
            await handle_dns_wizard_ip_input(update, context, text, dns_wizard)
            return
        elif record_type == 'TXT' and 'name' in wizard_data and 'content' not in wizard_data:
            # TXT record expecting content input
            await handle_dns_wizard_txt_input(update, context, text, dns_wizard)
            return
        elif record_type == 'CNAME' and 'name' in wizard_data and 'target' not in wizard_data:
            # CNAME record expecting target input
            await handle_dns_wizard_cname_input(update, context, text, dns_wizard)
            return
        elif record_type == 'MX' and 'name' in wizard_data and 'server' not in wizard_data:
            # MX record expecting server input
            await handle_dns_wizard_mx_input(update, context, text, dns_wizard)
            return
    
    # Check for custom subdomain input context (MX record)
    custom_subdomain_mx_input = user_data.get('expecting_custom_subdomain_mx')
    if custom_subdomain_mx_input:
        # Defensive check: verify wizard_state exists
        dns_wizard = user_data.get('dns_wizard')
        if not dns_wizard or dns_wizard.get('action') != 'add':
            # Orphaned flag detected - clear it
            logger.warning(f"⚠️ Orphaned expecting_custom_subdomain_mx flag detected for user {user.id if user else 'unknown'} - clearing")
            if 'expecting_custom_subdomain_mx' in context.user_data:
                del context.user_data['expecting_custom_subdomain_mx']
        else:
            await handle_custom_subdomain_mx_input(update, context, text, custom_subdomain_mx_input)
            return
    
    # Basic domain search functionality - only if not in wizard context
    if '.' in text and len(text) > 3:
        domain_name = text.lower().strip()
        
        # CRITICAL: Check if this is an admin user who might have just sent a broadcast
        # Admin broadcasts should never trigger domain searches
        if user and is_admin_user(user.id):
            logger.info(f"🔍 TEXT_HANDLER: Admin user {user.id} text detected - checking for recent broadcast activity")
            # Check if admin recently sent a broadcast (within last 30 seconds) 
            # This prevents admin broadcast messages from being treated as domain searches
            user_data = context.user_data or {}
            last_broadcast_time = user_data.get('last_broadcast_time', 0)
            current_time = time.time()
            
            if current_time - last_broadcast_time < 30:  # 30 second window
                logger.info(f"🔍 TEXT_HANDLER: Admin {user.id} recently sent broadcast - skipping domain search for: {text[:50]}")
                return
        
        # Only proceed if it's a valid domain name  
        if not is_valid_domain(domain_name):
            # For inline domain detection, show helpful error message
            error_msg = get_domain_validation_error(domain_name)
            if effective_message:
                user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
                await effective_message.reply_text(
                    create_warning_message(
                        "Domain Format Issue", 
                        f"{domain_name} - {error_msg}\n\n{t('help.try_typing', user_lang)} /search example.com"
                    ),
                    parse_mode='HTML'
                )
            return
            
        # CRITICAL: Check if TLD is supported before making API calls
        if not is_supported_tld(domain_name):
            # Show helpful error message for unsupported TLD
            error_msg = get_unsupported_tld_message(domain_name)
            if effective_message:
                user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
                await effective_message.reply_text(
                    create_warning_message(
                        "Unsupported Domain Extension", 
                        f"{error_msg}\n\n{t('help.try_typing', user_lang)} /search example.com"
                    ),
                    parse_mode='HTML'
                )
            logger.warning(f"🚫 DOMAIN_SEARCH: Blocked unsupported TLD search for {domain_name} by user {user.id if user else 'None'}")
            return
        
        # Get user language for localized responses
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
            
        if effective_message:
            searching_msg = await effective_message.reply_text(
                f"{t('domain.search.searching', user_lang, domain=domain_name)}\n\n"
                f"{t('domain.search.checking_availability', user_lang)}\n"
                f"{t('domain.search.getting_pricing', user_lang)}\n" 
                f"{t('domain.search.analyzing_status', user_lang)}",
                parse_mode=ParseMode.HTML
            )
        else:
            return
        
        # Perform actual domain search
        try:
            availability = await openprovider.check_domain_availability(domain_name)
            
            if availability is None:
                # API error or no response - provide helpful fallback
                message = t('errors.service_temporarily_down', user_lang)
                keyboard = [
                    [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data="search_domains")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
                ]
            elif availability.get('available'):
                # Domain is available - extract dynamic pricing
                price_info = availability.get('price_info', {})
                create_price = price_info.get('create_price', 0)
                currency = price_info.get('currency', 'EUR')
                is_premium = availability.get('premium', False)
                
                # Format pricing display using robust money formatting (price is already in USD after markup)
                if create_price > 0:
                    price_display = f"{format_money(create_price, currency, include_currency=True)}/year"
                else:
                    price_display = t('domain.contact_for_pricing', user_lang)
                
                domain_type = t('domain.status.premium_domain', user_lang) if is_premium else t('domain.status.standard_domain', user_lang)
                message = f"""
✅ {domain_name} {t('domain.status.available', user_lang)}

{domain_type}
{price_display}
"""
                keyboard = [
                    [InlineKeyboardButton(btn_t("register_domain_name", user_lang, domain_name=domain_name), callback_data=f"register_{domain_name}")],
                    [InlineKeyboardButton(t("buttons.search_another", user_lang), callback_data="search_domains")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
                ]
            else:
                # Domain is not available
                message = t('domain.already_registered_try_alternatives', user_lang)
                keyboard = [
                    [InlineKeyboardButton(t("buttons.search_another", user_lang), callback_data="search_domains")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data="main_menu")]
                ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await searching_msg.edit_text(message, reply_markup=reply_markup)
            
        except Exception as e:
            logger.error(f"Error searching domain {domain_name}: {e}")
            await searching_msg.edit_text(t('errors.domain_search_failed', user_lang))
        
        return
    
    # Enhanced response for unrecognized text - help users get oriented
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
    
    message = t('messages.unrecognized_input', user_lang)
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.main_menu", user_lang), callback_data="main_menu")],
        [InlineKeyboardButton(t("buttons.search_domains", user_lang), callback_data="search_domains")],
        [InlineKeyboardButton(t("buttons.hosting_plans", user_lang), callback_data="unified_hosting_plans")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if effective_message:
        await effective_message.reply_text(message, reply_markup=reply_markup)

# DNS Record Edit Wizard Functions  
async def continue_a_record_edit_wizard(query, context, wizard_state):
    """Continue A record edit wizard with auto-apply functionality"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Initialize or get AutoApplySession
    session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'A', user_lang)
    
    # Set original state from current wizard data if not already set
    if not session.original_state:
        await session.set_original_state(data)
    
    # Update session with current draft state
    session.draft_state = data.copy()
    
    # Check for validation errors and changes
    validation = session.validate_current_state()
    changes_summary = session.get_changes_summary()
    
    # Build display elements
    name_display = data['name'] if data['name'] != domain else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    proxy_display = "🟠 Proxied" if data['proxied'] == "true" else "⚪ Direct"
    
    # Status indicator based on validation and changes
    if validation['errors']:
        status_icon = "❌"
        status_text = "Validation Error"
    elif validation['has_changes']:
        if session.is_applying:
            status_icon = "🔄"
            status_text = "Applying..."
        else:
            status_icon = "⚡"
            status_text = "Auto-Apply Ready"
    else:
        status_icon = "✅"
        status_text = "Current State"
    
    # Build message with real-time status
    message = f"""
{status_icon} Edit A Record: {domain} • {status_text}

Current Configuration:
Name: {name_display} (read-only)
IP Address: {data['content']}
TTL: {ttl_display}
Proxy Status: {proxy_display}
"""
    
    # Add changes summary if there are changes
    if changes_summary:
        changes_text = "\n".join(f"• {change}" for change in changes_summary)
        message += f"\n⚡ Changes:\n{changes_text}\n"
    
    # Add validation errors if any
    if validation['errors']:
        error_text = "\n".join(f"• {error}" for error in validation['errors'].values())
        message += f"\n❌ Issues:\n{error_text}\n"
    
    message += "\nClick to modify fields:"
    
    # Build keyboard without Save Changes button
    keyboard = [
        [InlineKeyboardButton(t("buttons.change_ip_address", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:A:ip:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.change_ttl", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:A:ttl:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.toggle_proxy", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:A:proxy:{record_id}", context))]
    ]
    
    # Add action buttons based on state
    action_row = []
    if validation['has_changes']:
        if validation['errors']:
            action_row.append(InlineKeyboardButton(t("buttons.revert_changes", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:A:revert:{record_id}", context)))
        elif session.is_applying:
            action_row.append(InlineKeyboardButton(t("buttons.applying", user_lang), callback_data="noop"))
    
    action_row.append(InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=await compress_callback(f"dns:{domain}:record:{record_id}", context)))
    keyboard.append(action_row)
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Use safe_edit_message for centralized deduplication
    await safe_edit_message(query, message, reply_markup=reply_markup)
    
    # Trigger auto-apply if conditions are met
    if await session.should_auto_apply():
        asyncio.create_task(auto_apply_with_feedback(query, context, session))

async def continue_cname_record_edit_wizard(query, wizard_state):
    """Continue CNAME record edit wizard with auto-apply functionality"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    original_data = wizard_state['original_data']
    
    # Initialize or get AutoApplySession
    session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'CNAME', user_lang)
    
    # Set original state from wizard data if not already set
    if not session.original_state:
        await session.set_original_state(original_data)
    
    # Update session with current draft state
    session.draft_state = data.copy()
    
    # Check for validation errors and changes
    validation = session.validate_current_state()
    changes_summary = session.get_changes_summary()
    
    # Build display elements
    name_display = data['name'] if data['name'] != '@' else domain
    target_display, _ = escape_content_for_display(data['content'], mode="full")
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    
    # Status indicator based on validation and changes
    if validation['errors']:
        status_icon = "❌"
        status_text = "Validation Error"
    elif validation['has_changes']:
        if session.is_applying:
            status_icon = "🔄"
            status_text = "Applying..."
        else:
            status_icon = "⚡"
            status_text = "Auto-Apply Ready"
    else:
        status_icon = "✅"
        status_text = "Current State"
    
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
{status_icon} Edit CNAME Record: {domain} • {status_text}

Name: {name_summary}
Target: {target_display}
TTL: {ttl_display}
"""
    
    # Add changes summary if there are changes
    if changes_summary:
        changes_text = "\n".join(f"• {change}" for change in changes_summary)
        message += f"\n\n⚡ Changes:\n{changes_text}"
    
    # Add validation errors if any
    if validation['errors']:
        error_text = "\n".join(f"• {error}" for error in validation['errors'].values())
        message += f"\n\n❌ Issues:\n{error_text}"
    
    message += "\n\nClick to modify fields:"
    
    # Build keyboard without Save Changes button
    keyboard = [
        [InlineKeyboardButton(t("buttons.edit_target", user_lang), callback_data=f"dns_edit:{domain}:CNAME:content:{record_id}")],
        [InlineKeyboardButton(t("buttons.edit_ttl", user_lang), callback_data=f"dns_edit:{domain}:CNAME:ttl:{record_id}")]
    ]
    
    # Add action buttons based on state
    action_row = []
    if validation['has_changes']:
        if validation['errors']:
            action_row.append(InlineKeyboardButton(t("buttons.revert_changes", user_lang), callback_data=f"dns_edit:{domain}:CNAME:revert:{record_id}"))
        elif session.is_applying:
            action_row.append(InlineKeyboardButton(t("buttons.applying", user_lang), callback_data="noop"))
    
    action_row.append(InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:record:{record_id}"))
    keyboard.append(action_row)
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        # Trigger auto-apply if conditions are met
        if await session.should_auto_apply():
            asyncio.create_task(auto_apply_with_feedback(query, None, session))
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def continue_txt_record_edit_wizard(query, wizard_state):
    """Continue TXT record edit wizard with auto-apply functionality"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    original_data = wizard_state['original_data']
    
    # Initialize or get AutoApplySession
    session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'TXT', user_lang)
    
    # Set original state from wizard data if not already set
    if not session.original_state:
        await session.set_original_state(original_data)
    
    # Update session with current draft state
    session.draft_state = data.copy()
    
    # Check for validation errors and changes
    validation = session.validate_current_state()
    changes_summary = session.get_changes_summary()
    
    # Build display elements
    name_display = data['name'] if data['name'] != '@' else domain
    content_display, _ = escape_content_for_display(data['content'], mode="full")
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    
    # Status indicator based on validation and changes
    if validation['errors']:
        status_icon = "❌"
        status_text = "Validation Error"
    elif validation['has_changes']:
        if session.is_applying:
            status_icon = "🔄"
            status_text = "Applying..."
        else:
            status_icon = "⚡"
            status_text = "Auto-Apply Ready"
    else:
        status_icon = "✅"
        status_text = "Current State"
    
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
{status_icon} Edit TXT Record: {domain} • {status_text}

Name: {name_summary}
Content: {content_display}
TTL: {ttl_display}
"""
    
    # Add changes summary if there are changes
    if changes_summary:
        changes_text = "\n".join(f"• {change}" for change in changes_summary)
        message += f"\n\n⚡ Changes:\n{changes_text}"
    
    # Add validation errors if any
    if validation['errors']:
        error_text = "\n".join(f"• {error}" for error in validation['errors'].values())
        message += f"\n\n❌ Issues:\n{error_text}"
    
    message += "\n\nClick to modify fields:"
    
    # Build keyboard without Save Changes button
    keyboard = [
        [InlineKeyboardButton(t("buttons.edit_content", user_lang), callback_data=f"dns_edit:{domain}:TXT:content:{record_id}")],
        [InlineKeyboardButton(t("buttons.edit_ttl", user_lang), callback_data=f"dns_edit:{domain}:TXT:ttl:{record_id}")]
    ]
    
    # Add action buttons based on state
    action_row = []
    if validation['has_changes']:
        if validation['errors']:
            action_row.append(InlineKeyboardButton(t("buttons.revert_changes", user_lang), callback_data=f"dns_edit:{domain}:TXT:revert:{record_id}"))
        elif session.is_applying:
            action_row.append(InlineKeyboardButton(t("buttons.applying", user_lang), callback_data="noop"))
    
    action_row.append(InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:record:{record_id}"))
    keyboard.append(action_row)
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        # Trigger auto-apply if conditions are met
        if await session.should_auto_apply():
            asyncio.create_task(auto_apply_with_feedback(query, None, session))
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def continue_mx_record_edit_wizard(query, wizard_state):
    """Continue MX record edit wizard with auto-apply functionality"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    original_data = wizard_state['original_data']
    
    # Initialize or get AutoApplySession
    session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'MX', user_lang)
    
    # Set original state from wizard data if not already set
    if not session.original_state:
        await session.set_original_state(original_data)
    
    # Update session with current draft state
    session.draft_state = data.copy()
    
    # Check for validation errors and changes
    validation = session.validate_current_state()
    changes_summary = session.get_changes_summary()
    
    # Build display elements
    name_display = data['name'] if data['name'] != '@' else domain
    server_display, _ = escape_content_for_display(data['content'], mode="full")
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    priority = data.get('priority', '10')
    
    # Status indicator based on validation and changes
    if validation['errors']:
        status_icon = "❌"
        status_text = "Validation Error"
    elif validation['has_changes']:
        if session.is_applying:
            status_icon = "🔄"
            status_text = "Applying..."
        else:
            status_icon = "⚡"
            status_text = "Auto-Apply Ready"
    else:
        status_icon = "✅"
        status_text = "Current State"
    
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
{status_icon} Edit MX Record: {domain} • {status_text}

Name: {name_summary}
Mail Server: {server_display}
Priority: {priority}
TTL: {ttl_display}
"""
    
    # Add changes summary if there are changes
    if changes_summary:
        changes_text = "\n".join(f"• {change}" for change in changes_summary)
        message += f"\n\n⚡ Changes:\n{changes_text}"
    
    # Add validation errors if any
    if validation['errors']:
        error_text = "\n".join(f"• {error}" for error in validation['errors'].values())
        message += f"\n\n❌ Issues:\n{error_text}"
    
    message += "\n\nClick to modify fields:"
    
    # Build keyboard without Save Changes button
    keyboard = [
        [InlineKeyboardButton(t("buttons.edit_server", user_lang), callback_data=f"dns_edit:{domain}:MX:content:{record_id}")],
        [InlineKeyboardButton(t("buttons.edit_priority", user_lang), callback_data=f"dns_edit:{domain}:MX:priority:{record_id}")],
        [InlineKeyboardButton(t("buttons.edit_ttl", user_lang), callback_data=f"dns_edit:{domain}:MX:ttl:{record_id}")]
    ]
    
    # Add action buttons based on state
    action_row = []
    if validation['has_changes']:
        if validation['errors']:
            action_row.append(InlineKeyboardButton(t("buttons.revert_changes", user_lang), callback_data=f"dns_edit:{domain}:MX:revert:{record_id}"))
        elif session.is_applying:
            action_row.append(InlineKeyboardButton(t("buttons.applying", user_lang), callback_data="noop"))
    
    action_row.append(InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:record:{record_id}"))
    keyboard.append(action_row)
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        # Trigger auto-apply if conditions are met
        if await session.should_auto_apply():
            asyncio.create_task(auto_apply_with_feedback(query, None, session))
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def handle_delete_callback(query, context, callback_data):
    """Handle shortened delete callback: del:{record_id}"""
    try:
        # Extract record_id from callback data
        parts = callback_data.split(':')
        if len(parts) != 2:
            await safe_edit_message(query, "❌ Invalid Delete Action\n\nPlease try again.")
            return
        
        record_id = parts[1]
        
        # Get domain from stored context
        delete_context = context.user_data.get('delete_context')
        if not delete_context or delete_context.get('record_id') != record_id:
            await safe_edit_message(query, "❌ Session Expired\n\nPlease try the delete action again.")
            return
        
        domain = delete_context['domain']
        
        # Clean up context and execute deletion
        if 'delete_context' in context.user_data:
            del context.user_data['delete_context']
        
        await execute_dns_delete(query, context, domain, record_id)
        
    except Exception as e:
        logger.error(f"Error handling delete callback {callback_data}: {e}")
        await safe_edit_message(query, "❌ Delete Error\n\nCould not process deletion. Please try again.")

async def prompt_for_content_change(query, context, domain, record_id):
    """Prompt user to enter new TXT content"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"""
📝 Change TXT Content

Domain: {domain}

Please type the new content for this TXT record.

Type your new TXT content:
"""
    
    # Store context for text input handling
    context.user_data['edit_input'] = {
        'type': 'content',
        'domain': domain,
        'record_id': record_id
    }
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def prompt_for_ip_change(query, context, domain, record_id):
    """Prompt user to enter a new IP address"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"""
📝 Change IP Address

Domain: {domain}

Please type the new IP address for this A record.

Example: 192.168.1.1 or 8.8.8.8

Type your new IP address:
"""
    
    # Store context for text input handling
    context.user_data['edit_input'] = {
        'type': 'ip',
        'domain': domain,
        'record_id': record_id
    }
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def prompt_for_cname_target_change(query, context, domain, record_id):
    """Prompt user to enter new CNAME target"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"""
🔗 Change CNAME Target

Domain: {domain}

Please type the new target domain for this CNAME record.

Enter full domain name with extension.

Type your new CNAME target:
"""
    
    # Store context for text input handling
    context.user_data['edit_input'] = {
        'type': 'cname_target',
        'domain': domain,
        'record_id': record_id
    }
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def prompt_for_mx_server_change(query, context, domain, record_id):
    """Prompt user to enter new MX server"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"""
📧 Change MX Server

Domain: {domain}

Please type the new mail server for this MX record.

Type your new MX server:
"""
    
    # Store context for text input handling
    context.user_data['edit_input'] = {
        'type': 'mx_server',
        'domain': domain,
        'record_id': record_id
    }
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def prompt_for_mx_priority_change(query, context, domain, record_id):
    """Prompt user to select new MX priority"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"""
🔢 Change MX Priority

Domain: {domain}

Select the new priority for this MX record:

Lower numbers = higher priority
• 10 = Primary mail server
• 20 = Secondary mail server  
• 30 = Backup mail server
• 50 = Low priority backup

Choose your MX priority:
"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.priority_10", user_lang), callback_data=f"edit_mx_priority:{record_id}:10"),
         InlineKeyboardButton(t("buttons.priority_20", user_lang), callback_data=f"edit_mx_priority:{record_id}:20")],
        [InlineKeyboardButton(t("buttons.priority_30", user_lang), callback_data=f"edit_mx_priority:{record_id}:30"),
         InlineKeyboardButton(t("buttons.priority_50", user_lang), callback_data=f"edit_mx_priority:{record_id}:50")],
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def prompt_for_ttl_change(query, context, domain, record_id):
    """Show TTL selection buttons"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"""
⏰ Change TTL (Time To Live)

Domain: {domain}

Select the new TTL for this DNS record:
"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.auto_recommended", user_lang), callback_data=f"edit_ttl:{record_id}:1")],
        [InlineKeyboardButton(t("buttons.1_minute", user_lang), callback_data=f"edit_ttl:{record_id}:60")],
        [InlineKeyboardButton(t("buttons.5_minutes", user_lang), callback_data=f"edit_ttl:{record_id}:300")],
        [InlineKeyboardButton(t("buttons.30_minutes", user_lang), callback_data=f"edit_ttl:{record_id}:1800")],
        [InlineKeyboardButton(t("buttons.1_hour", user_lang), callback_data=f"edit_ttl:{record_id}:3600")],
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def toggle_proxy_setting(query, context, domain, record_id):
    """Toggle proxy setting for the DNS record with auto-apply"""
    try:
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        wizard_state = context.user_data.get('dns_wizard')
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get AutoApplySession
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'A', user_lang)
        
        # Get current proxy setting and IP address
        current_proxied = wizard_state['data'].get('proxied', 'false')
        new_proxied = 'false' if current_proxied == 'true' else 'true'
        ip_address = wizard_state['data'].get('content', '')
        
        # If trying to enable proxy, validate IP first
        if new_proxied == 'true' and ip_address:
            if not is_ip_proxyable(ip_address):
                # Show error message with detailed explanation
                error_message = get_proxy_restriction_message(ip_address, user_lang)
                
                keyboard = [
                    [InlineKeyboardButton(t("buttons.back_to_edit", user_lang), callback_data=await compress_callback(f"dns:{domain}:edit:{record_id}", context))]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await safe_edit_message(query, error_message, reply_markup=reply_markup)
                return
        
        # Update proxy setting using session
        session.update_field('proxied', new_proxied)
        
        # If enabling proxy, set TTL to Auto (1) as recommended by Cloudflare
        if new_proxied == 'true':
            session.update_field('ttl', '1')  # Auto TTL for proxied records (string for update_field)
            wizard_state['data']['ttl'] = 1  # Store as integer in wizard state
        
        # Update wizard state
        wizard_state['data']['proxied'] = new_proxied
        context.user_data['dns_wizard'] = wizard_state
        
        # Show updated edit interface with auto-apply
        await continue_a_record_edit_wizard(query, context, wizard_state)
        
    except Exception as e:
        logger.error(f"Error toggling proxy setting: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not toggle proxy setting.")

async def handle_dns_edit_callback(query, context, callback_data):
    """Handle DNS edit callback routing with auto-apply support"""
    try:
        # Parse callback: dns_edit:{domain}:{type}:{action}:{record_id}
        parts = callback_data.split(':')
        if len(parts) < 5:
            await safe_edit_message(query, "❌ Invalid Edit Action\n\nPlease try again.")
            return
        
        domain = parts[1]
        record_type = parts[2]
        action = parts[3]
        record_id = parts[4]
        
        # Handle different edit actions
        if action == "save":
            # Legacy save - redirect to record view since auto-apply handles saves now
            await safe_edit_message(query, "✅ Auto-Apply Active\n\nChanges are automatically applied when valid.")
            await asyncio.sleep(1.5)
            # Redirect to record view
            await show_dns_record_detail(query, domain, record_id)
        elif action == "revert":
            await handle_revert_changes(query, context, domain, record_type, record_id)
        elif action == "ip":
            await prompt_for_ip_change(query, context, domain, record_id)
        elif action == "content":
            # Handle content editing based on record type
            wizard_state = context.user_data.get('dns_wizard')
            if wizard_state and wizard_state.get('type') == 'CNAME':
                await prompt_for_cname_target_change(query, context, domain, record_id)
            elif wizard_state and wizard_state.get('type') == 'MX':
                await prompt_for_mx_server_change(query, context, domain, record_id)
            else:
                await prompt_for_content_change(query, context, domain, record_id)
        elif action == "priority":
            await prompt_for_mx_priority_change(query, context, domain, record_id)
        elif action == "ttl":
            await prompt_for_ttl_change(query, context, domain, record_id)
        elif action == "proxy":
            await toggle_proxy_setting(query, context, domain, record_id)
        else:
            await safe_edit_message(query, "❌ Unknown Edit Action\n\nPlease try again.")
            
    except Exception as e:
        logger.error(f"Error handling DNS edit callback {callback_data}: {e}")
        await safe_edit_message(query, "❌ Edit Error\n\nCould not process edit action.")

async def handle_revert_changes(query, context, domain, record_type, record_id):
    """Handle reverting changes back to original state"""
    try:
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        wizard_state = context.user_data.get('dns_wizard')
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get AutoApplySession and revert
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, record_type, user_lang)
        session.revert_to_original()
        
        # Update wizard state to match reverted state
        wizard_state['data'] = session.draft_state.copy()
        context.user_data['dns_wizard'] = wizard_state
        
        # Show success message and return to editing
        await safe_edit_message(query, "🔄 Changes Reverted\n\nRecord restored to original state.")
        await asyncio.sleep(1.0)
        
        # Return to appropriate editing interface
        if record_type == 'A':
            await continue_a_record_edit_wizard(query, context, wizard_state)
        # Add other record types as they are implemented
        else:
            await show_dns_record_detail(query, domain, record_id)
            
    except Exception as e:
        logger.error(f"Error reverting changes for {record_type} record {record_id}: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not revert changes.")

async def handle_ttl_selection(query, context, callback_data):
    """Handle TTL selection with auto-apply: edit_ttl:{record_id}:{ttl_value}"""
    try:
        parts = callback_data.split(':')
        if len(parts) != 3:
            await safe_edit_message(query, "❌ Invalid TTL Selection\n\nPlease try again.")
            return
        
        record_id = parts[1]
        ttl_value = parts[2]
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Update wizard state with new TTL
        wizard_state = context.user_data.get('dns_wizard')
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get domain and record type for auto-apply session
        domain = wizard_state['domain']
        record_type = wizard_state.get('type', 'A').upper()
        
        # Get AutoApplySession and update TTL
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, record_type, user_lang)
        validation = session.update_field('ttl', ttl_value)
        
        # Update wizard data (convert to integer to match validation expectations)
        wizard_state['data']['ttl'] = int(ttl_value)
        context.user_data['dns_wizard'] = wizard_state
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ TTL Update Failed\n\n{validation['errors'].get('ttl', 'Invalid TTL value')}"
            await safe_edit_message(query, error_message)
            return
        
        # Show updated edit interface with auto-apply (A records only for now)
        await continue_a_record_edit_wizard(query, context, wizard_state)
        
    except Exception as e:
        logger.error(f"Error handling TTL selection {callback_data}: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not update TTL.")

async def handle_mx_priority_selection(query, context, callback_data):
    """Handle MX priority selection: edit_mx_priority:{record_id}:{priority}"""
    try:
        parts = callback_data.split(':')
        if len(parts) != 3:
            await safe_edit_message(query, create_error_message("Invalid Priority Selection", "Please try again."))
            return
        
        record_id = parts[1]
        priority_value = parts[2]
        
        # Validate priority value
        try:
            priority = int(priority_value)
            if priority < 0 or priority > 65535:
                await safe_edit_message(query, create_error_message("Invalid Priority", "Priority must be between 0 and 65535."))
                return
        except ValueError:
            await safe_edit_message(query, create_error_message("Invalid Priority Format", "Priority must be a number."))
            return
        
        # Update wizard state with new priority
        wizard_state = context.user_data.get('dns_wizard')
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Update priority in wizard data
        wizard_state['data']['priority'] = priority_value
        context.user_data['dns_wizard'] = wizard_state
        
        # Show success message and return to edit interface
        await safe_edit_message(query, f"✅ Priority Updated\n\nNew priority: {priority}\n\nReturning to edit menu...")
        
        # Brief pause then show edit interface
        import asyncio
        await asyncio.sleep(1)
        await continue_mx_record_edit_wizard(query, wizard_state)
        
    except Exception as e:
        logger.error(f"Error handling MX priority selection {callback_data}: {e}")
        await safe_edit_message(query, "❌ Priority Update Error\n\nCould not update priority. Please try again.")

async def handle_content_input(update, context, text, edit_input):
    """Handle TXT content input during record editing with auto-apply"""
    try:
        # Validate TXT content
        content = text.strip()
        
        if not content:
            await update.message.reply_text(
                "❌ Empty Content\n\nPlease enter some content for the TXT record.\n\nTry again:"
            )
            return
        
        if len(content) > 4096:  # Cloudflare limit
            await update.message.reply_text(
                "❌ Content Too Long\n\nTXT content cannot exceed 4096 characters.\n\nTry again:"
            )
            return
        
        # Update wizard state and session
        wizard_state = context.user_data.get('dns_wizard')
        record_id = edit_input['record_id']
        domain = edit_input['domain']
        user = update.effective_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await update.message.reply_text(f"❌ <b>{t('errors.session_expired_edit', user_lang)}</b>")
            return
        
        # Get AutoApplySession and update content
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'TXT', user_lang)
        validation = session.update_field('content', content)
        
        # Update wizard data
        wizard_state['data']['content'] = content
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear edit input context
        if 'edit_input' in context.user_data:
            del context.user_data['edit_input']
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ Content Update Failed\n\n{validation['errors'].get('content', 'Invalid content')}\n\nPlease enter different content:"
            await update.message.reply_text(error_message)
            return
        
        # Show success message
        await update.message.reply_text(
            f"✅ Content Updated\n\nNew content: {content[:50]}{'...' if len(content) > 50 else ''}\n\n⚡ Auto-applying change..."
        )
        
        # Brief pause then show updated interface with auto-apply
        await asyncio.sleep(0.5)
        
        # Create a query adapter for the auto-apply edit wizard
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=update.message.message_id,
            user_id=user.id
        )
        
        await continue_txt_record_edit_wizard_as_message(update, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
            
    except Exception as e:
        logger.error(f"Error handling content input: {e}")
        await update.message.reply_text(
            "❌ Input Error\n\nPlease try again."
        )

async def continue_txt_record_edit_wizard_as_message(update, context, wizard_state):
    """Show TXT record edit wizard as a new message"""
    user = update.effective_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Build edit interface
    name_display = data['name'] if data['name'] != '@' else domain
    content_display, parse_mode = escape_content_for_display(data['content'], mode="full")
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
📝 Edit TXT Record: {domain}

Name: {name_summary} (read-only)
Content: {content_display}
TTL: {ttl_display}

Click to modify any field below:
"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.change_content", user_lang), callback_data=f"dns_edit:{domain}:TXT:content:{record_id}")],
        [InlineKeyboardButton(t("buttons.change_ttl", user_lang), callback_data=f"dns_edit:{domain}:TXT:ttl:{record_id}")],
        [InlineKeyboardButton(t("buttons.save_changes", user_lang), callback_data=f"dns_edit:{domain}:TXT:save:{record_id}")],
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain}:record:{record_id}")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        message,
        reply_markup=reply_markup,
        parse_mode='HTML'
    )

async def handle_dns_wizard_txt_input(update, context, txt_content, wizard_state):
    """Handle TXT content input during DNS wizard"""
    try:
        # Validate TXT content (basic validation - not empty and reasonable length)
        txt_content = txt_content.strip()
        
        if not txt_content:
            await update.message.reply_text(
                "❌ Empty TXT Content\n\nPlease enter some content for your TXT record.\n\nTry again:"
            )
            return
        
        if len(txt_content) > 4096:  # Cloudflare limit for TXT records
            await update.message.reply_text(
                "❌ TXT Content Too Long\n\nTXT records cannot exceed 4096 characters.\n\nPlease enter shorter content:"
            )
            return
        
        # Update wizard state with TXT content
        wizard_state['data']['content'] = txt_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Get the bot's last message ID from wizard state (not user's input message)
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            # Fallback: send new message instead of editing
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
            
        # Create adapter for continue_txt_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step
        await continue_txt_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
            
    except Exception as e:
        logger.error(f"Error handling TXT content input: {e}")
        await update.message.reply_text(
            "❌ Input Error\n\nPlease try entering your TXT content again:"
        )

async def handle_cname_target_input(update, context, target_content, edit_input):
    """Handle CNAME target input during record editing with auto-apply"""
    try:
        # Validate CNAME target
        target_content = target_content.strip()
        
        if not target_content:
            await update.message.reply_text(
                "❌ <b>Empty CNAME Target</b>\n\nPlease enter a target domain for your CNAME record.\n\nTry again:"
            )
            return
        
        # Update wizard state and session
        wizard_state = context.user_data.get('dns_wizard')
        record_id = edit_input['record_id']
        domain = edit_input['domain']
        user = update.effective_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await update.message.reply_text(f"❌ <b>{t('errors.session_expired_edit', user_lang)}</b>")
            return
        
        # Get AutoApplySession and update target
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'CNAME', user_lang)
        validation = session.update_field('content', target_content)
        
        # Update wizard data
        wizard_state['data']['content'] = target_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear edit input context
        if 'edit_input' in context.user_data:
            del context.user_data['edit_input']
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ Target Update Failed\n\n{validation['errors'].get('content', 'Invalid target domain')}\n\nPlease enter a different target:"
            await update.message.reply_text(error_message)
            return
        
        # Show success message
        await update.message.reply_text(
            f"✅ CNAME Target Updated\n\nNew target: {target_content}\n\n⚡ Auto-applying change..."
        )
        
        # Brief pause then show updated interface with auto-apply
        await asyncio.sleep(0.5)
        
        # Create a query adapter for the auto-apply edit wizard
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=update.message.message_id,
            user_id=user.id
        )
        
        await continue_cname_record_edit_wizard_as_message(update, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
        
    except Exception as e:
        logger.error(f"Error handling CNAME target input: {e}")
        await update.message.reply_text("❌ Error\n\nCould not process CNAME target.")

async def handle_mx_server_input(update, context, server_content, edit_input):
    """Handle MX server input during record editing with auto-apply"""
    try:
        # Validate MX server
        server_content = server_content.strip()
        
        if not server_content:
            await update.message.reply_text(
                "❌ <b>Empty Mail Server</b>\n\nPlease enter a mail server for your MX record.\n\nTry again:"
            )
            return
        
        # Update wizard state and session
        wizard_state = context.user_data.get('dns_wizard')
        record_id = edit_input['record_id']
        domain = edit_input['domain']
        user = update.effective_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await update.message.reply_text(f"❌ <b>{t('errors.session_expired_edit', user_lang)}</b>")
            return
        
        # Get AutoApplySession and update server
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'MX', user_lang)
        validation = session.update_field('content', server_content)
        
        # Update wizard data
        wizard_state['data']['content'] = server_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear edit input context
        if 'edit_input' in context.user_data:
            del context.user_data['edit_input']
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ <b>Server Update Failed</b>\n\n{validation['errors'].get('content', 'Invalid mail server')}\n\nPlease enter a different server:"
            await update.message.reply_text(error_message)
            return
        
        # Show success message
        await update.message.reply_text(
            f"✅ <b>MX Server Updated</b>\n\nNew server: <code>{server_content}</code>\n\n⚡ Auto-applying change..."
        )
        
        # Brief pause then show updated interface with auto-apply
        await asyncio.sleep(0.5)
        
        # Create a query adapter for the auto-apply edit wizard
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=update.message.message_id,
            user_id=user.id
        )
        
        await continue_mx_record_edit_wizard_as_message(update, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
        
    except Exception as e:
        logger.error(f"Error handling MX server input: {e}")
        await update.message.reply_text("❌ Error\n\nCould not process MX server.")

async def continue_cname_record_edit_wizard_as_message(update, context, wizard_state):
    """Show CNAME record edit wizard as a new message"""
    user = update.effective_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Show edit interface with editable fields
    name_display = data['name'] if data['name'] != domain else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    target_display, _ = escape_content_for_display(data['content'], mode="summary")
    
    message = f"""
✏️ <b>Edit CNAME Record: {domain}</b>

<b>Current Configuration:</b>
Name: <code>{name_display}</code> (read-only)
<b>Target:</b> <code>{target_display}</code>
TTL: {ttl_display}

<b>Click to modify any field below:</b>
"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.change_target", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:CNAME:content:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.change_ttl", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:CNAME:ttl:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.save_changes", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:CNAME:save:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=await compress_callback(f"dns:{domain}:record:{record_id}", context))]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, reply_markup=reply_markup)

async def continue_mx_record_edit_wizard_as_message(update, context, wizard_state):
    """Show MX record edit wizard as a new message"""
    user = update.effective_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Show edit interface with editable fields
    name_display = data['name'] if data['name'] != domain else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    server_display, _ = escape_content_for_display(data['content'], mode="summary")
    priority = data.get('priority', '10')
    
    message = f"""
✏️ <b>Edit MX Record: {domain}</b>

<b>Current Configuration:</b>
Name: <code>{name_display}</code> (read-only)
<b>Mail Server:</b> <code>{server_display}</code>
Priority: {priority}
TTL: {ttl_display}

<b>Click to modify any field below:</b>
"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.change_server", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:MX:content:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.change_priority", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:MX:priority:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.change_ttl", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:MX:ttl:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.save_changes", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:MX:save:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=await compress_callback(f"dns:{domain}:record:{record_id}", context))]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, reply_markup=reply_markup)

async def handle_custom_subdomain_input(update, context, subdomain_name, custom_input):
    """Handle custom subdomain name input for CNAME wizard"""
    try:
        import re
        
        subdomain_name = subdomain_name.strip().lower()
        wizard_state = custom_input['wizard_state']
        domain = custom_input['domain']
        
        # Validate subdomain format
        if not subdomain_name:
            await update.message.reply_text(
                "❌ <b>Empty Subdomain</b>\n\nPlease enter a subdomain name.\n\nTry again:"
            )
            return
        
        # Allow @ for root domain
        if subdomain_name == '@':
            # Use @ as-is for root domain
            pass
        else:
            # Validate subdomain format (RFC 1123)
            # - Letters, numbers, hyphens only
            # - Cannot start or end with hyphen
            # - Max 63 characters per label
            subdomain_pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
            
            if not re.match(subdomain_pattern, subdomain_name):
                await update.message.reply_text(
                    "❌ <b>Invalid Subdomain Format</b>\n\n"
                    "Subdomain must:\n"
                    "• Start and end with letter/number\n"
                    "• Contain only letters, numbers, hyphens\n"
                    "• Be 1-63 characters long\n\n"
                    "Examples: shop, staging, api-v2\n\n"
                    "Try again:"
                )
                return
        
        # Check for conflicts with existing records
        cf_zone = await get_cloudflare_zone(domain)
        if cf_zone:
            cloudflare = CloudflareService()
            existing_records = await cloudflare.list_dns_records(cf_zone['cf_zone_id'])
            
            # Check if subdomain already has records
            full_name = domain if subdomain_name == '@' else f"{subdomain_name}.{domain}"
            for record in existing_records:
                if record.get('name') == full_name:
                    record_type = record.get('type', 'Unknown')
                    await update.message.reply_text(
                        f"❌ <b>Subdomain Conflict</b>\n\n"
                        f"<code>{subdomain_name}</code> already has a {record_type} record.\n\n"
                        f"CNAME records cannot coexist with other record types.\n\n"
                        f"Try a different subdomain:"
                    )
                    return
        
        # Update wizard state with validated custom subdomain
        wizard_state['data']['name'] = subdomain_name
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear custom subdomain context
        if 'expecting_custom_subdomain' in context.user_data:
            del context.user_data['expecting_custom_subdomain']
        
        # Get the bot's last message ID from wizard state
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
        
        # Create adapter for continue_cname_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step (target domain)
        await continue_cname_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass
            
    except Exception as e:
        logger.error(f"Error handling custom subdomain input: {e}")
        await update.message.reply_text(
            "❌ <b>Input Error</b>\n\nPlease try entering your subdomain again:"
        )

async def handle_custom_subdomain_a_input(update, context, subdomain_name, custom_input):
    """Handle custom subdomain name input for A record wizard"""
    try:
        import re
        
        subdomain_name = subdomain_name.strip().lower()
        wizard_state = custom_input['wizard_state']
        domain = custom_input['domain']
        
        # Validate subdomain format
        if not subdomain_name:
            await update.message.reply_text(
                "❌ <b>Empty Subdomain</b>\n\nPlease enter a subdomain name.\n\nTry again:"
            )
            return
        
        # Allow @ for root domain
        if subdomain_name == '@':
            # Use @ as-is for root domain
            pass
        else:
            # Validate subdomain format (RFC 1123)
            subdomain_pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
            
            if not re.match(subdomain_pattern, subdomain_name):
                await update.message.reply_text(
                    "❌ <b>Invalid Subdomain Format</b>\n\n"
                    "Subdomain must:\n"
                    "• Start and end with letter/number\n"
                    "• Contain only letters, numbers, hyphens\n"
                    "• Be 1-63 characters long\n\n"
                    "Examples: www, api, server-1\n\n"
                    "Try again:"
                )
                return
        
        # Check for CNAME conflicts (A records cannot coexist with CNAME)
        cf_zone = await get_cloudflare_zone(domain)
        if cf_zone:
            cloudflare = CloudflareService()
            existing_records = await cloudflare.list_dns_records(cf_zone['cf_zone_id'])
            
            # Check if subdomain has CNAME record
            full_name = domain if subdomain_name == '@' else f"{subdomain_name}.{domain}"
            for record in existing_records:
                if record.get('name') == full_name and record.get('type') == 'CNAME':
                    await update.message.reply_text(
                        f"❌ <b>CNAME Conflict</b>\n\n"
                        f"<code>{subdomain_name}</code> already has a CNAME record.\n\n"
                        f"A records cannot coexist with CNAME records.\n\n"
                        f"Try a different subdomain:"
                    )
                    return
        
        # Update wizard state with validated custom subdomain
        wizard_state['data']['name'] = subdomain_name
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear custom subdomain context
        if 'expecting_custom_subdomain_a' in context.user_data:
            del context.user_data['expecting_custom_subdomain_a']
        
        # Get the bot's last message ID from wizard state
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
        
        # Create adapter for continue_a_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step (IP address)
        await continue_a_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass
            
    except Exception as e:
        logger.error(f"Error handling A record custom subdomain input: {e}")
        await update.message.reply_text(
            "❌ <b>Input Error</b>\n\nPlease try entering your subdomain again:"
        )

async def handle_custom_subdomain_txt_input(update, context, subdomain_name, custom_input):
    """Handle custom subdomain name input for TXT record wizard"""
    try:
        import re
        
        subdomain_name = subdomain_name.strip().lower()
        wizard_state = custom_input['wizard_state']
        domain = custom_input['domain']
        
        # Validate subdomain format
        if not subdomain_name:
            await update.message.reply_text(
                "❌ <b>Empty Subdomain</b>\n\nPlease enter a subdomain name.\n\nTry again:"
            )
            return
        
        # Allow @ for root domain
        if subdomain_name == '@':
            # Use @ as-is for root domain
            pass
        else:
            # Validate subdomain format (RFC 1123 with underscore support for TXT records)
            # TXT records allow underscores for special use cases (_dmarc, _domainkey, etc.)
            # - Letters, numbers, hyphens, underscores
            # - Cannot start or end with hyphen
            # - Max 63 characters per label
            subdomain_pattern = r'^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$'
            
            if not re.match(subdomain_pattern, subdomain_name):
                await update.message.reply_text(
                    "❌ <b>Invalid Subdomain Format</b>\n\n"
                    "Subdomain must:\n"
                    "• Start and end with letter/number/underscore\n"
                    "• Contain only letters, numbers, hyphens, underscores\n"
                    "• Be 1-63 characters long\n\n"
                    "Examples: _dmarc, mail, verification-code\n\n"
                    "Try again:"
                )
                return
        
        # Update wizard state with validated custom subdomain (no conflict check for TXT)
        wizard_state['data']['name'] = subdomain_name
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear custom subdomain context
        if 'expecting_custom_subdomain_txt' in context.user_data:
            del context.user_data['expecting_custom_subdomain_txt']
        
        # Get the bot's last message ID from wizard state
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
        
        # Create adapter for continue_txt_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step (TXT content)
        await continue_txt_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass
            
    except Exception as e:
        logger.error(f"Error handling TXT record custom subdomain input: {e}")
        await update.message.reply_text(
            "❌ <b>Input Error</b>\n\nPlease try entering your subdomain again:"
        )

async def handle_dns_wizard_cname_input(update, context, target_content, wizard_state):
    """Handle CNAME target input during DNS wizard"""
    try:
        # Validate CNAME target (basic validation - not empty and reasonable format)
        target_content = target_content.strip()
        
        if not target_content:
            await update.message.reply_text(
                "❌ <b>Empty CNAME Target</b>\n\nPlease enter a target domain for your CNAME record.\n\nTry again:"
            )
            return
        
        # Basic domain format validation (must contain a dot and be reasonable length)
        if '.' not in target_content or len(target_content) < 3:
            await update.message.reply_text(
                "❌ Invalid Domain Format\n\nPlease enter a valid domain name (e.g., example.com).\n\nTry again:"
            )
            return
        
        if len(target_content) > 253:  # RFC limit for domain names
            await update.message.reply_text(
                "❌ <b>Domain Name Too Long</b>\n\nDomain names cannot exceed 253 characters.\n\nPlease enter a shorter domain:"
            )
            return
        
        # Update wizard state with CNAME target
        wizard_state['data']['target'] = target_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Get the bot's last message ID from wizard state (not user's input message)
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            # Fallback: send new message instead of editing
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
            
        # Create adapter for continue_cname_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step
        await continue_cname_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
            
    except Exception as e:
        logger.error(f"Error handling CNAME target input: {e}")
        await update.message.reply_text(
            "❌ <b>Input Error</b>\n\nPlease try entering your CNAME target again:"
        )

async def handle_custom_subdomain_mx_input(update, context, subdomain_name, custom_input):
    """Handle custom subdomain name input for MX record wizard"""
    try:
        import re
        
        subdomain_name = subdomain_name.strip().lower()
        wizard_state = custom_input['wizard_state']
        domain = custom_input['domain']
        user = update.effective_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Validate subdomain format
        if not subdomain_name:
            await update.message.reply_text(
                f"❌ <b>{t('errors.empty_subdomain', user_lang)}</b>\n\n{t('errors.try_again', user_lang)}"
            )
            return
        
        # Allow @ for root domain
        if subdomain_name == '@':
            # Use @ as-is for root domain
            pass
        else:
            # Validate subdomain format (RFC 1123)
            subdomain_pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
            
            if not re.match(subdomain_pattern, subdomain_name):
                await update.message.reply_text(
                    f"❌ <b>{t('errors.invalid_subdomain_format', user_lang)}</b>\n\n"
                    f"{t('errors.subdomain_rules', user_lang)}\n\n"
                    f"{t('errors.try_again', user_lang)}"
                )
                return
        
        # Check for CNAME conflicts (MX records cannot coexist with CNAME)
        cf_zone = await get_cloudflare_zone(domain)
        if cf_zone:
            cloudflare = CloudflareService()
            existing_records = await cloudflare.list_dns_records(cf_zone['cf_zone_id'])
            
            # Check if subdomain has CNAME record
            full_name = domain if subdomain_name == '@' else f"{subdomain_name}.{domain}"
            for record in existing_records:
                if record.get('name') == full_name and record.get('type') == 'CNAME':
                    await update.message.reply_text(
                        f"❌ <b>{t('errors.cname_conflict_title', user_lang)}</b>\n\n"
                        f"<code>{subdomain_name}</code> {t('errors.has_cname_record', user_lang)}\n\n"
                        f"{t('errors.mx_cname_conflict', user_lang)}\n\n"
                        f"{t('errors.try_different_subdomain', user_lang)}"
                    )
                    return
        
        # Update wizard state with validated custom subdomain
        wizard_state['data']['name'] = subdomain_name
        wizard_state['data']['custom_name_entered'] = True
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear custom subdomain context
        if 'expecting_custom_subdomain_mx' in context.user_data:
            del context.user_data['expecting_custom_subdomain_mx']
        
        # Get the bot's last message ID from wizard state
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            await update.message.reply_text(
                f"❌ <b>{t('errors.wizard_error', user_lang)}</b>\n\n{t('errors.restart_wizard', user_lang)}"
            )
            return
        
        # Create adapter for continue_mx_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step (Mail Server)
        await continue_mx_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass
            
    except Exception as e:
        logger.error(f"Error handling MX record custom subdomain input: {e}")
        await update.message.reply_text(
            f"❌ <b>{t('errors.input_error', user_lang)}</b>\n\n{t('errors.try_again', user_lang)}"
        )

async def handle_dns_wizard_mx_input(update, context, server_content, wizard_state):
    """Handle MX server input during DNS wizard"""
    try:
        # Validate MX server (basic validation - not empty and reasonable format)
        server_content = server_content.strip()
        
        if not server_content:
            await update.message.reply_text(
                "❌ <b>Empty Mail Server</b>\n\nPlease enter a mail server for your MX record.\n\nTry again:"
            )
            return
        
        # Basic mail server format validation (must contain a dot and be reasonable length)
        if '.' not in server_content or len(server_content) < 3:
            await update.message.reply_text(
                "❌ <b>Invalid Server Format</b>\n\nPlease enter a valid mail server (e.g., mail.example.com).\n\nTry again:"
            )
            return
        
        if len(server_content) > 253:  # RFC limit for domain names
            await update.message.reply_text(
                "❌ <b>Server Name Too Long</b>\n\nServer names cannot exceed 253 characters.\n\nPlease enter a shorter server name:"
            )
            return
        
        # Update wizard state with MX server
        wizard_state['data']['server'] = server_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Get the bot's last message ID from wizard state (not user's input message)
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            # Fallback: send new message instead of editing
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
            
        # Create adapter for continue_mx_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step
        await continue_mx_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
            
    except Exception as e:
        logger.error(f"Error handling MX server input: {e}")
        await update.message.reply_text(
            "❌ Input Error\n\nPlease try entering your mail server again:"
        )

async def handle_dns_wizard_ip_input(update, context, ip_address, wizard_state):
    """Handle IP address input during DNS wizard"""
    try:
        # Validate IP address format
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        if not re.match(ip_pattern, ip_address.strip()):
            await update.message.reply_text(
                "❌ <b>Invalid IP Address</b>\n\nPlease enter a valid IPv4 address (e.g., 192.168.1.1)\n\nTry again:"
            )
            return
        
        # Update wizard state with IP address
        wizard_state['data']['ip'] = ip_address.strip()
        wizard_state['data']['content'] = ip_address.strip()  # For record creation
        context.user_data['dns_wizard'] = wizard_state
        
        # Continue to next step of wizard
        # Send confirmation and continue wizard
        name_display = wizard_state['data'].get('name', '@')
        
        await update.message.reply_text(
            f"✅ <b>IP Address Set</b>\n\nName: <code>{name_display}</code>\nIP: <code>{ip_address.strip()}</code>\n\nContinuing to next step..."
        )
        
        # Brief pause then send next wizard step as new message
        import asyncio
        await asyncio.sleep(1)
        
        # Show next step of wizard based on current state
        await show_next_wizard_step(update.message, context, wizard_state)
        
    except Exception as e:
        logger.error(f"Error handling DNS wizard IP input: {e}")
        await update.message.reply_text("❌ Error\n\nCould not process IP address.")

async def handle_ip_input(update, context, ip_address, edit_input):
    """Handle IP address input for editing with auto-apply"""
    try:
        # Validate IP address format
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        if not re.match(ip_pattern, ip_address.strip()):
            await update.message.reply_text(
                "❌ <b>Invalid IP Address</b>\n\nPlease enter a valid IPv4 address (e.g., 192.168.1.1)\n\nTry again:"
            )
            return
        
        # Update wizard state and session
        wizard_state = context.user_data.get('dns_wizard')
        record_id = edit_input['record_id']
        domain = edit_input['domain']
        user = update.effective_user
        
        # Get user_lang early for all uses in this function
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await update.message.reply_text(f"❌ <b>{t('errors.session_expired_edit', user_lang)}</b>")
            return
        
        # Get AutoApplySession and update IP
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'A', user_lang)
        validation = session.update_field('content', ip_address.strip())
        
        # Update wizard data
        wizard_state['data']['content'] = ip_address.strip()
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear edit input context
        if 'edit_input' in context.user_data:
            del context.user_data['edit_input']
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ IP Update Failed\n\n{validation['errors'].get('content', 'Invalid IP address')}\n\nPlease enter a different IP address:"
            await update.message.reply_text(error_message)
            return
        
        # Show immediate success with auto-apply in progress
        success_msg = await update.message.reply_text(
            f"✅ IP Updated\n\nNew IP: {ip_address.strip()}\n\n⚡ Auto-applying to Cloudflare..."
        )
        
        # Poll for auto-apply completion (max 2 seconds, check every 0.3s)
        max_wait = 2.0
        poll_interval = 0.3
        elapsed = 0
        
        while elapsed < max_wait:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            
            # Check if auto-apply is complete
            if not session.is_applying:
                break
        
        # Show completion with link back to DNS records
        keyboard = [
            [InlineKeyboardButton(t("buttons.back_to_dns_records", user_lang), callback_data=await compress_callback(f"dns:{domain}:list", context))]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        status_emoji = "🌐" if not session.is_applying else "⏳"
        status_text = "DNS record has been updated on Cloudflare" if not session.is_applying else "DNS update in progress..."
        
        try:
            await success_msg.edit_text(
                f"✅ IP Updated Successfully\n\nNew IP: {ip_address.strip()}\n\n{status_emoji} {status_text}",
                reply_markup=reply_markup
            )
        except Exception:
            # If edit fails, send new message
            await update.message.reply_text(
                f"✅ IP Updated Successfully\n\nNew IP: {ip_address.strip()}\n\n{status_emoji} {status_text}",
                reply_markup=reply_markup
            )
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
        
    except Exception as e:
        logger.error(f"Error handling IP input: {e}")
        await update.message.reply_text("❌ Error\n\nCould not process IP address.")

async def continue_a_record_edit_wizard_as_message(update, context, wizard_state):
    """Show A record edit wizard as a new message"""
    user = update.effective_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Show edit interface with editable fields
    name_display = data['name'] if data['name'] != domain else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    proxy_display = "🟠 Proxied" if data['proxied'] == "true" else "⚪ Direct"
    
    message = f"""
✏️ Edit A Record: {domain}

Current Configuration:
Name: {name_display} (read-only)
IP Address: {data['content']}
TTL: {ttl_display}
Proxy Status: {proxy_display}

<b>Click to modify any field below:</b>
"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.change_ip_address", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:A:ip:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.change_ttl", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:A:ttl:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.toggle_proxy", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:A:proxy:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.save_changes", user_lang), callback_data=await compress_callback(f"dns_edit:{domain}:A:save:{record_id}", context))],
        [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=await compress_callback(f"dns:{domain}:record:{record_id}", context))]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, reply_markup=reply_markup)

async def save_dns_record_changes(query, context, domain, record_type, record_id):
    """Save DNS record changes from edit wizard"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get wizard state
        wizard_state = context.user_data.get('dns_wizard')
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, t('dns.session_expired', user_lang))
            return
        
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, t('dns.access_denied', user_lang))
            return
        
        # Get Cloudflare zone
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, t('dns.dns_unavailable', user_lang, domain=domain))
            return
        
        # Show updating message
        await safe_edit_message(query, t('dns.updating_record', user_lang))
        
        # Update DNS record using CloudflareService
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        data = wizard_state['data']
        
        # Prepare record data based on record type
        record_name = data['name']
        record_content = data['content']
        record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        
        if record_type == "A":
            record_proxied = data['proxied'] == 'true'
            
            # Update A record
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=record_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl,
                proxied=record_proxied
            )
            
            if result and result.get('success') and result.get('result', {}).get('id'):
                # Success message for A record
                name_display = record_name if record_name != domain else domain
                ttl_display = "Auto" if record_ttl == 1 else f"{record_ttl}s"
                proxy_display = "🟠 Proxied" if record_proxied else "⚪ Direct"
                
                message = t('dns.update_success', user_lang, domain=domain, type='A', proxy=proxy_display, name=name_display, content=record_content, ttl=ttl_display)
            else:
                message = t('dns.update_failed', user_lang, domain=domain, type=record_type, name=data.get('name', 'Unknown'))
                
        elif record_type == "CNAME":
            # Update CNAME record
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=record_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl
            )
            
            if result and result.get('success') and result.get('result', {}).get('id'):
                # Success message for CNAME record
                name_display = record_name if record_name != domain else domain
                ttl_display = "Auto" if record_ttl == 1 else f"{record_ttl}s"
                target_display, _ = escape_content_for_display(record_content, mode="summary")
                
                message = t('dns.update_success', user_lang, domain=domain, type='CNAME', proxy='', name=name_display, content=target_display, ttl=ttl_display)
            else:
                message = f"""
❌ DNS Record Update Failed

Domain: {domain}
Record: {record_type} {data.get('name', 'Unknown')}

Could not update the CNAME record. Please verify the target domain is valid.
"""
                
        elif record_type == "MX":
            # MX records need priority parameter
            record_priority = int(data.get('priority', 10))
            
            # Update MX record
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=record_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl,
                priority=record_priority
            )
            
            if result and result.get('success') and result.get('result', {}).get('id'):
                # Success message for MX record
                name_display = record_name if record_name != domain else domain
                ttl_display = "Auto" if record_ttl == 1 else f"{record_ttl}s"
                server_display, _ = escape_content_for_display(record_content, mode="summary")
                
                message = f"""
✅ DNS Record Updated

Domain: {domain}
Type: MX
Name: {name_display}
Mail Server: {server_display}
Priority: {record_priority}
TTL: {ttl_display}

Record updated and active.
"""
            else:
                message = f"""
❌ DNS Record Update Failed

Domain: {domain}
Record: {record_type} {data.get('name', 'Unknown')}

Could not update the MX record. Please verify the mail server is valid.
"""
                
        elif record_type == "TXT":
            # Update TXT record
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=record_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl
            )
            
            if result and result.get('success') and result.get('result', {}).get('id'):
                # Success message for TXT record
                name_display = record_name if record_name != domain else domain
                ttl_display = "Auto" if record_ttl == 1 else f"{record_ttl}s"
                content_preview = record_content[:50] + "..." if len(record_content) > 50 else record_content
                
                message = f"""
✅ DNS Record Updated

Domain: {domain}
Type: TXT
Name: {name_display}
Content: {content_preview}
TTL: {ttl_display}

Record updated and active.
"""
            else:
                message = f"""
❌ DNS Record Update Failed

Domain: {domain}
Record: {record_type} {data.get('name', 'Unknown')}

Could not update the TXT record. Please try again.
"""
        else:
            # Unsupported record type for editing
            message = f"""
🚧 Edit Not Supported

Editing {record_type} records is not yet supported. You can:
• Delete and recreate the record
• Use the Cloudflare dashboard for advanced editing
"""
            
        # Clear wizard state if update was successful  
        result = locals().get('result')
        if result and result.get('success') and result.get('result', {}).get('id'):
            if 'dns_wizard' in context.user_data:
                del context.user_data['dns_wizard']
            
            # CRITICAL: Sync updated record to database for dashboard display
            try:
                from database import update_single_dns_record_in_db
                record_data = result.get('result', {})
                if record_data:
                    await update_single_dns_record_in_db(domain, record_data)
                    logger.info(f"✅ DNS record update synced to database: {record_type} for {domain}")
            except Exception as db_err:
                logger.warning(f"Failed to sync DNS record update to database: {db_err}")
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.view_record_details", user_lang), callback_data=f"dns:{domain}:record:{record_id}")],
                [InlineKeyboardButton(t("buttons.records", user_lang), callback_data=f"dns:{domain}:list")],
                [InlineKeyboardButton(t("buttons.add_new_record", user_lang), callback_data=f"dns:{domain}:add")],
                [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=f"dns:{domain}:view")]
            ]
        else:
            # Failed update or unsupported type
            keyboard = [
                [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"dns:{domain}:edit:{record_id}")],
                [InlineKeyboardButton(t("buttons.view_record_details", user_lang), callback_data=f"dns:{domain}:record:{record_id}")],
                [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=f"dns:{domain}:view")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error saving DNS record changes: {e}")
        await safe_edit_message(query, "❌ Update Error\n\nCould not save changes. Please try again.")

async def show_next_wizard_step(message, context, wizard_state):
    """Show next wizard step as new message instead of editing existing one"""
    user = message.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        domain = wizard_state['domain']
        record_type = wizard_state['type']
        data = wizard_state['data']
        
        if record_type == 'A':
            if 'name' not in data:
                # Step 1: Name/Host
                message_text = f"""
🅰️ Add A Record (1/4): {domain}

Enter the name/host for this A record.
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.use_root", user_lang), callback_data=f"dns_wizard:{domain}:A:name:@")],
                    [InlineKeyboardButton(t("buttons.use_www", user_lang), callback_data=f"dns_wizard:{domain}:A:name:www")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain}:add")]
                ]
            elif 'ip' not in data:
                # This shouldn't happen as we just set the IP, but safety check
                message_text = f"✅ IP Address Set\n\nReturning to wizard menu..."
                keyboard = [[InlineKeyboardButton(t("buttons.back_to_dns", user_lang), callback_data=f"dns:{domain}:view")]]
            elif 'ttl' not in data:
                # Step 3: TTL
                name_display = data['name'] if data['name'] != '@' else domain
                message_text = f"""
🅰️ Add A Record (3/4): {domain}

Name: {name_display}
IP: {data['ip']}

Select TTL (Time To Live):
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.auto_recommended_label", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:1")],
                    [InlineKeyboardButton(t("buttons.5_minutes_label", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:300")],
                    [InlineKeyboardButton(t("buttons.1_hour_label", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:3600"),
                     InlineKeyboardButton(t("buttons.1_day", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:86400")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:ip:back")]
                ]
            elif 'proxied' not in data:
                # Step 4: Proxy Setting
                name_display = data['name'] if data['name'] != '@' else domain
                ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
                message_text = f"""
🅰️ Add A Record (4/4): {domain}

Name: {name_display}
IP: {data['ip']}
TTL: {ttl_display}

Enable Cloudflare Proxy?

🔒 Proxied (Recommended): Hide your server IP, get DDoS protection & caching
🌐 DNS Only: Direct connection to your server
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.enable_proxy_recommended", user_lang), callback_data=f"dns_wizard:{domain}:A:proxied:true")],
                    [InlineKeyboardButton(t("buttons.dns_only", user_lang), callback_data=f"dns_wizard:{domain}:A:proxied:false")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:ttl:back")]
                ]
            else:
                # All data collected, show final confirmation
                name_display = data['name'] if data['name'] != '@' else domain
                ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
                proxy_display = "🔒 Proxied" if data['proxied'] == 'true' else "🌐 DNS Only"
                
                message_text = f"""
✅ Create A Record - Final Confirmation

Domain: {domain}
Name: {name_display}
IP Address: {data['ip']}
TTL: {ttl_display}
Proxy: {proxy_display}

Confirm to create this DNS record?
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.create_record", user_lang), callback_data=f"dns_wizard:{domain}:A:create:confirm")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns_wizard:{domain}:A:proxied:back")]
                ]
        else:
            # Fallback for other record types
            message_text = f"✅ Data Updated\n\nReturning to wizard..."
            keyboard = [[InlineKeyboardButton(t("buttons.back_to_dns", user_lang), callback_data=f"dns:{domain}:view")]]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await message.reply_text(message_text, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing next wizard step: {e}")
        await message.reply_text("❌ Error\n\nCould not continue wizard.")

# =============================================================================
# NAMESERVER MANAGEMENT FUNCTIONS
# =============================================================================

async def show_nameserver_management(query, domain_name, context):
    """Show nameserver management interface"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        
        # Check if user owns this domain
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get nameservers from database (reflects actual registrar settings)
        # CRITICAL FIX: Fetch from database instead of Cloudflare API
        # Database stores the actual nameservers set at the registrar
        from database import execute_query
        ns_result = await execute_query(
            "SELECT nameservers FROM domains WHERE domain_name = %s AND user_id = %s",
            (domain_name, user_record['id'])
        )
        
        nameservers = []
        if ns_result and ns_result[0].get('nameservers'):
            nameservers = ns_result[0]['nameservers']
        
        # If no nameservers in database, try Cloudflare zone as fallback
        if not nameservers:
            cf_zone = await get_cloudflare_zone(domain_name)
            if cf_zone:
                zone_id = cf_zone['cf_zone_id']
                cloudflare = CloudflareService()
                zone_info = await cloudflare.get_zone_info(zone_id)
                nameservers = zone_info.get('name_servers', []) if zone_info else []
                
                # Store Cloudflare nameservers in database for future lookups
                if nameservers:
                    await update_domain_nameservers(domain_name, nameservers)
        
        # Detect provider and format display
        provider_type, provider_name = detect_nameserver_provider(nameservers)
        nameserver_display = format_nameserver_display(nameservers, max_display=4)
        
        # Provider status and recommendations
        if provider_type == "cloudflare":
            status_icon = "🟢"
            recommendation = "✅ Optimal Configuration\nYour domain is using Cloudflare's nameservers for best performance and security."
        else:
            status_icon = "🔶"
            recommendation = "Consider switching to Cloudflare nameservers for better performance and DNS management."
        
        message = f"""
📡 NS: {domain_name}

{status_icon} {provider_name}
{nameserver_display}

Type new nameservers:
"""
        
        keyboard = []
        
        # Add appropriate management options
        if provider_type != "cloudflare":
            keyboard.append([InlineKeyboardButton(t("buttons.switch_to_cloudflare_ns", user_lang), callback_data=f"dns:{domain_name}:ns_to_cloudflare")])
        
        keyboard.extend([
            [InlineKeyboardButton(t("buttons.records", user_lang), callback_data=f"dns:{domain_name}:list")],
            [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data=f"dns:{domain_name}:view")]
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context for direct nameserver input
        context.user_data['expecting_nameserver_input'] = {
            'domain': domain_name,
            'chat_id': query.message.chat.id if query.message else None,
            'message_id': query.message.message_id if query.message else None
        }
        
    except Exception as e:
        logger.error(f"Error showing nameserver management: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load nameserver information.")

async def confirm_switch_to_cloudflare_ns(query, domain_name):
    """Confirm switching to Cloudflare nameservers"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get current nameserver info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nDomain zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        zone_info = await cloudflare.get_zone_info(zone_id)
        cf_nameservers = zone_info.get('name_servers', []) if zone_info else []
        
        if not cf_nameservers:
            await safe_edit_message(query, t('nameservers.cloudflare_ns_retrieval_error', user_lang))
            return
        
        cf_ns_display = format_nameserver_display(cf_nameservers, max_display=4)
        
        message = t('nameservers.switch_confirmation', user_lang, domain=domain_name, nameservers=cf_ns_display)
        
        keyboard = [
            [InlineKeyboardButton(btn_t("confirm_switch", user_lang), callback_data=f"dns:{domain_name}:ns_to_cloudflare:confirm")],
            [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing Cloudflare NS confirmation: {e}")
        user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
        await safe_edit_message(query, t('nameservers.prepare_switch_error', user_lang))

async def execute_switch_to_cloudflare_ns(query, context, domain_name):
    """Execute switch to Cloudflare nameservers via OpenProvider API"""
    try:
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Show processing message
        await safe_edit_message(query, t('nameservers.switching_to_cloudflare', user_lang))
        
        # Get Cloudflare nameservers
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, t('nameservers.zone_not_found', user_lang))
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        zone_info = await cloudflare.get_zone_info(zone_id)
        cf_nameservers = zone_info.get('name_servers', []) if zone_info else []
        
        if not cf_nameservers:
            await safe_edit_message(query, t('nameservers.cloudflare_ns_retrieval_error', user_lang))
            return
        
        cf_ns_display = format_nameserver_display(cf_nameservers, max_display=4)
        
        # Try to update nameservers via OpenProvider API
        logger.info(f"Attempting to switch {domain_name} to Cloudflare nameservers via OpenProvider API")
        
        # CRITICAL FIX: Get domain ID from database first
        domain_id = await get_domain_provider_id(domain_name)
        domain_id = str(domain_id) if domain_id else None
        
        if not domain_id:
            logger.error(f"❌ No provider domain ID found for {domain_name} in database")
            await safe_edit_message(query, t('nameservers.registration_data_not_found', user_lang, support=BrandConfig().support_contact))
            return
        
        logger.info(f"Using domain ID {domain_id} for Cloudflare nameserver switch")
        openprovider = OpenProviderService()
        update_result = await openprovider.update_nameservers(domain_name, cf_nameservers, domain_id)
        
        # Check success conditions
        if update_result and (update_result.get('success') or update_result.get('code') == 0):
            # Success case - nameservers updated via API
            # CRITICAL: Update database with new Cloudflare nameservers for sync
            db_updated = await update_domain_nameservers(domain_name, cf_nameservers)
            if db_updated:
                logger.info(f"✅ Database updated with Cloudflare nameservers for {domain_name}")
            else:
                logger.warning(f"⚠️ Failed to update database nameservers for {domain_name}")
            
            # Compact nameserver display for mobile
            ns_count = len(cf_nameservers)
            ns_summary = f"{ns_count} Cloudflare NS" if ns_count > 1 else "Cloudflare NS"
            
            message = f"""
✅ Cloudflare Nameservers Updated
Domain: {domain_name}
Status: ✅ API Updated
Nameservers: {ns_summary}
Propagation: 24-48 hours
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.manage_dns_records", user_lang), callback_data=f"dns:{domain_name}:list")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.info(f"Successfully switched {domain_name} to Cloudflare nameservers via OpenProvider API")
            
        elif update_result and not update_result.get('success'):
            # API call failed - show error with fallback instructions
            error_msg = update_result.get('message', 'Unknown error')
            error_code = update_result.get('error_code', 0)
            
            message = f"""
⚠️ API Update Failed - Manual Action Required

Domain: {domain_name}
Error: {error_msg}

Cloudflare Nameservers (for manual update):
{cf_ns_display}

Manual Steps Required:
1. Log in to your domain registrar
2. Find domain management for {domain_name}
3. Update nameserver settings with the Cloudflare nameservers above
4. Save changes - DNS propagation takes 24-48 hours

⚠️ Note: 
The automated update failed (Error {error_code}). Please update manually at your registrar.

Once updated, all DNS management for this domain will be handled through Cloudflare and this bot.
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.retry_api_update", user_lang), callback_data=f"dns:{domain_name}:ns_to_cloudflare:confirm")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.warning(f"Nameserver API update failed for {domain_name} Cloudflare switch: {error_msg} (Error {error_code})")
            
        else:
            # API unavailable - show fallback instructions
            message = f"""
⚠️ Manual Update Required

Domain: {domain_name}

Cloudflare Nameservers (for manual update):
{cf_ns_display}

Manual Steps:
1. Log in to your domain registrar
2. Find domain management for {domain_name}
3. Update nameserver settings with the Cloudflare nameservers above
4. Save changes - DNS propagation takes 24-48 hours

Benefits after update:
• Enhanced DDoS protection and CDN
• Full DNS management through this bot
• Better security and performance

⚠️ Note: 
Automated update is currently unavailable. Please update manually.

Once updated, all DNS management for this domain will be handled through Cloudflare and this bot.
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.retry_api_update", user_lang), callback_data=f"dns:{domain_name}:ns_to_cloudflare:confirm")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.warning(f"Nameserver API unavailable for Cloudflare nameserver switch of {domain_name}")
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error executing Cloudflare NS switch for {domain_name}: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not process nameserver switch. Please try again.")

async def handle_nameserver_input(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str, nameserver_input_context):
    """Handle nameserver input from user - simplified single input interface"""
    try:
        user = update.effective_user
        effective_message = update.effective_message
        domain_name = nameserver_input_context['domain']
        
        # Parse nameservers from various input formats
        nameservers = parse_nameserver_input(text)
        
        if not nameservers:
            if effective_message:
                await effective_message.reply_text(
                    "❌ No Valid Nameservers Found\n\n"
                    "Please enter nameservers in one of these formats:\n"
                    "• Line-separated (one per line)\n"
                    "• Comma-separated: ns1.example.com, ns2.example.com\n"
                    "• Space-separated: ns1.example.com ns2.example.com\n\n"
                    "Each nameserver must be a valid FQDN (e.g., ns1.example.com)"
                )
            return
        
        # Validate nameservers
        valid_nameservers = []
        invalid_nameservers = []
        
        for ns in nameservers:
            ns_clean = ns.strip().lower()
            if ns_clean and is_valid_nameserver(ns_clean):
                valid_nameservers.append(ns_clean)
            elif ns_clean:  # Only add to invalid if not empty
                invalid_nameservers.append(ns)
        
        # Check for validation errors
        if len(valid_nameservers) < 2:
            if effective_message:
                await effective_message.reply_text(
                    f"❌ Not Enough Valid Nameservers\n\n"
                    f"At least 2 valid nameservers required. Found {len(valid_nameservers)} valid nameserver(s).\n\n"
                    "Please enter 2-5 valid nameserver addresses."
                )
            return
        
        if len(valid_nameservers) > 5:
            if effective_message:
                await effective_message.reply_text(
                    f"❌ Too Many Nameservers\n\n"
                    f"Maximum 5 nameservers allowed. You provided {len(valid_nameservers)} nameservers.\n\n"
                    "Please reduce to 2-5 nameservers for optimal DNS performance."
                )
            return
        
        if invalid_nameservers:
            invalid_list = "\n".join([f"• {ns}" for ns in invalid_nameservers])
            if effective_message:
                await effective_message.reply_text(
                    f"❌ Invalid Nameservers Found\n\n"
                    f"The following nameservers are invalid:\n{invalid_list}\n\n"
                    "Please use valid FQDN format (e.g., ns1.example.com)."
                )
            return
        
        # If all validations pass, proceed with update
        if not user or not effective_message:
            logger.error("Missing user or message in nameserver input handler")
            return
            
        # Clean up context
        if context.user_data and 'expecting_nameserver_input' in context.user_data:
            del context.user_data['expecting_nameserver_input']
        
        # Execute the nameserver update directly for text input
        await execute_nameserver_update_text(effective_message, context, domain_name, valid_nameservers, user)
        
    except Exception as e:
        logger.error(f"Error handling nameserver input: {e}")
        if update.effective_message:
            await update.effective_message.reply_text(
                "❌ Error Processing Nameservers\n\n"
                "Could not process your nameserver input. Please try again."
            )

def parse_nameserver_input(text: str) -> list:
    """Parse nameserver input from various formats"""
    if not text:
        return []
    
    # Try different separation methods
    nameservers = []
    
    # First try newline separation (most common for multi-line input)
    if '\n' in text:
        nameservers = [ns.strip() for ns in text.split('\n') if ns.strip()]
    # Then try comma separation
    elif ',' in text:
        nameservers = [ns.strip() for ns in text.split(',') if ns.strip()]
    # Finally try space separation
    elif ' ' in text:
        nameservers = [ns.strip() for ns in text.split() if ns.strip()]
    # Single nameserver
    else:
        nameservers = [text.strip()] if text.strip() else []
    
    # Remove duplicates while preserving order
    seen = set()
    unique_nameservers = []
    for ns in nameservers:
        ns_lower = ns.lower()
        if ns_lower not in seen:
            seen.add(ns_lower)
            unique_nameservers.append(ns)
    
    return unique_nameservers

async def show_custom_nameserver_form(query, context, domain_name):
    """Show simplified form for entering all custom nameservers at once"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # CRITICAL: Clear all DNS wizard state to prevent cross-contamination
        # This fixes the bug where nameserver input triggers A record IP validation
        clear_all_dns_wizard_state(context)
        
        message = f"""
⚙️ <b>Set Custom Nameservers: {domain_name}</b>

<b>Enter all nameservers (2-5 required):</b>

You can enter nameservers in any of these formats:

Line-separated (recommended):
<code>ns1.example.com
ns2.example.com
ns3.example.com</code>

<b>Comma-separated:</b>
<code>ns1.example.com, ns2.example.com, ns3.example.com</code>

<b>Space-separated:</b>
<code>ns1.example.com ns2.example.com ns3.example.com</code>

<b>Requirements:</b>
• 2-5 nameservers required
• Valid FQDN format (e.g., ns1.example.com)
• Each nameserver must end with a domain

Update nameservers at your registrar after entering.

<b>Type your nameservers below:</b>
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.cancel", user_lang), callback_data=f"dns:{domain_name}:nameservers")],
            [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context for text input
        context.user_data['expecting_nameserver_input'] = {
            'domain': domain_name,
            'chat_id': query.message.chat.id if query.message else None,
            'message_id': query.message.message_id if query.message else None
        }
        
    except Exception as e:
        logger.error(f"Error showing custom nameserver form: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load nameserver form.")

async def execute_nameserver_update_text(message, context, domain_name, nameservers, user):
    """Execute nameserver update for text input with direct message sending"""
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Show processing message
        processing_msg = await message.reply_text(
            "🔄 Processing Nameserver Update\n\nValidating nameservers and updating domain configuration..."
        )
        
        # Get the domain ID from database for OpenProvider API
        provider_domain_id = await get_domain_provider_id(domain_name)
        
        # Try to update nameservers via OpenProvider API
        openprovider = OpenProviderService()
        api_success = await openprovider.update_nameservers(domain_name, nameservers, provider_domain_id)
        
        if api_success and api_success.get('success'):
            # Store updated nameservers in database
            db_update_success = await update_domain_nameservers(domain_name, nameservers)
            if db_update_success:
                logger.info(f"✅ Stored updated nameservers in database for {domain_name}")
            else:
                logger.warning(f"⚠️ Failed to store nameservers in database for {domain_name}")
            
            ns_list = "\n".join([f"• {ns}" for ns in nameservers])
            success_message = f"""
✅ Nameservers Updated

Domain: {domain_name}
Nameservers: {len(nameservers)} configured
{ns_list}

Changes propagate globally within 24-48 hours.
"""
            
            # Check if nameservers are Cloudflare - only show DNS management if they are
            provider_type, _ = detect_nameserver_provider(nameservers)
            
            if provider_type == "cloudflare":
                keyboard = [
                    [InlineKeyboardButton(t("buttons.manage_dns", user_lang), callback_data=f"dns:{domain_name}:main")],
                    [InlineKeyboardButton(t("buttons.my_domains", user_lang), callback_data="my_domains")]
                ]
            else:
                # Custom nameservers - no DNS management available, show Cloudflare switch
                keyboard = [
                    [InlineKeyboardButton(t("buttons.switch_to_cloudflare_ns", user_lang), callback_data=f"dns:{domain_name}:ns_to_cloudflare")],
                    [InlineKeyboardButton(t("buttons.my_domains", user_lang), callback_data="my_domains")]
                ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=processing_msg.message_id,
                text=success_message,
                reply_markup=reply_markup
            )
            
            logger.info(f"Nameservers updated successfully for {domain_name}")
            
        elif api_success and not api_success.get('success'):
            # API returned an error response
            error_code = api_success.get('error', '')
            correct_nameservers = api_success.get('correct_nameservers', [])
            user_action = api_success.get('user_action', '')
            
            # Check if this is a DENIC NS consistency error with correct nameservers
            if error_code == 'DENIC_NS_CONSISTENCY_ERROR' and correct_nameservers:
                correct_ns_display = "\n".join([f"• {ns}" for ns in correct_nameservers])
                ns_list = "\n".join([f"• {ns}" for ns in nameservers])
                
                error_message = f"""
❌ Wrong Nameservers for .de Domain

Domain: {domain_name}

<b>The nameservers you entered don't match your Cloudflare zone.</b>

You entered:
{ns_list}

<b>✅ Use these nameservers instead:</b>
{correct_ns_display}

These are the nameservers assigned to your domain in Cloudflare. German .de domains require an exact match.

💡 <b>Tip:</b> Log into your Cloudflare account and find the nameservers shown for this domain.
"""
                keyboard = [
                    [InlineKeyboardButton("🔄 Try Again", callback_data=f"dns:{domain_name}:nameservers")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:manage")]
                ]
            elif user_action:
                # Show user-friendly action message
                ns_list = "\n".join([f"• {ns}" for ns in nameservers])
                error_message = f"""
⚠️ Update Failed

Domain: {domain_name}

{user_action}

Your Nameservers:
{ns_list}
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.retry_api_update", user_lang), callback_data=f"retry_ns_update:{domain_name}:{user.id}")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
                ]
            else:
                # Default error handling
                ns_list = "\n".join([f"• {ns}" for ns in nameservers])
                error_message = f"""
⚠️ Update Failed

Domain: {domain_name}
{ns_list}

Please try again or contact support.
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.retry_api_update", user_lang), callback_data=f"retry_ns_update:{domain_name}:{user.id}")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
                ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=processing_msg.message_id,
                text=error_message,
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            
            logger.warning(f"Nameserver update failed for {domain_name}: {error_code}")
            
        else:
            # API unavailable - show manual instructions
            ns_list = "\n".join([f"• {ns}" for ns in nameservers])
            manual_message = f"""
⚠️ Manual Update Required

Domain: {domain_name}
Status: API unavailable
{ns_list}

Steps: Your Registrar → Domain Settings → Update Nameservers

Return here after updating (24-48h propagation).
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.retry_api_update", user_lang), callback_data=f"retry_ns_update:{domain_name}:{user.id}")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=processing_msg.message_id,
                text=manual_message,
                reply_markup=reply_markup
            )
            
            logger.warning(f"Nameserver API unavailable for nameserver update of {domain_name}")
            
    except Exception as e:
        logger.error(f"Error executing nameserver update for {domain_name}: {e}")
        try:
            await message.reply_text(
                "❌ Error\n\nCould not process nameserver update. Please try again."
            )
        except Exception as reply_error:
            logger.error(f"Error sending error message: {reply_error}")

async def handle_retry_nameserver_update(query, context, callback_data):
    """Handle retry nameserver update callback: retry_ns_update:{domain_name}:{user_id}"""
    try:
        parts = callback_data.split(":")
        if len(parts) < 3:
            user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
            await safe_edit_message(query, t('nameservers.invalid_retry', user_lang))
            return
        
        domain_name = parts[1]
        expected_user_id = int(parts[2])
        user = query.from_user
        
        # Verify user ID matches for security
        if user.id != expected_user_id:
            user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
            await safe_edit_message(query, t('nameservers.unauthorized_retry', user_lang))
            return
        
        # Show the custom nameserver form for retry
        await show_custom_nameserver_form(query, context, domain_name)
        
    except Exception as e:
        logger.error(f"Error handling retry nameserver update: {e}")
        user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
        await safe_edit_message(query, t('nameservers.retry_error', user_lang))

async def execute_nameserver_update(query, context, domain_name, ns_data_token):
    """Execute custom nameserver update via OpenProvider API"""
    try:
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Show processing message
        await safe_edit_message(query, t('nameservers.processing_update', user_lang))
        
        # Retrieve nameserver data from token
        ns_data = await retrieve_callback_token(user.id, ns_data_token)
        if not ns_data or ns_data.startswith("error:"):
            await safe_edit_message(query, t('nameservers.data_expired', user_lang))
            return
        
        # Parse nameservers
        nameservers = ns_data.split("|")
        
        # Validate nameservers with enhanced checks
        valid_nameservers = []
        invalid_nameservers = []
        
        for ns in nameservers:
            ns = ns.strip().lower()  # Normalize to lowercase
            if ns and is_valid_nameserver(ns):
                valid_nameservers.append(ns)
            else:
                invalid_nameservers.append(ns)
        
        # Enforce 2-5 nameserver limit
        if len(valid_nameservers) < 2:
            await safe_edit_message(query, t('nameservers.invalid_config_min_ns', user_lang, count=len(valid_nameservers)))
            return
        
        if len(valid_nameservers) > 5:
            await safe_edit_message(query, t('nameservers.too_many_nameservers', user_lang, count=len(valid_nameservers)))
            return
        
        if invalid_nameservers:
            invalid_list = "\n".join([f"• {ns}" for ns in invalid_nameservers])
            await safe_edit_message(query, 
                f"❌ Invalid Nameservers\n\nThe following nameservers are invalid:\n{invalid_list}\n\nPlease use valid FQDN format.")
            return
        
        # Get the domain ID from database for OpenProvider API
        provider_domain_id = await get_domain_provider_id(domain_name)
        
        # Try to update nameservers via OpenProvider API
        logger.info(f"Attempting to update nameservers for {domain_name} (ID: {provider_domain_id}) via OpenProvider API")
        openprovider = OpenProviderService()
        update_result = await openprovider.update_nameservers(domain_name, valid_nameservers, provider_domain_id)
        
        if update_result and update_result.get('success'):
            # Success case - nameservers updated via API
            # Store updated nameservers in database
            db_update_success = await update_domain_nameservers(domain_name, valid_nameservers)
            if db_update_success:
                logger.info(f"✅ Stored updated nameservers in database for {domain_name}")
            else:
                logger.warning(f"⚠️ Failed to store nameservers in database for {domain_name}")
            
            ns_display = format_nameserver_display(valid_nameservers, max_display=4)
            provider_type, provider_name = detect_nameserver_provider(valid_nameservers)
            
            message = f"""
✅ Nameservers Updated Successfully

Domain: {domain_name}
Provider: {provider_name}

Updated Nameservers:
{ns_display}

Status: ✅ Successfully Updated
Propagation: Changes will propagate over the next 24-48 hours

Next Steps:
• DNS changes are now live at your registrar
• No additional action required
• DNS management available through this bot for Cloudflare nameservers

DNS changes propagate within 48 hours.
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.info(f"Successfully updated nameservers for {domain_name} via OpenProvider API: {valid_nameservers}")
            
        elif update_result and not update_result.get('success'):
            # API call failed - show error with fallback instructions
            error_msg = update_result.get('message', 'Unknown error')
            error_code = update_result.get('error_code', 0)
            user_action = update_result.get('user_action', '')
            correct_nameservers = update_result.get('correct_nameservers', [])
            
            # Check if this is a DENIC NS consistency error with correct nameservers
            if update_result.get('error') == 'DENIC_NS_CONSISTENCY_ERROR' and correct_nameservers:
                correct_ns_display = "\n".join([f"• {ns}" for ns in correct_nameservers])
                
                message = f"""
❌ Wrong Nameservers for .de Domain

Domain: {domain_name}

<b>The nameservers you entered don't match your Cloudflare zone.</b>

You entered:
{format_nameserver_display(valid_nameservers, max_display=4)}

<b>✅ Use these nameservers instead:</b>
{correct_ns_display}

These are the nameservers assigned to your domain in Cloudflare. German .de domains require an exact match.

💡 <b>Tip:</b> Log into your Cloudflare account and find the nameservers shown for this domain - they should match the ones above.
"""
                keyboard = [
                    [InlineKeyboardButton("🔄 Try Again with Correct NS", callback_data=f"dns:{domain_name}:nameservers")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:manage")]
                ]
            elif user_action:
                # Show user-friendly action message from the API result
                ns_display = format_nameserver_display(valid_nameservers, max_display=4)
                
                message = f"""
⚠️ API Update Failed

Domain: {domain_name}

{user_action}

Your Nameservers:
{ns_display}
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.retry_api_update", user_lang), callback_data=f"dns:{domain_name}:ns_update:{ns_data_token}")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
                ]
            else:
                # Default error message
                ns_display = format_nameserver_display(valid_nameservers, max_display=4)
                
                message = f"""
⚠️ API Update Failed - Manual Action Required

Domain: {domain_name}
Error: {error_msg}

Your Nameservers (for manual update):
{ns_display}

Manual Steps Required:
1. Log in to your domain registrar
2. Find domain management for {domain_name}
3. Update nameserver settings with the nameservers above
4. Save changes - DNS propagation takes 24-48 hours

⚠️ Note: 
The automated update failed (Error {error_code}). Please update manually at your registrar.
"""
                keyboard = [
                    [InlineKeyboardButton(t("buttons.retry_api_update", user_lang), callback_data=f"dns:{domain_name}:ns_update:{ns_data_token}")],
                    [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
                ]
            
            logger.warning(f"Nameserver API update failed for {domain_name}: {error_msg} (Error {error_code})")
            
        else:
            # API unavailable - show fallback instructions
            ns_display = format_nameserver_display(valid_nameservers, max_display=4)
            provider_type, provider_name = detect_nameserver_provider(valid_nameservers)
            
            message = f"""
⚠️ Manual Update Required

Domain: {domain_name}
Provider: {provider_name}

Your Nameservers (for manual update):
{ns_display}

Manual Steps:
1. Log in to your domain registrar
2. Find domain management for {domain_name}
3. Update nameserver settings with the nameservers above
4. Save changes - DNS propagation takes 24-48 hours

⚠️ Note: 
Automated update is currently unavailable. Please update manually.
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.retry_api_update", user_lang), callback_data=f"dns:{domain_name}:ns_update:{ns_data_token}")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.warning(f"Nameserver API unavailable for nameserver update of {domain_name}")
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Clean up context
        if 'expecting_nameserver_input' in context.user_data:
            del context.user_data['expecting_nameserver_input']
        
    except Exception as e:
        logger.error(f"Error executing nameserver update for {domain_name}: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not process nameserver update. Please try again.")

# =============================================================================
# CLOUDFLARE SECURITY SETTINGS FUNCTIONS
# =============================================================================

async def show_security_settings(query, domain_name):
    """Show Cloudflare security settings interface with JavaScript Challenge toggle"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        
        # Check if user owns this domain
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # FIXED LOGIC: Check Cloudflare zone existence FIRST before nameserver validation
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            # No Cloudflare zone found - check if domain uses Cloudflare nameservers
            nameservers = await get_domain_nameservers(domain_name)
            
            # If no nameservers stored, try to fetch from Cloudflare API as fallback
            if not nameservers:
                logger.info(f"No stored nameservers for {domain_name}, attempting Cloudflare API fallback")
                cloudflare = CloudflareService()
                zone_info = await cloudflare.get_zone_by_name(domain_name)
                
                if zone_info and zone_info.get('name_servers'):
                    # Found zone via API - persist nameservers and update database
                    api_nameservers = zone_info.get('name_servers', [])
                    logger.info(f"✅ Fetched nameservers from Cloudflare API for {domain_name}: {api_nameservers}")
                    
                    # Persist nameservers to database
                    await update_domain_nameservers(domain_name, api_nameservers)
                    nameservers = api_nameservers
                    
                    # Also save zone info if missing in database
                    if zone_info.get('id'):
                        await save_cloudflare_zone(
                            domain_name=domain_name,
                            cf_zone_id=zone_info['id'],
                            nameservers=api_nameservers,
                            status=zone_info.get('status', 'active')
                        )
                        # Reload zone from database now that it's saved
                        cf_zone = await get_cloudflare_zone(domain_name)
                        logger.info(f"✅ Saved Cloudflare zone info for {domain_name}")
            
            # If still no Cloudflare zone after API fallback, check nameserver provider
            if not cf_zone:
                provider_type, _ = detect_nameserver_provider(nameservers)
                
                if provider_type != "cloudflare":
                    await safe_edit_message(query, t('security.unavailable_no_cloudflare', user_lang))
                    return
                else:
                    # Domain uses Cloudflare nameservers but zone not found in database
                    await safe_edit_message(query, t('security.unavailable_no_zone', user_lang, domain=domain_name))
                    return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        # Get current security settings
        await safe_edit_message(query, t('security.loading_settings', user_lang))
        
        settings = await cloudflare.get_zone_settings(zone_id)
        if not settings:
            await safe_edit_message(query, t('security.load_error', user_lang))
            return
        
        # Get JavaScript Challenge status from WAF Custom Rules
        js_challenge_status = await cloudflare.get_javascript_challenge_status(zone_id)
        js_challenge = js_challenge_status.get('enabled', False)
        force_https = settings.get('always_use_https', False)
        
        # Get auto-proxy preference for this domain
        auto_proxy_enabled = await get_domain_auto_proxy_enabled(domain_name)
        
        # Format JavaScript Challenge status
        if js_challenge:
            rule_count = js_challenge_status.get('rule_count', 0)
            js_status = t('security.status_on', user_lang)
            plural_s = 's' if rule_count != 1 else ''
            js_description = t('security.js_challenge_active', user_lang, count=rule_count, plural=plural_s)
        else:
            js_status = t('security.status_off', user_lang)
            js_description = t('security.js_challenge_inactive', user_lang)
        
        https_status = t('security.status_on', user_lang) if force_https else t('security.status_off', user_lang)
        auto_proxy_status = t('security.status_on', user_lang) if auto_proxy_enabled else t('security.status_off', user_lang)
        
        message = f"""{t('security.title', user_lang, domain=domain_name)}

{t('security.js_challenge_label', user_lang)} {js_status}
_{js_description}_

{t('security.force_https_label', user_lang)} {https_status}

{t('security.auto_proxy_label', user_lang)} {auto_proxy_status}
_{t('security.auto_proxy_description', user_lang)}_

Adjust security settings for your domain:
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.javascript_challenge_toggle", user_lang), callback_data=f"dns:{domain_name}:security:js_challenge:toggle")],
            [InlineKeyboardButton(t("buttons.toggle_force_https", user_lang), callback_data=f"dns:{domain_name}:security:force_https:toggle")],
            [InlineKeyboardButton(t("buttons.toggle_auto_enable_proxy", user_lang), callback_data=f"dns:{domain_name}:security:auto_proxy:toggle")],
            [InlineKeyboardButton(t("buttons.back_to_dns", user_lang), callback_data=f"dns:{domain_name}:view")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing security settings: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load security settings.")

async def toggle_javascript_challenge(query, domain_name, action):
    """Handle JavaScript Challenge toggle"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get Cloudflare zone info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nCloudflare zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        if action == "toggle":
            # Show JavaScript Challenge options
            message = f"""
🔐 Visible JavaScript Challenge: {domain_name}

Choose protection level:

Enable: Show 5-second "Checking your browser" page to all visitors
Disable: Allow all traffic without visible challenge

_Visible JavaScript Challenge displays an interstitial page to verify browsers and block automated attacks._
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.enable", user_lang), callback_data=f"dns:{domain_name}:security:js_challenge:on"),
                 InlineKeyboardButton(t("buttons.disable", user_lang), callback_data=f"dns:{domain_name}:security:js_challenge:off")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
        else:
            # Apply Visible JavaScript Challenge setting
            enabled = action == "on"
            
            try:
                if enabled:
                    # Auto-enable proxy for web records before enabling JavaScript Challenge
                    proxy_result = await ensure_proxy_for_feature(
                        zone_id=zone_id,
                        domain_name=domain_name,
                        feature_name="Visible JavaScript Challenge",
                        query=query
                    )
                    
                    if not proxy_result.get('success'):
                        # Check if user confirmation is needed for proxy enablement
                        if proxy_result.get('needs_confirmation'):
                            # Show confirmation dialog for proxy enablement
                            confirmation_message = proxy_result.get('message', 'Proxy enablement required')
                            
                            message = f"""
🔧 Proxy Confirmation Required

{confirmation_message}

Visible JavaScript Challenge requires Cloudflare proxy to function properly. 

Would you like to enable proxy for these records now?
"""
                            
                            keyboard = [
                                [InlineKeyboardButton(t("buttons.yes_enable_proxy", user_lang), callback_data=f"dns:{domain_name}:security:js_challenge:confirm_proxy:on"),
                                 InlineKeyboardButton(t("buttons.no_cancel", user_lang), callback_data=f"dns:{domain_name}:security")],
                            ]
                            
                            reply_markup = InlineKeyboardMarkup(keyboard)
                            await safe_edit_message(query, message, reply_markup=reply_markup)
                            return
                        else:
                            # Proxy enablement failed, show error and return
                            error_message = proxy_result.get('message', 'Failed to enable proxy for JavaScript Challenge')
                            await safe_edit_message(query, f"❌ JavaScript Challenge Setup Failed\n\n{error_message}")
                            return
                    
                    # Enable visible JavaScript challenge for all traffic
                    result = await cloudflare.enable_javascript_challenge(zone_id, "Visible JavaScript Challenge - Bot Protection")
                    
                    # If JavaScript Challenge fails, rollback proxy changes
                    if not result.get('success') and proxy_result.get('rollback_needed'):
                        logger.warning("JavaScript Challenge failed, rolling back proxy changes")
                        rollback_success = await rollback_proxy_changes(zone_id, proxy_result.get('modified_records', []))
                        if rollback_success:
                            logger.info("Successfully rolled back proxy changes")
                        else:
                            logger.warning("Proxy rollback partially failed")
                else:
                    # Disable JavaScript challenge by removing all JS challenge rules
                    # Note: We don't disable proxy when turning features off - that's user choice
                    success = await cloudflare.disable_javascript_challenge(zone_id)
                    result = {'success': success}
                    
            except asyncio.CancelledError:
                await safe_edit_message(query, "⏱️ Request Timeout\n\nThe JavaScript Challenge update was cancelled. Please try again.")
                return
            
            if result.get('success'):
                status = "Enabled" if enabled else "Disabled"
                if enabled:
                    description = "All visitors will see a 5-second 'Checking your browser' page before accessing your site."
                else:
                    description = "Visitors can access your site directly without any JavaScript challenge."
                
                message = f"""
✅ Visible JavaScript Challenge Updated

Domain: {domain_name}
Status: {status}

_{description}_

Changes take effect within a few minutes.
"""
            else:
                # Handle detailed error messages
                errors = result.get('errors', [{'message': 'Unknown error occurred'}])
                error_messages = []
                
                # Ensure errors is a list
                if not isinstance(errors, list):
                    errors = [{'message': 'Unknown error occurred'}]
                    
                for error in errors:
                    error_msg = error.get('user_message') or error.get('message', 'Unknown error')
                    error_messages.append(error_msg)
                
                error_text = "\n\n".join(error_messages)
                
                message = f"""
❌ Visible JavaScript Challenge Update Failed

{error_text}

Please try again later.
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.back_to_security", user_lang), callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
    except Exception as e:
        logger.error(f"Error toggling JavaScript Challenge setting: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not update JavaScript Challenge setting.")

async def toggle_force_https_setting(query, domain_name, action):
    """Toggle Force HTTPS setting"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get Cloudflare zone info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nCloudflare zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        if action == "toggle":
            # Show Force HTTPS options
            message = f"""
🔒 Force HTTPS: {domain_name}

Choose HTTPS redirect behavior:

On: Automatically redirect HTTP to HTTPS
Off: Allow both HTTP and HTTPS
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.enable_force_https", user_lang), callback_data=f"dns:{domain_name}:security:force_https:on"),
                 InlineKeyboardButton(t("buttons.disable_force_https", user_lang), callback_data=f"dns:{domain_name}:security:force_https:off")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
        else:
            # Apply Force HTTPS setting
            enabled = action == "on"
            
            if enabled:
                # Auto-enable proxy for web records before enabling Force HTTPS
                proxy_result = await ensure_proxy_for_feature(
                    zone_id=zone_id,
                    domain_name=domain_name,
                    feature_name="Force HTTPS",
                    query=query
                )
                
                if not proxy_result.get('success'):
                    # Check if user confirmation is needed for proxy enablement
                    if proxy_result.get('needs_confirmation'):
                        # Show confirmation dialog for proxy enablement
                        confirmation_message = proxy_result.get('message', 'Proxy enablement required')
                        
                        message = f"""
🔧 Proxy Confirmation Required

{confirmation_message}

Force HTTPS requires Cloudflare proxy to function properly. 

Would you like to enable proxy for these records now?
"""
                        
                        keyboard = [
                            [InlineKeyboardButton(t("buttons.yes_enable_proxy", user_lang), callback_data=f"dns:{domain_name}:security:force_https:confirm_proxy:on"),
                             InlineKeyboardButton(t("buttons.no_cancel", user_lang), callback_data=f"dns:{domain_name}:security")],
                        ]
                        
                        reply_markup = InlineKeyboardMarkup(keyboard)
                        await safe_edit_message(query, message, reply_markup=reply_markup)
                        return
                    else:
                        # Proxy enablement failed, show error and return
                        error_message = proxy_result.get('message', 'Failed to enable proxy for Force HTTPS')
                        await safe_edit_message(query, f"❌ Force HTTPS Setup Failed\n\n{error_message}")
                        return
                
                # Enable Force HTTPS
                result = await cloudflare.update_force_https(zone_id, enabled)
                
                # If Force HTTPS fails, rollback proxy changes
                if not result.get('success') and proxy_result.get('rollback_needed'):
                    logger.warning("Force HTTPS failed, rolling back proxy changes")
                    rollback_success = await rollback_proxy_changes(zone_id, proxy_result.get('modified_records', []))
                    if rollback_success:
                        logger.info("Successfully rolled back proxy changes")
                    else:
                        logger.warning("Proxy rollback partially failed")
            else:
                # Disable Force HTTPS
                # Note: We don't disable proxy when turning features off - that's user choice
                result = await cloudflare.update_force_https(zone_id, enabled)
            
            if result.get('success'):
                status = "Enabled" if enabled else "Disabled"
                message = f"""
✅ Force HTTPS Updated

Domain: {domain_name}
Status: {status}

{'All HTTP traffic will now redirect to HTTPS.' if enabled else 'HTTP and HTTPS are both allowed.'}
"""
            else:
                # Handle detailed error messages including SSL validation
                errors = result.get('errors', [{'message': 'Unknown error occurred'}])
                error_messages = []
                
                for error in errors:
                    error_code = error.get('code', '')
                    
                    if error_code == 'ssl_required':
                        error_msg = (
                            "🔒 SSL Certificate Required\n\n"
                            "Force HTTPS requires an active SSL certificate. "
                            "Please ensure your domain has a valid SSL certificate configured before enabling this feature."
                        )
                    else:
                        error_msg = error.get('user_message') or error.get('message', 'Unknown error')
                    
                    error_messages.append(error_msg)
                
                error_text = "\n\n".join(error_messages)
                
                message = f"""
❌ Force HTTPS Update Failed

{error_text}

Please try again later.
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.back_to_security", user_lang), callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
    except Exception as e:
        logger.error(f"Error toggling Force HTTPS setting: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not update Force HTTPS setting.")

async def toggle_auto_proxy_setting(query, domain_name, action):
    """Toggle Auto-Enable Proxy setting for user preference control"""
    try:
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        user_record = await get_or_create_user(user.id)
        
        # Check if user owns this domain
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        if action == "toggle":
            # Show Auto-Proxy preference options
            current_setting = await get_domain_auto_proxy_enabled(domain_name)
            current_status = "✅ Enabled" if current_setting else "❌ Disabled"
            
            message = f"""
🔧 Auto-Enable Proxy: {domain_name}

Current Setting: {current_status}

Choose your preference:

Enable: Automatically enable Cloudflare proxy when using security features
Disable: Ask for confirmation before enabling proxy

_Auto-proxy automatically enables Cloudflare proxy for DNS records when features like JavaScript Challenge or Force HTTPS require it for proper functionality._
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.enable_auto_proxy", user_lang), callback_data=f"dns:{domain_name}:security:auto_proxy:on"),
                 InlineKeyboardButton(t("buttons.disable_auto_proxy", user_lang), callback_data=f"dns:{domain_name}:security:auto_proxy:off")],
                [InlineKeyboardButton(t("buttons.back", user_lang), callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
        else:
            # Apply Auto-Proxy preference setting
            enabled = action == "on"
            
            # Update the database setting
            success = await set_domain_auto_proxy_enabled(domain_name, enabled)
            
            if success:
                status = "Enabled" if enabled else "Disabled"
                status_icon = "✅" if enabled else "❌"
                
                if enabled:
                    description = "Security features will automatically enable proxy when needed"
                else:
                    description = "You will be prompted before proxy changes are made"
                
                message = f"""
{status_icon} Auto-Proxy Setting Updated

Domain: {domain_name}
Auto-Enable Proxy: {status}

{description}

Your preference has been saved and will apply to future security feature configurations.
"""
            else:
                message = f"""
❌ Auto-Proxy Update Failed

Could not update the auto-proxy setting for {domain_name}.

Please try again later.
"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.back_to_security", user_lang), callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
    except Exception as e:
        logger.error(f"Error toggling auto-proxy setting: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not update auto-proxy setting.")

async def force_enable_proxy_and_feature(query, domain_name, feature_type):
    """Force enable proxy and then enable security feature when user confirms despite auto-proxy being disabled"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get Cloudflare zone info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nCloudflare zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        # Show progress message
        await safe_edit_message(query, "🔄 Enabling Proxy...\n\nForce enabling proxy for security feature...")
        
        # Force enable proxy by temporarily overriding auto_proxy_enabled check
        web_records = await cloudflare.get_web_records_for_proxy(zone_id, domain_name)
        
        if not web_records:
            await safe_edit_message(query, "❌ Error\n\nNo web records found to proxy.")
            return
        
        # Categorize records and enable proxy for needed records
        proxy_needed = []
        for record in web_records:
            is_proxied = record.get('proxied', False)
            is_eligible = record.get('proxy_eligible', False)
            
            if is_eligible and not is_proxied:
                proxy_needed.append(record)
        
        if not proxy_needed:
            await safe_edit_message(query, "✅ Proxy Already Enabled\n\nAll required records are already proxied.")
            # Continue to feature enablement
        else:
            # Enable proxy for required records
            modified_records = []
            failed_records = []
            
            for record in proxy_needed:
                record_id = record.get('id')
                record_name = record.get('name', 'unknown')
                
                if not record_id:
                    continue
                
                result = await cloudflare.update_record_proxied(zone_id, record_id, True)
                
                if result.get('success'):
                    modified_records.append({
                        'id': record_id,
                        'name': record_name,
                        'type': record.get('type'),
                        'content': record.get('content')
                    })
                    logger.info(f"✅ Force enabled proxy for {record_name}")
                else:
                    errors = result.get('errors', [])
                    error_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
                    failed_records.append({'name': record_name, 'error': error_msg})
                    logger.error(f"❌ Failed to force enable proxy for {record_name}: {error_msg}")
            
            if failed_records:
                error_list = "\n".join([f"• {r['name']}: {r['error']}" for r in failed_records])
                await safe_edit_message(query, f"❌ Proxy Enablement Failed\n\nSome records could not be proxied:\n\n{error_list}")
                return
        
        # Now enable the requested security feature
        await safe_edit_message(query, f"🔄 Enabling Security Feature...\n\nProxy enabled, now configuring {feature_type.replace('_', ' ').title()}...")
        
        if feature_type == "js_challenge":
            result = await cloudflare.enable_javascript_challenge(zone_id, "Visible JavaScript Challenge - Bot Protection")
            feature_name = "Visible JavaScript Challenge"
        elif feature_type == "force_https":
            result = await cloudflare.update_force_https(zone_id, True)
            feature_name = "Force HTTPS"
        else:
            await safe_edit_message(query, "❌ Error\n\nUnknown security feature type.")
            return
        
        # Show final result
        if result.get('success'):
            message = f"""
✅ {feature_name} Enabled Successfully

Domain: {domain_name}
Proxy: ✅ Enabled for required records
{feature_name}: ✅ Active

Your security feature is now active and working properly.
"""
        else:
            message = f"""
❌ {feature_name} Setup Failed

Proxy was enabled successfully, but the security feature could not be activated.

Please try enabling {feature_name} again from the security settings.
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.back_to_security", user_lang), callback_data=f"dns:{domain_name}:security")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error in force_enable_proxy_and_feature: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not enable proxy and security feature.")

async def ensure_proxy_for_feature(zone_id: str, domain_name: str, feature_name: str, query=None) -> Dict:
    """
    Automatically enable Cloudflare proxy for web records when required by security features.
    Respects user preference for auto-proxy behavior.
    
    Args:
        zone_id: Cloudflare zone ID
        domain_name: Domain name
        feature_name: Name of feature requiring proxy (for user messaging)
        query: Telegram query for user notifications (optional)
        
    Returns:
        Dict with success status, modified records, and rollback info
    """
    try:
        cloudflare = CloudflareService()
        logger.info(f"🔄 Auto-proxy check for {feature_name} on {domain_name}")
        
        # Check user's auto-proxy preference for this domain
        auto_proxy_enabled = await get_domain_auto_proxy_enabled(domain_name)
        logger.info(f"Auto-proxy preference for {domain_name}: {auto_proxy_enabled}")
        
        # Get web records that should be proxied for web features
        web_records = await cloudflare.get_web_records_for_proxy(zone_id, domain_name)
        
        if not web_records:
            logger.info(f"No web records found for {domain_name}")
            return {
                'success': True,
                'modified_records': [],
                'message': f"No standard web records found to proxy for {feature_name}.",
                'rollback_needed': False
            }
        
        # Categorize records by eligibility and current proxy status
        proxy_needed = []  # Records that need proxy enabled
        already_proxied = []  # Records already proxied
        ineligible = []  # Records that cannot be proxied
        
        for record in web_records:
            is_proxied = record.get('proxied', False)
            is_eligible = record.get('proxy_eligible', False)
            
            if is_eligible and not is_proxied:
                proxy_needed.append(record)
            elif is_eligible and is_proxied:
                already_proxied.append(record)
            else:
                ineligible.append(record)
        
        # If no records need proxy changes, we're good
        if not proxy_needed:
            if already_proxied:
                record_names = [r.get('name', 'unknown') for r in already_proxied]
                message = f"✅ Proxy already enabled for: {', '.join(record_names)}"
            else:
                message = f"No eligible records found for {feature_name}"
            
            return {
                'success': True,
                'modified_records': [],
                'message': message,
                'rollback_needed': False
            }
        
        # Check user preference for auto-proxy - if disabled, require confirmation
        if not auto_proxy_enabled:
            record_names = [r.get('name', 'unknown') for r in proxy_needed]
            record_count = len(proxy_needed)
            
            logger.info(f"Auto-proxy disabled for {domain_name}, requiring user confirmation for {record_count} records")
            
            # Return special status requiring user confirmation
            return {
                'success': False,
                'needs_confirmation': True,
                'pending_records': proxy_needed,
                'message': f"{feature_name} requires proxy to be enabled for {record_count} DNS record{'s' if record_count != 1 else ''} ({', '.join(record_names)}). Enable proxy?",
                'rollback_needed': False
            }
        
        # Auto-proxy is enabled, proceed with automatic proxy enablement
        logger.info(f"Auto-proxy enabled for {domain_name}, proceeding with automatic proxy enablement")
        
        # Enable proxy for eligible records
        modified_records = []
        failed_records = []
        
        logger.info(f"🔧 Enabling proxy for {len(proxy_needed)} records")
        
        for record in proxy_needed:
            record_id = record.get('id')
            record_name = record.get('name', 'unknown')
            
            if not record_id:
                logger.warning(f"No record ID for {record_name}, skipping")
                continue
            
            result = await cloudflare.update_record_proxied(zone_id, record_id, True)
            
            if result.get('success'):
                modified_records.append({
                    'id': record_id,
                    'name': record_name,
                    'type': record.get('type'),
                    'content': record.get('content')
                })
                logger.info(f"✅ Proxy enabled for {record_name}")
            else:
                errors = result.get('errors', [])
                error_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
                failed_records.append({'name': record_name, 'error': error_msg})
                logger.error(f"❌ Failed to enable proxy for {record_name}: {error_msg}")
        
        # Prepare user-friendly message
        success_count = len(modified_records)
        total_needed = len(proxy_needed)
        
        if success_count == total_needed and success_count > 0:
            # Complete success
            record_names = [r['name'] for r in modified_records]
            formatted_names = []
            for name in record_names:
                if name == domain_name:
                    formatted_names.append(f"{name} (root)")
                else:
                    formatted_names.append(f"{name}")
            
            message = f"🔧 Auto-Enabled Cloudflare Proxy\n\n"
            message += f"Enabled proxy for: {', '.join(formatted_names)}\n"
            message += f"_Required for {feature_name} to function properly._"
            
            # Notify user if query is provided
            if query:
                notification = f"""
🔧 Cloudflare Proxy Auto-Enabled

Enabled proxy for: {', '.join(formatted_names)}

_This is required for {feature_name} to work properly. Your feature will be enabled next._
"""
                await safe_edit_message(query, notification)
                # Brief pause for user to read
                await asyncio.sleep(1)
            
            return {
                'success': True,
                'modified_records': modified_records,
                'message': message,
                'rollback_needed': True
            }
        
        elif success_count > 0:
            # Partial success
            success_names = [r['name'] for r in modified_records]
            failed_names = [r['name'] for r in failed_records]
            
            message = f"⚠️ Partial Proxy Success\n\n"
            message += f"✅ Enabled: {', '.join(success_names)}\n"
            message += f"❌ Failed: {', '.join(failed_names)}\n\n"
            message += f"_Proceeding with {feature_name} for successfully proxied records._"
            
            return {
                'success': True,  # Partial success still allows feature to work
                'modified_records': modified_records,
                'message': message,
                'rollback_needed': True
            }
        
        else:
            # Complete failure
            error_details = []
            for failed in failed_records:
                error_details.append(f"• {failed['name']}: {failed['error']}")
            
            message = f"❌ Proxy Enablement Failed\n\n"
            message += f"Could not enable proxy for any records:\n"
            message += "\n".join(error_details[:3])  # Limit to 3 errors for readability
            if len(error_details) > 3:
                message += f"\n... and {len(error_details) - 3} more"
            
            return {
                'success': False,
                'modified_records': [],
                'message': message,
                'rollback_needed': False
            }
        
    except Exception as e:
        logger.error(f"❌ Error in auto-proxy for {feature_name}: {e}")
        return {
            'success': False,
            'modified_records': [],
            'message': f"Error enabling proxy for {feature_name}: {str(e)}",
            'rollback_needed': False
        }

async def rollback_proxy_changes(zone_id: str, modified_records: List[Dict]) -> bool:
    """
    Rollback proxy changes if feature enablement fails.
    
    Args:
        zone_id: Cloudflare zone ID
        modified_records: List of records that were modified during auto-proxy
        
    Returns:
        True if rollback successful, False otherwise
    """
    try:
        if not modified_records:
            return True
        
        cloudflare = CloudflareService()
        rollback_success = True
        
        logger.info(f"🔄 Rolling back proxy changes for {len(modified_records)} records")
        
        for record in modified_records:
            record_id = record.get('id')
            record_name = record.get('name', 'unknown')
            
            if not record_id:
                continue
            
            result = await cloudflare.update_record_proxied(zone_id, record_id, False)
            
            if result.get('success'):
                logger.info(f"↩️ Proxy disabled for {record_name} (rollback)")
            else:
                logger.error(f"❌ Failed to rollback proxy for {record_name}")
                rollback_success = False
        
        if rollback_success:
            logger.info("✅ Proxy rollback completed successfully")
        else:
            logger.warning("⚠️ Proxy rollback partially failed")
        
        return rollback_success
        
    except Exception as e:
        logger.error(f"❌ Error during proxy rollback: {e}")
        return False

def format_proxy_notification(domain_name: str, feature_name: str, modified_records: List[Dict]) -> str:
    """Format user notification for automatic proxy enablement"""
    if not modified_records:
        return f"No proxy changes needed for {feature_name}."
    
    record_names = []
    for record in modified_records:
        name = record.get('name', 'unknown')
        if name == domain_name:
            record_names.append(f"{name} (root)")
        else:
            record_names.append(f"{name}")
    
    notification = f"🔧 Proxy Auto-Enabled\n\n"
    notification += f"Records: {', '.join(record_names)}\n"
    notification += f"Feature: {feature_name}\n\n"
    notification += "_Cloudflare proxy is now active for these records to enable the requested feature._"
    
    return notification

# HOSTING PAYMENT INTEGRATION - PRIORITY 1
async def show_hosting_payment_options_with_intent(query, intent_id: int, price: float, plan_name: str, domain_name: str):
    """Show payment options for hosting provision intent"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        wallet_balance = await get_user_wallet_balance(user.id)
        has_sufficient_balance = wallet_balance >= float(price)
        domain_display = f"Domain: {domain_name}" if domain_name != 'pending-domain' else "Domain: To be configured"
        
        message = f"""💰 {t("hosting.payment_required_provision", user_lang)}
        
{domain_display}
{t("hosting.plan_label", user_lang)} {plan_name}
Price: ${price}/month
{t('wallet.your_wallet_balance', user_lang)} {format_money(wallet_balance, 'USD', include_currency=True)}

{t("hosting.choose_payment", user_lang)}"""
        
        keyboard = []
        if has_sufficient_balance:
            keyboard.append([InlineKeyboardButton(btn_t("pay_with_wallet_amount", user_lang, price=price), callback_data=f"pay_hosting_intent_wallet_{intent_id}")])
        
        keyboard.extend([
            [InlineKeyboardButton(t("buttons.pay_with_bitcoin", user_lang), callback_data=f"pay_hosting_intent_crypto_{intent_id}_bitcoin")],
            [InlineKeyboardButton(t("buttons.pay_with_ethereum", user_lang), callback_data=f"pay_hosting_intent_crypto_{intent_id}_ethereum")],
            [InlineKeyboardButton(t("buttons.pay_with_usdt", user_lang), callback_data=f"pay_hosting_intent_crypto_{intent_id}_usdt")],
            [InlineKeyboardButton(t("buttons.back_to_plans", user_lang), callback_data="hosting_plans")]
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Update intent status to payment_pending
        await update_hosting_intent_status(intent_id, 'payment_pending')
        
    except Exception as e:
        logger.error(f"Error showing hosting payment options with intent {intent_id}: {e}")
        await safe_edit_message(query, "❌ Error showing payment options. Please try again.")

async def show_hosting_payment_options(query, subscription_id: int, price: float, plan_name: str, domain_name: str):
    """Show payment options for hosting subscription (legacy - for existing subscriptions)"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        user_record = await get_or_create_user(user.id)
        wallet_balance = await get_user_wallet_balance(user.id)
        has_sufficient_balance = wallet_balance >= float(price)
        domain_display = f"Domain: {domain_name}" if domain_name != 'pending-domain' else "Domain: To be configured"
        
        message = f"""💰 {t("hosting.payment_required_title", user_lang)}

{domain_display}
{t("hosting.plan_label", user_lang)} {plan_name}
Price: ${price}/month
{t('wallet.your_wallet_balance', user_lang)} {format_money(wallet_balance, 'USD', include_currency=True)}

{t("hosting.choose_payment", user_lang)}"""
        
        keyboard = []
        if has_sufficient_balance:
            keyboard.append([InlineKeyboardButton(t("buttons.pay_with_wallet_balance", user_lang), callback_data=f"pay_hosting_wallet_{subscription_id}_{price}")])
        else:
            keyboard.append([InlineKeyboardButton(t("buttons.insufficient_balance", user_lang), callback_data="wallet_deposit")])
        
        keyboard.extend([
            [InlineKeyboardButton(t("buttons.bitcoin_btc", user_lang), callback_data=f"pay_hosting_btc_{subscription_id}_{price}")],
            [InlineKeyboardButton(t("buttons.litecoin_ltc", user_lang), callback_data=f"pay_hosting_ltc_{subscription_id}_{price}")],
            [InlineKeyboardButton(t("buttons.back_to_plans", user_lang), callback_data="hosting_plans")]
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing hosting payment options: {e}")
        await safe_edit_message(query, "❌ Error loading payment options. Please try again.")

async def process_hosting_crypto_payment(query, crypto_type: str, subscription_id: str, price: str):
    """Generate crypto payment for hosting subscription (based on domain crypto payment)"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        amount = float(price)
        
        # Get subscription details
        subscription = await execute_query(
            "SELECT * FROM hosting_subscriptions WHERE id = %s",
            (int(subscription_id),)
        )
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting subscription not found.")
            return
        
        subscription = subscription[0]
        
        await safe_edit_message(query, f"Generating {crypto_type.upper()} payment address...")
        
        # Get user record for database ID
        from database import get_or_create_user
        user_record = await get_or_create_user(telegram_id=user.id)
        
        # Skip $2 padding for USDT (stablecoin, no volatility)
        original_amount = Decimal(str(amount))
        is_stablecoin = crypto_type.lower() in ('usdt', 'usdt_trc20', 'usdt_erc20')
        gateway_amount = original_amount if is_stablecoin else original_amount + Decimal('2')
        
        # Generate payment with configured provider (DynoPay/BlockBee)
        order_id = f"hosting_{subscription_id}_{user.id}_{int(time.time())}"
        
        # FIXED: Use centralized factory method which creates payment intent and passes intent_id
        from services.payment_provider import PaymentProviderFactory
        payment_result = await PaymentProviderFactory.create_payment_address_with_fallback(
            currency=crypto_type.lower(),
            order_id=order_id,
            value=gateway_amount,
            user_id=user_record['id']
        )
        
        if not payment_result:
            await safe_edit_message(query, "❌ Payment Error\n\nCould not generate payment address. Please try again.")
            return
        
        # Save hosting payment order using single-table architecture (hosting_orders)
        # This consolidates all hosting orders (crypto + wallet) into one table
        hosting_order_id = await create_hosting_order_crypto(
            user_id=user_record['id'],
            hosting_plan_id=subscription.get('hosting_plan_id', 1),  # Get plan ID from subscription
            domain_name=subscription['domain_name'],
            expected_amount=Decimal(str(amount)),
            currency='USD',
            blockbee_order_id=order_id,  # Tracking ID for crypto payment
            intent_id=None,  # Will be set during provisioning
            subscription_id=int(subscription_id),
            payment_address=payment_result['address'],
            status='pending_payment'
        )
        
        if not hosting_order_id:
            await safe_edit_message(query, "❌ Error creating order. Please try again.")
            return
        
        # Show payment instructions
        payment_message = f"""
💰 Hosting Payment Instructions

Domain: {subscription['domain_name']}
Plan: {subscription.get('plan_name', 'Hosting Plan')}
Amount: ${amount}/month (≈ {payment_result.get('crypto_amount', 'TBD')} {crypto_type.upper()})

Send exactly this amount to:
<code>{payment_result['address']}</code>

⏰ Payment expires in 15 minutes
💡 Tap the address above to copy it

{t('hosting.errors.payment_required_message', user_lang)}
"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.cancel_order", user_lang), callback_data="hosting_plans")],
            [InlineKeyboardButton(t("buttons.back_to_hosting", user_lang), callback_data="my_hosting")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, payment_message, reply_markup=reply_markup)
        
        logger.info(f"Hosting crypto payment generated: {crypto_type.upper()} for subscription {subscription_id}")
        
    except Exception as e:
        logger.error(f"Error generating hosting crypto payment: {e}")
        await safe_edit_message(query, "❌ Error generating payment. Please try again.")

async def process_hosting_wallet_payment(query, subscription_id: str, price: str):
    """Process wallet payment for hosting subscription - OPTIMIZED with parallel DB queries"""
    user = query.from_user
    
    try:
        amount = float(price)
        
        # PERFORMANCE OPTIMIZATION: Fetch subscription, user, and language in parallel
        user_lang_code = user.language_code if hasattr(user, 'language_code') else None
        subscription_result, user_record, user_lang = await asyncio.gather(
            execute_query("SELECT * FROM hosting_subscriptions WHERE id = %s", (int(subscription_id),)),
            get_or_create_user(user.id),
            resolve_user_language(user.id, user_lang_code)
        )
        
        if not subscription_result:
            await safe_edit_message(query, "❌ Hosting subscription not found.")
            return
        
        subscription = subscription_result[0]
        user_id = user_record['id']
        
        await safe_edit_message(query, f"💳 Processing wallet payment for hosting...")
        
        # 🔒 REVENUE PROTECTION: Reserve wallet balance instead of immediate debit
        from database import reserve_wallet_balance
        
        hold_id = await reserve_wallet_balance(
            user_id, 
            Decimal(str(amount)), 
            f"Hosting subscription hold - {subscription['domain_name']}"
        )
        
        if not hold_id:
            await safe_edit_message(query, "❌ Insufficient wallet balance or payment error.")
            return
        
        logger.info(f"💳 WALLET HOLD: Created reservation {hold_id} for hosting subscription {subscription_id}")
        
        # Create payment details for wallet payments (matching registration fix pattern)
        wallet_payment_details = {
            'amount_usd': amount,
            'currency': 'USD', 
            'payment_method': 'wallet',
            'hold_transaction_id': hold_id  # Track the hold for finalization
        }
        
        # Update subscription with hold reference before processing
        await execute_update(
            "UPDATE hosting_subscriptions SET status = 'processing_payment', hold_transaction_id = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (hold_id, int(subscription_id))
        )
        
        # 🚀 REVENUE PROTECTION: Try hosting creation with hold in place
        hosting_success = False
        hosting_error = None
        
        try:
            # Create hosting account with hold protection
            await create_hosting_account_after_payment(int(subscription_id), subscription, wallet_payment_details)
            hosting_success = True
            logger.info(f"✅ Hosting account created successfully for subscription {subscription_id}")
            
        except Exception as hosting_exc:
            hosting_success = False
            hosting_error = str(hosting_exc)
            logger.error(f"❌ Hosting account creation failed for subscription {subscription_id}: {hosting_error}")
        
        # 🔒 CRITICAL: Finalize wallet payment based on hosting outcome
        from database import finalize_wallet_reservation
        
        finalization_success = await finalize_wallet_reservation(hold_id, success=hosting_success)
        
        if hosting_success and finalization_success:
            # Both hosting and payment succeeded
            await execute_update(
                "UPDATE hosting_subscriptions SET status = 'paid', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (int(subscription_id),)
            )
            logger.info(f"✅ REVENUE PROTECTION: Hosting subscription {subscription_id} completed with successful wallet charge")
            
            # Success message
            message = f"""{t('hosting.wallet_payment.success_title', user_lang)}

{t('hosting.account_notification.domain_label_emoji', user_lang)} {subscription['domain_name']}
{t('hosting.plan_label', user_lang)} {subscription.get('plan_name', 'Hosting Plan')}
{t('hosting.wallet_payment.amount_charged', user_lang)} ${amount:.2f}/month
{t('hosting.wallet_payment.payment_method', user_lang)} {t('wallet.balance', user_lang)}

{t('hosting.errors.account_being_created', user_lang)}
{t('hosting.errors.account_details_shortly', user_lang)}"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.my_hosting", user_lang), callback_data="my_hosting")],
                [InlineKeyboardButton(t("buttons.wallet", user_lang), callback_data="wallet_main")]
            ]
            
        elif hosting_success and not finalization_success:
            # Hosting created but wallet charge failed - REVENUE PROTECTION CRITICAL
            logger.error(f"🚨 REVENUE PROTECTION: Hosting created but wallet settlement failed for subscription {subscription_id}")
            
            # TODO: Send critical alert to admins when alert system is implemented  
            logger.error(f"ADMIN ALERT: HostingWalletSettlementFailure - domain {subscription['domain_name']} needs manual intervention")
            logger.error(f"Settlement failure context: subscription_id={subscription_id}, user_id={user_id}, domain_name={subscription['domain_name']}")
            
            # Mark as settlement failed
            await execute_update(
                "UPDATE hosting_subscriptions SET status = 'settlement_failed', error_message = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (f"Hosting created but wallet charge failed - hold {hold_id}", int(subscription_id))
            )
            
            # Notify user of temporary issue
            message = f"""{t('hosting.wallet_payment.settlement_issue_title', user_lang)}

{t('hosting.wallet_payment.settlement_issue_message', user_lang)}

{t('hosting.account_notification.domain_label_emoji', user_lang)} {subscription['domain_name']}
{t('hosting.wallet_payment.amount_charged', user_lang)} ${amount:.2f}/month"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.contact_support", user_lang), callback_data="contact_support")],
                [InlineKeyboardButton(t("buttons.wallet", user_lang), callback_data="wallet_main")]
            ]
            
        else:
            # Hosting creation failed - wallet hold refunded
            logger.info(f"💰 REVENUE PROTECTION: Hosting creation failed, wallet refunded for subscription {subscription_id}")
            
            # Mark as failed
            await execute_update(
                "UPDATE hosting_subscriptions SET status = 'failed', error_message = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (f"Hosting creation failed: {hosting_error}", int(subscription_id))
            )
            
            # User gets refund automatically
            message = f"""{t('hosting.wallet_payment.creation_failed_title', user_lang)}

{t('hosting.wallet_payment.creation_failed_message', user_lang)}

{t('hosting.wallet_payment.amount_refunded', user_lang)} ${amount:.2f}
{t('hosting.wallet_payment.error_label', user_lang)} {hosting_error or t('errors.try_again', user_lang)}"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"pay_hosting_wallet_{subscription_id}_{price}")],
                [InlineKeyboardButton(t("buttons.contact_support", user_lang), callback_data="contact_support")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Final logging
        if hosting_success and finalization_success:
            logger.info(f"✅ Hosting wallet payment successful: User {user.id}, Subscription {subscription_id}, Amount ${amount}")
        else:
            logger.warning(f"⚠️ Hosting wallet payment issue: User {user.id}, Subscription {subscription_id}, Hosting={hosting_success}, Settlement={finalization_success}")
        
    except Exception as e:
        logger.error(f"Error in hosting wallet payment: {e}")
        await safe_edit_message(query, "❌ Payment error. Please try again.")

async def create_hosting_account_after_payment(subscription_id: int, subscription: Dict, payment_details: Optional[Dict] = None):
    """Create cPanel hosting account after successful payment"""
    try:
        logger.info(f"🚀 Creating hosting account for subscription {subscription_id}")
        # Use configured service email for hosting account creation
        from utils.email_config import get_hosting_contact_email
        user_email = get_hosting_contact_email(subscription['user_id'])
        
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if p.get('id') == subscription['hosting_plan_id']), None)
        
        if not plan:
            logger.error(f"❌ Plan not found for subscription {subscription_id}")
            return
        
        account_details = await cpanel.create_hosting_account(
            domain=subscription['domain_name'],
            plan=plan.get('name', 'default'),
            email=user_email
        )
        
        if account_details:
            await execute_update(
                "UPDATE hosting_subscriptions SET cpanel_username = %s, cpanel_password = %s, server_ip = %s, status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (account_details['username'], account_details['password'], account_details['server_ip'], subscription_id)
            )
            
            await create_cpanel_account(
                subscription_id=subscription_id,
                username=account_details['username'],
                domain=subscription['domain_name'],
                server_name=account_details.get('server_name', 'server1'),
                ip_address=account_details['server_ip']
            )
            
            await send_hosting_account_notification(subscription['user_id'], account_details, subscription)
            logger.info(f"✅ Hosting account created successfully for subscription {subscription_id}")
            
        else:
            logger.error(f"❌ Failed to create hosting account for subscription {subscription_id}")
            
    except Exception as e:
        logger.error(f"Error creating hosting account after payment: {e}")

async def send_hosting_account_notification(user_id: int, account_details: Dict, subscription: Dict):
    """Send hosting account details to user via Telegram"""
    try:
        user = await execute_query("SELECT telegram_id FROM users WHERE id = %s", (user_id,))
        if not user:
            logger.error(f"User not found for hosting notification: {user_id}")
            return
        
        telegram_id = user[0]['telegram_id']
        
        message = f"""{t('hosting.account_notification.ready_title', 'en')}

{t('hosting.account_notification.created_successfully', 'en')}

{t('hosting.account_notification.domain_label_emoji', 'en')} {subscription['domain_name']}
{t('hosting.account_notification.username_label_emoji', 'en')} {account_details['username']}
{t('hosting.account_notification.password_label_emoji', 'en')} {account_details['password']}
{t('hosting.account_notification.server_ip_label', 'en')} {account_details['server_ip']}

{t('hosting.account_notification.cpanel_login_label', 'en')} {account_details.get('cpanel_url', f"https://{subscription['domain_name']}:2083")}

{t('hosting.account_notification.nameservers_title', 'en')}
{chr(10).join(f"• {ns}" for ns in account_details.get('nameservers', ['ns1.yourhost.com', 'ns2.yourhost.com']))}

{t('hosting.account_notification.setup_instructions_title', 'en')}
{t('hosting.account_notification.setup_step_1', 'en')}
{t('hosting.account_notification.setup_step_2', 'en')}
{t('hosting.account_notification.setup_step_3', 'en')}

{t('help.contact', 'en', support_contact=BrandConfig().support_contact)}"""
        
        from webhook_handler import queue_user_message
        await queue_user_message(telegram_id, message)
        logger.info(f"✅ Hosting account notification sent to user {telegram_id}")
            
    except Exception as e:
        logger.error(f"Error sending hosting account notification: {e}")

# PRIORITY 2.1: DOMAIN + HOSTING BUNDLE INTEGRATION
async def show_domain_hosting_bundle(query):
    """Show domain + hosting bundle options with clear value proposition"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        plans = cpanel.get_hosting_plans()
        
        message = f"""📦 {t("hosting.bundle_title", user_lang)}

🎯 {t("hosting.bundle_subtitle", user_lang)}
✅ {t("hosting.bundle_feature_domain", user_lang)}
✅ {t("hosting.bundle_feature_dns", user_lang)}
✅ {t("hosting.bundle_feature_setup", user_lang)}
✅ {t("hosting.bundle_feature_email", user_lang)}
✅ {t("hosting.bundle_feature_uptime", user_lang)}

💰 {t("hosting.bundle_savings_title", user_lang)}
• {t("hosting.bundle_savings_time", user_lang)}
• {t("hosting.bundle_savings_oneclick", user_lang)}
• {t("hosting.bundle_savings_nameservers", user_lang)}
• {t("hosting.bundle_savings_support", user_lang)}

🚀 {t("hosting.bundle_choose_plan", user_lang)}"""
        
        keyboard = []
        
        # Add hosting plans with bundle indicators
        for plan in plans:
            plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
            monthly_price = plan.get('monthly_price', 0)
            plan_id = plan.get('id')
            
            # Calculate typical domain price for bundle display using pricing system
            from pricing_utils import PricingConfig
            pricing_config = PricingConfig()
            typical_domain_price = pricing_config.minimum_price
            bundle_total = monthly_price + typical_domain_price
            
            button_text = f"🌟 {plan_name} - ${bundle_total:.0f}/month* (Domain + Hosting)"
            keyboard.append([InlineKeyboardButton(button_text, callback_data=f"bundle_plan_{plan_id}")])
        
        keyboard.extend([
            [InlineKeyboardButton(btn_t("how_it_works", user_lang), callback_data="bundle_how_it_works")],
            [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data="main_menu")]
        ])
        
        footer_text = "\n\n*Domain price varies by extension (.com, .net, etc.)\nFinal price shown during checkout"
        message += footer_text
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing domain hosting bundle: {e}")
        await safe_edit_message(query, "❌ Error loading bundle options. Please try again.")

async def show_bundle_how_it_works(query):
    """Explain the domain + hosting bundle process"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    message = f"""💡 {t("hosting.bundle_how_it_works_title", user_lang)}

1️⃣ {t("hosting.bundle_how_it_works_steps", user_lang)} ✅

{t("hosting.bundle_how_it_works_includes", user_lang)}

{t("hosting.bundle_ready", user_lang)}"""
    
    keyboard = [
        [InlineKeyboardButton(t("buttons.start_bundle_purchase", user_lang), callback_data="domain_hosting_bundle")],
        [InlineKeyboardButton(t("buttons.back_to_dashboard", user_lang), callback_data="main_menu")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def start_bundle_domain_search(query, context, plan_id):
    """Start domain search for bundle purchase"""
    user = query.from_user
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""🔍 {plan_name} Bundle (${monthly_price}/month)

Enter domain name:
<i>e.g., mybusiness.com</i>"""
        
        keyboard = [
            [InlineKeyboardButton(t("buttons.back_to_bundle_plans", user_lang), callback_data="domain_hosting_bundle")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context for next user message in proper context storage
        context.user_data['bundle_domain_search'] = {'plan_id': plan_id}
        
    except Exception as e:
        logger.error(f"Error starting bundle domain search: {e}")
        await safe_edit_message(query, "❌ Error starting domain search. Please try again.")

async def process_bundle_domain_search(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_name: str, plan_id: str):
    """Process domain search for bundle purchase"""
    message = update.effective_message
    user = update.effective_user
    
    # Get user_lang early for all uses in this function
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None) if user else 'en'
    
    try:
        # Validate domain format with detailed error message
        if not is_valid_domain(domain_name):
            error_msg = get_domain_validation_error(domain_name)
            if message:
                await message.reply_text(
                    create_error_message(
                        "Invalid Domain Format",
                        f"{domain_name} - {error_msg}\n\nValid examples:\n• example.com\n• my-site.org\n• sub.domain.net"
                    ),
                    parse_mode='HTML'
                )
            return
        
        # Get hosting plan details
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            if message:
                await message.reply_text(t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        monthly_price = plan.get('monthly_price', 0)
        
        searching_msg = None
        if message:
            searching_msg = await message.reply_text(f"🔄 {t('wallet.searching_bundle', user_lang, domain=domain_name)}")
        
        # Check domain availability
        availability = await openprovider.check_domain_availability(domain_name)
        
        if availability is None:
            response_text = t('errors.service_temporarily_down', user_lang)
            keyboard = [
                [InlineKeyboardButton(t("buttons.try_again", user_lang), callback_data=f"bundle_plan_{plan_id}")],
                [InlineKeyboardButton(t("buttons.back_to_bundle", user_lang), callback_data="domain_hosting_bundle")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            if searching_msg:
                await searching_msg.edit_text(response_text, reply_markup=reply_markup)
            return
        
        if availability.get('available'):
            # Domain is available - show bundle pricing
            price_info = availability.get('price_info', {})
            domain_price = price_info.get('create_price', 0)
            currency = price_info.get('currency', 'USD')
            is_premium = availability.get('premium', False)
            
            bundle_total = domain_price + monthly_price
            
            # Create attractive bundle presentation
            domain_display = f"💎 {t('domain.status.premium_domain', user_lang).capitalize()}" if is_premium else f"✅ {t('domain.status.available', user_lang).capitalize()}"
            
            response_text = f"""{t('domain.bundle.available_title', user_lang, domain=domain_name)}

{domain_display}

📦 Bundle Breakdown:
🌐 Domain: {domain_name} - ${domain_price:.2f}/year
🏠 Hosting: {plan_name} - ${monthly_price:.2f}/month

💰 Total First Month: ${bundle_total:.2f}
💡 Then ${monthly_price:.2f}/month for hosting

🚀 Bundle Includes:
✅ Domain registered with hosting nameservers
✅ Automatic DNS configuration
✅ Instant hosting account setup
✅ Professional email hosting
✅ cPanel control panel access
✅ 99.9% uptime guarantee

Ready to complete your bundle purchase?"""
            
            keyboard = [
                [InlineKeyboardButton(btn_t("purchase_bundle", user_lang, price=f"{bundle_total:.2f}"), callback_data=f"confirm_bundle_{plan_id}_{domain_name}")],
                [InlineKeyboardButton(t("buttons.search_different_domain", user_lang), callback_data=f"bundle_plan_{plan_id}")],
                [InlineKeyboardButton(t("buttons.back_to_bundle_plans", user_lang), callback_data="domain_hosting_bundle")]
            ]
        else:
            # Domain not available - show alternatives
            response_text = f"""{t('domain.bundle.not_available_title', user_lang, domain=domain_name)}

{t('domain.bundle.already_registered', user_lang)}

{t('domain.bundle.try_alternatives', user_lang)}
{t('domain.bundle.alternatives_list', user_lang)}

{t('domain.bundle.search_another', user_lang)}"""
            
            keyboard = [
                [InlineKeyboardButton(t("buttons.search_different_domain", user_lang), callback_data=f"bundle_plan_{plan_id}")],
                [InlineKeyboardButton(t("buttons.back_to_bundle_plans", user_lang), callback_data="domain_hosting_bundle")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        if searching_msg:
            await searching_msg.edit_text(response_text, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error processing bundle domain search: {e}")
        if message:
            await message.reply_text(t('errors.domain_search_failed', user_lang))

async def confirm_bundle_purchase(query, plan_id: str, domain_name: str):
    """Confirm and create bundle purchase (domain + hosting)"""
    user = query.from_user
    
    # Get user language early
    user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
    
    try:
        # Get final pricing and create combined order
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, t('hosting.plan_not_found', user_lang))
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        monthly_price = plan.get('monthly_price', 0)
        
        # Get final domain pricing
        availability = await openprovider.check_domain_availability(domain_name)
        if not availability or not availability.get('available'):
            await safe_edit_message(query, t('hosting.domain_unavailable', user_lang, domain=domain_name))
            return
        
        domain_price = availability.get('price_info', {}).get('create_price', 0)
        bundle_total = domain_price + monthly_price
        
        # Create database user record
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Create hosting provision intent for bundle orders to prevent duplicates
        existing_intent = await get_active_hosting_intent(db_user['id'], domain_name)
        if existing_intent:
            # Use existing intent for bundle orders
            logger.info(f"⚠️ Using existing hosting intent {existing_intent['id']} for bundle order")
            # Still create a temporary subscription ID for bundle flow compatibility
            subscription_id = 999999  # Temporary placeholder for bundle flow
        else:
            # Create new hosting provision intent
            intent_id = await create_hosting_intent(
                user_id=db_user['id'],
                domain_name=domain_name,
                hosting_plan_id=plan.get('id'),
                estimated_price=bundle_total,  # Use full bundle price
                service_type='hosting_domain_bundle'  # This is a domain + hosting bundle
            )
            if intent_id:
                subscription_id = intent_id  # Use intent_id as subscription_id for bundle flow
                logger.info(f"✅ Created hosting provision intent {intent_id} for bundle order")
            else:
                subscription_id = None
        
        if not subscription_id:
            user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
            await safe_edit_message(query, t('errors.bundle_order_creation_failed', user_lang))
            return
        
        # Store bundle context in subscription (for coordinated provisioning)
        await execute_update(
            "UPDATE hosting_subscriptions SET notes = %s WHERE id = %s",
            (f"bundle_order:domain_price:{domain_price}", subscription_id)
        )
        
        # Show combined payment options (hosting price + domain price)
        await show_hosting_payment_options(query, subscription_id, bundle_total, f"{plan_name} + {domain_name}", domain_name)
        
        logger.info(f"✅ Bundle order created: User {user.id}, Domain {domain_name}, Plan {plan_name}, Total ${bundle_total}")
        
    except Exception as e:
        logger.error(f"Error confirming bundle purchase: {e}")
        user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
        await safe_edit_message(query, t('errors.bundle_purchase_processing_failed', user_lang))

async def handle_unified_checkout_review(query, subscription_id: str):
    """Handle when user wants to change payment method - redirect to payment options"""
    try:
        # Get subscription details from database
        from database import get_hosting_subscription_details_admin
        
        subscription = await get_hosting_subscription_details_admin(int(subscription_id))
        if not subscription:
            user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
            await safe_edit_message(query, t('errors.order_not_found', user_lang))
            return
        
        # Extract details
        plan_name = subscription.get('plan_name', 'Unknown Plan')
        domain_name = subscription.get('domain_name', '')
        service_type = subscription.get('service_type', 'hosting_only')
        
        # Determine items and pricing based on service type
        if service_type == 'hosting_domain_bundle' and domain_name:
            items = [f"Domain registration: {domain_name}", f"{plan_name} hosting"]
            # Get combined pricing from subscription notes if available
            notes = subscription.get('notes', '')
            if 'domain_price:' in notes:
                domain_price = float(notes.split('domain_price:')[1])
                total_price = subscription.get('total_amount', domain_price + subscription.get('period_price', 0))
            else:
                total_price = subscription.get('total_amount', subscription.get('period_price', 0))
        elif service_type == 'hosting_with_existing_domain' and domain_name:
            items = [f"Connect domain: {domain_name}", f"{plan_name} hosting"]
            total_price = subscription.get('period_price', 0)
        else:
            items = [f"{plan_name} hosting"]
            total_price = subscription.get('period_price', 0)
        
        # Show payment options again
        await show_unified_payment_options(
            query,
            int(subscription_id),
            float(total_price),
            plan_name,
            domain_name or f"temp_{query.from_user.id}_{int(time.time())}",
            items,
            service_type
        )
        
    except Exception as e:
        logger.error(f"Error in unified checkout review: {e}")
        user_lang = await resolve_user_language(query.from_user.id, query.from_user.language_code if hasattr(query.from_user, 'language_code') else None)
        await safe_edit_message(query, t('errors.payment_options_load_failed', user_lang))

# ====================================================================
# WINDOWS RDP SERVER MANAGEMENT
# ====================================================================

# RDP Smart Defaults System
RDP_SMART_DEFAULTS = {
    'template_id': 2514,  # Windows 2025 Standard (vultr_os_id)
    'plan_name': 'Starter',
    'region': 'ewr',  # New York fallback
    'billing_cycle': 'monthly',
    'payment_method': 'wallet'
}

def get_rdp_default(key):
    """Get smart default with logging"""
    default = RDP_SMART_DEFAULTS.get(key)
    logger.info(f"📋 Using RDP default: {key}={default}")
    return default

async def send_provisioning_error(telegram_id: int, message: str):
    """Send provisioning error message to user via Telegram"""
    try:
        bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        if not bot_token:
            logger.error("❌ TELEGRAM_BOT_TOKEN not set in environment")
            return
        
        from telegram import Bot
        bot = Bot(token=bot_token)
        await bot.send_message(
            chat_id=telegram_id,
            text=f"❌ {message}",
            parse_mode='HTML'
        )
    except Exception as e:
        logger.error(f"Failed to send provisioning error to user {telegram_id}: {e}")

async def handle_rdp_main(query):
    """Show RDP main menu"""
    try:
        user = query.from_user
        
        message = await t_for_user('rdp.main.title', user.id)
        message += "\n\n"
        message += await t_for_user('rdp.main.features', user.id)
        message += "\n"
        message += await t_for_user('rdp.main.description', user.id)
        message += "\n"
        message += await t_for_user('rdp.main.offerings', user.id)
        
        keyboard = [
            [InlineKeyboardButton(await t_for_user('rdp.buttons.purchase', user.id), callback_data="rdp_purchase_start")],
            [InlineKeyboardButton(await t_for_user('rdp.buttons.my_servers', user.id), callback_data="rdp_my_servers")],
            [InlineKeyboardButton(await t_for_user('rdp.buttons.back_main', user.id), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in RDP main menu: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.menu_error', user.id))

async def handle_rdp_purchase_start(query, context):
    """Phase 1 Optimized: Two-path entry point for RDP purchase"""
    user = query.from_user
    try:
        logger.info(f"🚀 RDP purchase start - two-path entry for user {user.id}")
        
        # Initialize wizard state (context.user_data is managed by PTB, just update it)
        context.user_data['rdp_wizard'] = {
            'template_id': None,
            'plan_id': None,
            'region': None,
            'billing_cycle': 'monthly'
        }
        
        # Get user ID and existing servers
        db_user_id = await get_internal_user_id_from_telegram_id(user.id)
        servers = []
        if db_user_id:
            servers = await execute_query("""
                SELECT id, hostname, status, plan_id, public_ip 
                FROM rdp_servers 
                WHERE user_id = %s AND deleted_at IS NULL 
                ORDER BY created_at DESC 
                LIMIT 3
            """, (db_user_id,))
        
        message = await t_for_user('rdp.purchase.title', user.id) + "\n\n"
        message += await t_for_user('rdp.purchase.features_short', user.id) + "\n"
        message += await t_for_user('rdp.purchase.description_short', user.id) + "\n\n"
        
        # Show existing servers if any
        if servers and len(servers) > 0:
            message += f"<b>{await t_for_user('rdp.purchase.your_servers', user.id)}</b>\n"
            for server in servers:
                status_emoji = "🟢" if server['status'] == 'active' else "🟡" if server['status'] == 'provisioning' else "⚪"
                ip = server['public_ip'] if server.get('public_ip') else await t_for_user('rdp.purchase.pending', user.id)
                message += f"{status_emoji} <code>{ip}</code>\n"
            message += "\n"
        
        message += f"<b>{await t_for_user('rdp.purchase.choose_method', user.id)}</b>\n\n"
        message += f"<b>{await t_for_user('rdp.purchase.quick_deploy_label', user.id)}</b> {await t_for_user('rdp.purchase.quick_deploy_desc', user.id)}\n"
        message += f"<b>{await t_for_user('rdp.purchase.customize_label', user.id)}</b> {await t_for_user('rdp.purchase.customize_desc', user.id)}"
        
        keyboard = [
            [InlineKeyboardButton(await t_for_user('rdp.buttons.quick_deploy', user.id), callback_data="rdp_quick_deploy")],
            [InlineKeyboardButton(await t_for_user('rdp.buttons.customize', user.id), callback_data="rdp_customize_start")]
        ]
        
        # Add "My Servers" button if user has servers
        if servers and len(servers) > 0:
            keyboard.append([InlineKeyboardButton(await t_for_user('rdp.buttons.view_all', user.id), callback_data="rdp_my_servers")])
        
        keyboard.append([InlineKeyboardButton(await t_for_user('rdp.buttons.back_main', user.id), callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in RDP purchase start: {e}")
        await safe_edit_message(query, await t_for_user('rdp.errors.purchase_start_error', user.id))

async def handle_rdp_quick_deploy(query, context):
    """Phase 1: Quick Deploy with smart defaults and last order memory"""
    try:
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        db_user_id = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user_id:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_load_error', user.id))
            return
        
        logger.info(f"⚡ Quick Deploy for user {user.id}")
        
        # Retrieve last successful order
        last_server = await execute_query("""
            SELECT rs.template_id, rs.plan_id, rs.region, rs.billing_cycle,
                   rt.windows_version, rt.edition, rt.vultr_os_id,
                   rp.plan_name, rp.vcpu_count, rp.ram_mb, rp.storage_gb, rp.our_monthly_price
            FROM rdp_servers rs
            LEFT JOIN rdp_templates rt ON rs.template_id = rt.id
            LEFT JOIN rdp_plans rp ON rs.plan_id = rp.id
            WHERE rs.user_id = %s AND rs.status = 'active' AND rs.deleted_at IS NULL
            ORDER BY rs.created_at DESC
            LIMIT 1
        """, (db_user_id,))
        
        # Smart defaults
        if last_server and len(last_server) > 0:
            # Use last order settings
            last_server = last_server[0]
            template_id = last_server['template_id']
            plan_id = last_server['plan_id']
            region = last_server['region']
            billing_cycle = last_server['billing_cycle'] or 'monthly'
            windows_version = last_server['windows_version']
            edition = last_server['edition']
            plan_name = last_server['plan_name']
            ram_gb = last_server['ram_mb'] / 1024
            vcpu = last_server['vcpu_count']
            monthly_price = float(last_server['our_monthly_price'])
            source = "last order"
        else:
            # First-time user: smart defaults
            logger.warning(f"📋 No previous RDP servers for user {user.id}, using smart defaults")
            
            # Windows 2025 Standard (vultr_os_id = 2514)
            template = await execute_query("""
                SELECT id, windows_version, edition, vultr_os_id
                FROM rdp_templates
                WHERE vultr_os_id = 2514 AND is_active = true
                LIMIT 1
            """)
            
            if not template or len(template) == 0:
                logger.warning("⚠️ Default template (Windows 2025) not found, trying fallback")
                # Fallback to any active template
                template = await execute_query("""
                    SELECT id, windows_version, edition, vultr_os_id
                    FROM rdp_templates
                    WHERE is_active = true
                    ORDER BY windows_version DESC
                    LIMIT 1
                """)
            
            # Starter plan (default)
            plan = await execute_query("""
                SELECT id, plan_name, vcpu_count, ram_mb, storage_gb, our_monthly_price
                FROM rdp_plans
                WHERE plan_name = 'Starter' AND is_active = true
                LIMIT 1
            """)
            
            # Check if queries returned data
            if not template or len(template) == 0 or not plan or len(plan) == 0:
                logger.error(f"❌ RDP catalog empty - template: {bool(template)}, plan: {bool(plan)}")
                await safe_edit_message(query, await t_for_user('rdp.errors.catalog_empty', user.id))
                return
            
            template = template[0]
            plan = plan[0]
            template_id = template['id']
            plan_id = plan['id']
            windows_version = template['windows_version']
            edition = template['edition']
            plan_name = plan['plan_name']
            vcpu = plan['vcpu_count']
            ram_gb = plan['ram_mb'] / 1024
            monthly_price = float(plan['our_monthly_price'])
            billing_cycle = 'monthly'
            
            # Auto-detect region from user's language code
            user_lang = user.language_code or 'en'
            region_map = {
                'en': 'ewr', 'de': 'fra', 'fr': 'cdg', 'es': 'mad',
                'ja': 'nrt', 'ko': 'icn', 'zh': 'sgp', 'pt': 'sao',
                'nl': 'ams', 'pl': 'waw', 'sv': 'sto', 'it': 'fra'
            }
            region = region_map.get(user_lang, 'ewr')
            source = "smart defaults"
        
        # Get region display name
        region_data = await execute_query("""
            SELECT city, country FROM 
            (VALUES 
                ('ewr', 'New Jersey', 'US'),
                ('ord', 'Chicago', 'US'),
                ('lhr', 'London', 'GB'),
                ('fra', 'Frankfurt', 'DE'),
                ('nrt', 'Tokyo', 'JP'),
                ('sgp', 'Singapore', 'SG'),
                ('syd', 'Sydney', 'AU'),
                ('cdg', 'Paris', 'FR'),
                ('ams', 'Amsterdam', 'NL'),
                ('mad', 'Madrid', 'ES'),
                ('icn', 'Seoul', 'KR'),
                ('sao', 'São Paulo', 'BR')
            ) AS regions(id, city, country)
            WHERE id = %s
        """, (region,))
        
        region_name = f"{region_data[0]['city']}" if region_data else region.upper()
        
        # Check if wizard already has a billing cycle (from user selection)
        wizard = context.user_data.get('rdp_wizard', {})
        if wizard.get('billing_cycle'):
            billing_cycle = wizard['billing_cycle']
        
        # Store in wizard state
        context.user_data['rdp_wizard'] = {
            'template_id': template_id,
            'plan_id': plan_id,
            'region': region,
            'billing_cycle': billing_cycle,
            'confirmation_source': 'quick_deploy'
        }
        
        # Calculate total upfront amount based on billing cycle
        billing_multipliers = {
            'monthly': 1.0,
            'quarterly': 0.94,  # 6% discount
            'yearly': 0.89      # 11% discount
        }
        billing_periods = {
            'monthly': 1,
            'quarterly': 3,
            'yearly': 12
        }
        
        multiplier = billing_multipliers.get(billing_cycle, 1.0)
        periods = billing_periods.get(billing_cycle, 1)
        
        # Total upfront payment
        total_amount = monthly_price * periods * multiplier
        # Effective per-month rate
        per_month_rate = total_amount / periods
        
        # Get wallet balance (db_user_id is internal user_id, not telegram_id)
        wallet_balance = await get_user_wallet_balance_by_id(db_user_id)
        
        # Format price display based on billing cycle
        if billing_cycle == 'monthly':
            price_display = f"${total_amount:.2f}/mo"
        else:
            price_display = f"Total ${total_amount:.2f} (${per_month_rate:.2f}/mo)"
        
        message = f"🚀 <b>{await t_for_user('rdp.quick_deploy.ready_title', user.id)}</b>\n\n"
        message += f"🖥️ <b>{plan_name}</b> • {vcpu}c/{ram_gb:.0f}GB • {price_display}\n"
        message += f"📍 {region_name} • 🪟 {windows_version} {edition}\n"
        message += f"💰 {await t_for_user('rdp.quick_deploy.billing', user.id, billing=billing_cycle.capitalize())}\n\n"
        message += f"💳 {await t_for_user('rdp.quick_deploy.wallet', user.id, balance=float(wallet_balance))}\n\n"
        message += f"<i>{await t_for_user('rdp.quick_deploy.using_source', user.id, source=source)}</i>"
        
        keyboard = [
            [InlineKeyboardButton(await t_for_user('rdp.buttons.confirm_pay', user.id), callback_data="rdp_confirm_and_create_order")],
            [InlineKeyboardButton(await t_for_user('rdp.buttons.change_billing', user.id), callback_data=f"rdp_change_billing_{region}")],
            [InlineKeyboardButton(await t_for_user('rdp.buttons.edit_settings', user.id), callback_data="rdp_customize_start")],
            [InlineKeyboardButton(await t_for_user('rdp.buttons.cancel', user.id), callback_data="rdp_purchase_start")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in Quick Deploy: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.quick_deploy_error', user.id))

async def handle_rdp_customize_start(query, context):
    """Phase 1: Bundled Plan + OS Selection (Customize Path)"""
    try:
        user = query.from_user
        logger.info(f"🛠️ Customize start for user {user.id}")
        
        # Initialize wizard if needed
        if not context.user_data.get('rdp_wizard'):
            context.user_data['rdp_wizard'] = {}
        
        # Check if template already selected
        selected_template = None
        if context.user_data.get('rdp_wizard', {}).get('template_id'):
            # Use previously selected template
            template_id = context.user_data['rdp_wizard']['template_id']
            selected_template = await execute_query("""
                SELECT id, windows_version, edition, vultr_os_id
                FROM rdp_templates
                WHERE id = %s AND is_active = true
                LIMIT 1
            """, (template_id,))
        
        # If no template selected or template not found, use default (Windows 2025)
        if not selected_template:
            default_template = await execute_query("""
                SELECT id, windows_version, edition, vultr_os_id
                FROM rdp_templates
                WHERE vultr_os_id = 2514 AND is_active = true
                LIMIT 1
            """)
            
            if not default_template:
                default_template = await execute_query("""
                    SELECT id, windows_version, edition, vultr_os_id
                    FROM rdp_templates
                    WHERE is_active = true
                    ORDER BY windows_version DESC
                    LIMIT 1
                """)
            
            if not default_template:
                await safe_edit_message(query, await t_for_user('rdp.errors.no_templates', user.id))
                return
            
            default_template = default_template[0]
            context.user_data['rdp_wizard']['template_id'] = default_template['id']
        else:
            # Use the selected template
            default_template = selected_template[0]
        
        # Get all plans with markup pricing
        plans = await execute_query("""
            SELECT id, plan_name, vcpu_count, ram_mb, storage_gb, our_monthly_price
            FROM rdp_plans
            WHERE is_active = true
            ORDER BY our_monthly_price ASC
        """)
        
        if not plans:
            await safe_edit_message(query, await t_for_user('rdp.errors.no_plans', user.id))
            return
        
        # Build compact plan selection with OS badge
        plan_icons = {
            'Starter': '💰',
            'Basic': '⚙️',
            'Performance': '🚀',
            'Power': '💪'
        }
        
        message = f"<b>{await t_for_user('rdp.customize.select_server', user.id)}</b>\n\n"
        message += f"🪟 <b>{await t_for_user('rdp.customize.windows_version', user.id, version=default_template['windows_version'], edition=default_template['edition'])}</b>\n\n"
        
        keyboard = []
        for plan in plans:
            icon = plan_icons.get(plan['plan_name'], '💻')
            vcpu = plan['vcpu_count']
            ram_gb = plan['ram_mb'] / 1024
            storage = plan['storage_gb']
            price = float(plan['our_monthly_price'])
            
            button_text = f"{icon} {plan['plan_name'].upper()} • ${price}/mo"
            keyboard.append([InlineKeyboardButton(button_text, callback_data=f"rdp_select_plan_{plan['id']}")])
        
        # Change Windows version button
        keyboard.append([InlineKeyboardButton(await t_for_user('rdp.buttons.change_windows', user.id), callback_data="rdp_change_windows")])
        keyboard.append([InlineKeyboardButton(await t_for_user('rdp.buttons.back', user.id), callback_data="rdp_purchase_start")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in Customize start: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.customize_error', user.id))

async def handle_rdp_select_plan(query, context, plan_id: str):
    """Handle plan selection from customize flow"""
    try:
        user = query.from_user
        
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, await t_for_user('rdp.region.loading', user.id))
        
        # Store selected plan
        if not context.user_data.get('rdp_wizard'):
            context.user_data['rdp_wizard'] = {}
        context.user_data['rdp_wizard']['plan_id'] = int(plan_id)
        
        logger.info(f"📦 Plan {plan_id} selected")
        
        # Proceed to smart region selection
        await handle_rdp_region_smart(query, context)
        
    except Exception as e:
        logger.error(f"Error selecting plan: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.regions_error', user.id))

async def handle_rdp_change_windows(query, context):
    """Show Windows version selection"""
    try:
        user = query.from_user
        
        templates = await execute_query("""
            SELECT id, windows_version, edition
            FROM rdp_templates
            WHERE is_active = true
            ORDER BY windows_version DESC
        """)
        
        if not templates:
            await safe_edit_message(query, await t_for_user('rdp.customize.no_templates', user.id))
            return
        
        title = await t_for_user('rdp.windows.title', user.id)
        prompt = await t_for_user('rdp.windows.prompt', user.id)
        
        message = f"""
<b>{title}</b>

{prompt}
"""
        
        keyboard = []
        for template in templates:
            button_text = f"🪟 {template['windows_version']} {template['edition']}"
            keyboard.append([InlineKeyboardButton(button_text, callback_data=f"rdp_set_template_{template['id']}")])
        
        keyboard.append([InlineKeyboardButton(await t_for_user('rdp.buttons.back', user.id), callback_data="rdp_customize_start")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing Windows versions: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.windows_error', user.id))

async def handle_rdp_set_template(query, context, template_id: str):
    """Set template and return to plan selection"""
    try:
        if not context.user_data.get('rdp_wizard'):
            context.user_data['rdp_wizard'] = {}
        context.user_data['rdp_wizard']['template_id'] = int(template_id)
        
        logger.info(f"🪟 Template {template_id} selected")
        
        # Return to customize start
        await handle_rdp_customize_start(query, context)
        
    except Exception as e:
        logger.error(f"Error setting template: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.windows_error', user.id))

async def handle_rdp_region_smart(query, context):
    """Phase 1: Smart region detection with top 3 suggestions"""
    try:
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        logger.info(f"🌍 Smart region selection for user {user.id}")
        
        # Detect user location from language code
        user_lang = user.language_code or 'en'
        
        # Region suggestions based on language/locale
        region_suggestions = {
            'en': ['ewr', 'ord', 'lhr'],
            'de': ['fra', 'ams', 'lhr'],
            'fr': ['cdg', 'fra', 'ams'],
            'es': ['mad', 'fra', 'lhr'],
            'ja': ['nrt', 'sgp', 'syd'],
            'ko': ['icn', 'nrt', 'sgp'],
            'zh': ['sgp', 'nrt', 'icn'],
            'pt': ['sao', 'mia', 'mad'],
            'nl': ['ams', 'fra', 'lhr'],
            'pl': ['waw', 'fra', 'ams'],
            'sv': ['sto', 'fra', 'ams'],
            'it': ['fra', 'mad', 'lhr']
        }
        
        top_regions = region_suggestions.get(user_lang, ['ewr', 'lhr', 'sgp'])
        
        # Region data with emojis
        region_info = {
            'ewr': {'name': 'New Jersey', 'emoji': '🌎', 'desc': 'East Coast US'},
            'ord': {'name': 'Chicago', 'emoji': '🌎', 'desc': 'Central US'},
            'lhr': {'name': 'London', 'emoji': '🌍', 'desc': 'Europe'},
            'fra': {'name': 'Frankfurt', 'emoji': '🌍', 'desc': 'Europe'},
            'nrt': {'name': 'Tokyo', 'emoji': '🌏', 'desc': 'Asia Pacific'},
            'sgp': {'name': 'Singapore', 'emoji': '🌏', 'desc': 'Asia Pacific'},
            'syd': {'name': 'Sydney', 'emoji': '🌏', 'desc': 'Australia'},
            'cdg': {'name': 'Paris', 'emoji': '🌍', 'desc': 'Europe'},
            'ams': {'name': 'Amsterdam', 'emoji': '🌍', 'desc': 'Europe'},
            'mad': {'name': 'Madrid', 'emoji': '🌍', 'desc': 'Europe'},
            'icn': {'name': 'Seoul', 'emoji': '🌏', 'desc': 'Asia Pacific'},
            'sao': {'name': 'São Paulo', 'emoji': '🌎', 'desc': 'South America'},
            'waw': {'name': 'Warsaw', 'emoji': '🌍', 'desc': 'Europe'},
            'sto': {'name': 'Stockholm', 'emoji': '🌍', 'desc': 'Europe'},
            'mia': {'name': 'Miami', 'emoji': '🌎', 'desc': 'Southeast US'}
        }
        
        title = await t_for_user('rdp.region.title', user.id)
        closest_text = await t_for_user('rdp.region.closest', user.id)
        view_all_text = await t_for_user('rdp.region.view_all', user.id)
        back_text = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
<b>{title}</b>

"""
        
        keyboard = []
        
        # Top 3 suggestions as full-width buttons
        for i, region_code in enumerate(top_regions):
            info = region_info.get(region_code, {'name': region_code.upper(), 'emoji': '🌐', 'desc': ''})
            closest = closest_text if i == 0 else ""
            button_text = f"{info['emoji']} {info['name'].upper()}{closest}\n{info['desc']}"
            keyboard.append([InlineKeyboardButton(button_text, callback_data=f"rdp_set_region_{region_code}")])
        
        # View All Regions button
        keyboard.append([InlineKeyboardButton(view_all_text, callback_data="rdp_regions_all")])
        
        # Context-aware Back button
        # If there's an order UUID, we came from confirmation screen (Quick Deploy flow)
        # Otherwise, we came from customize flow (plan selection)
        if context.user_data.get('rdp_order_uuid'):
            keyboard.append([InlineKeyboardButton(back_text, callback_data="rdp_back_to_confirmation")])
        else:
            keyboard.append([InlineKeyboardButton(back_text, callback_data="rdp_customize_start")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in smart region selection: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.regions_error', user.id))

async def handle_rdp_regions_all(query, context):
    """Show all available regions for selection"""
    try:
        user = query.from_user
        logger.info(f"🌐 Showing all regions to user {user.id}")
        
        # All available regions
        all_regions = [
            ('ewr', '🌎', 'New Jersey, USA'),
            ('ord', '🌎', 'Chicago, USA'),
            ('dfw', '🌎', 'Dallas, USA'),
            ('sea', '🌎', 'Seattle, USA'),
            ('lax', '🌎', 'Los Angeles, USA'),
            ('atl', '🌎', 'Atlanta, USA'),
            ('mia', '🌎', 'Miami, USA'),
            ('lhr', '🌍', 'London, UK'),
            ('fra', '🌍', 'Frankfurt, Germany'),
            ('ams', '🌍', 'Amsterdam, Netherlands'),
            ('cdg', '🌍', 'Paris, France'),
            ('mad', '🌍', 'Madrid, Spain'),
            ('waw', '🌍', 'Warsaw, Poland'),
            ('sto', '🌍', 'Stockholm, Sweden'),
            ('nrt', '🌏', 'Tokyo, Japan'),
            ('sgp', '🌏', 'Singapore'),
            ('icn', '🌏', 'Seoul, South Korea'),
            ('syd', '🌏', 'Sydney, Australia'),
            ('mel', '🌏', 'Melbourne, Australia'),
            ('bom', '🌏', 'Mumbai, India'),
            ('del', '🌏', 'Delhi, India'),
            ('sao', '🌎', 'São Paulo, Brazil'),
        ]
        
        title = await t_for_user('rdp.region.all_regions_title', user.id)
        prompt = await t_for_user('rdp.region.all_regions_prompt', user.id)
        back_text = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
<b>{title}</b>

{prompt}
"""
        
        keyboard = []
        for region_code, emoji, name in all_regions:
            keyboard.append([InlineKeyboardButton(f"{emoji} {name}", callback_data=f"rdp_set_region_{region_code}")])
        
        keyboard.append([InlineKeyboardButton(back_text, callback_data="rdp_region_smart")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing all regions: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.regions_error', user.id))

async def handle_rdp_billing_confirm(query, context, billing_cycle: str):
    """Handle billing cycle selection from confirmation screen and return to confirmation"""
    try:
        user = query.from_user
        
        # Update billing cycle in wizard
        if not context.user_data.get('rdp_wizard'):
            context.user_data['rdp_wizard'] = {}
        context.user_data['rdp_wizard']['billing_cycle'] = billing_cycle
        
        logger.info(f"📅 Billing cycle updated to: {billing_cycle}")
        
        # Return to the appropriate confirmation screen based on source
        wizard = context.user_data.get('rdp_wizard', {})
        confirmation_source = wizard.get('confirmation_source', 'customize')
        
        if confirmation_source == 'quick_deploy':
            await handle_rdp_quick_deploy(query, context)
        else:
            await handle_rdp_compact_confirmation(query, context)
        
    except Exception as e:
        logger.error(f"Error confirming billing: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.billing_error', user.id))

async def handle_rdp_change_billing(query, context, region_code: str):
    """Show billing cycle options from confirmation screen"""
    try:
        user = query.from_user
        
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, await t_for_user('rdp.billing.loading', user.id))
        
        wizard = context.user_data.get('rdp_wizard', {})
        plan_id = wizard.get('plan_id')
        
        if not plan_id:
            logger.error(f"❌ No plan_id in wizard data")
            await safe_edit_message(query, await t_for_user('rdp.errors.config_incomplete', user.id))
            return
        
        # Get plan details with markup pricing
        plan = await execute_query("""
            SELECT plan_name, our_monthly_price
            FROM rdp_plans
            WHERE id = %s
        """, (plan_id,))
        
        if not plan or len(plan) == 0:
            await safe_edit_message(query, await t_for_user('rdp.errors.plan_not_found', user.id))
            return
        
        plan = plan[0]
        monthly_price = float(plan['our_monthly_price'])
        
        # Calculate total prices with discounts
        monthly_total = monthly_price
        quarterly_total = monthly_price * 3 * 0.94  # 6% discount
        yearly_total = monthly_price * 12 * 0.89  # 11% discount
        
        # Calculate per-month prices
        quarterly_per_month = quarterly_total / 3
        yearly_per_month = yearly_total / 12
        
        title = await t_for_user('rdp.billing.title', user.id)
        prompt = await t_for_user('rdp.billing.prompt', user.id)
        monthly_btn = await t_for_user('rdp.billing.monthly', user.id)
        quarterly_btn = await t_for_user('rdp.billing.quarterly_save', user.id)
        yearly_btn = await t_for_user('rdp.billing.yearly_save', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
📅 <b>{title}</b>

<b>{plan['plan_name']}</b>

{prompt}
"""
        
        keyboard = [
            [InlineKeyboardButton(monthly_btn.format(total=f"{monthly_total:.2f}", permonth=f"{monthly_price:.2f}"), callback_data="rdp_billing_monthly_confirm")],
            [InlineKeyboardButton(quarterly_btn.format(total=f"{quarterly_total:.2f}", permonth=f"{quarterly_per_month:.2f}", percent="6"), callback_data="rdp_billing_quarterly_confirm")],
            [InlineKeyboardButton(yearly_btn.format(total=f"{yearly_total:.2f}", permonth=f"{yearly_per_month:.2f}", percent="11"), callback_data="rdp_billing_yearly_confirm")],
            [InlineKeyboardButton(back_btn, callback_data="rdp_back_to_confirmation")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in change billing: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.billing_error', user.id))

async def handle_rdp_set_region(query, context, region_code: str):
    """Set region and proceed to compact confirmation"""
    try:
        user = query.from_user
        
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, await t_for_user('rdp.confirmation.preparing', user.id))
        
        if not context.user_data.get('rdp_wizard'):
            context.user_data['rdp_wizard'] = {}
        context.user_data['rdp_wizard']['region'] = region_code
        context.user_data['rdp_wizard']['billing_cycle'] = 'monthly'
        context.user_data['rdp_wizard']['confirmation_source'] = 'customize'
        
        logger.info(f"📍 Region {region_code} selected")
        
        # Show compact confirmation
        await handle_rdp_compact_confirmation(query, context)
        
    except Exception as e:
        logger.error(f"Error setting region: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.regions_error', user.id))

async def handle_rdp_compact_confirmation(query, context):
    """Phase 1: Compact confirmation before payment"""
    try:
        user = query.from_user
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        wizard = context.user_data.get('rdp_wizard', {})
        template_id = wizard.get('template_id')
        plan_id = wizard.get('plan_id')
        region = wizard.get('region')
        billing_cycle = wizard.get('billing_cycle', 'monthly')
        
        if not all([template_id, plan_id, region]):
            logger.warning(f"❌ Incomplete RDP wizard data: template={template_id}, plan={plan_id}, region={region}")
            await safe_edit_message(query, await t_for_user('rdp.errors.config_incomplete', user.id))
            return
        
        # Get plan and template details with markup pricing
        plan = await execute_query("""
            SELECT plan_name, vcpu_count, ram_mb, storage_gb, our_monthly_price
            FROM rdp_plans
            WHERE id = %s
        """, (plan_id,))
        
        template = await execute_query("""
            SELECT windows_version, edition
            FROM rdp_templates
            WHERE id = %s
        """, (template_id,))
        
        # Check if queries returned data
        if not plan or len(plan) == 0 or not template or len(template) == 0:
            logger.error(f"❌ Failed to load RDP configuration - plan: {bool(plan)}, template: {bool(template)}")
            await safe_edit_message(query, await t_for_user('rdp.errors.plan_not_found', user.id))
            return
        
        plan = plan[0]
        template = template[0]
        monthly_price = float(plan['our_monthly_price'])
        
        # Calculate total price and period based on billing cycle
        if billing_cycle == 'monthly':
            total_price = monthly_price
            period_months = 1
        elif billing_cycle == 'quarterly':
            total_price = monthly_price * 3 * 0.94  # 6% discount
            period_months = 3
        elif billing_cycle == 'yearly':
            total_price = monthly_price * 12 * 0.89  # 11% discount
            period_months = 12
        else:
            total_price = monthly_price
            period_months = 1
        
        # Get region name
        region_names = {
            'ewr': 'New Jersey, USA', 'ord': 'Chicago, USA', 'lhr': 'London, UK',
            'fra': 'Frankfurt, DE', 'nrt': 'Tokyo, JP', 'sgp': 'Singapore',
            'syd': 'Sydney, AU', 'cdg': 'Paris, FR', 'ams': 'Amsterdam, NL',
            'mad': 'Madrid, ES', 'icn': 'Seoul, KR', 'sao': 'São Paulo, BR'
        }
        region_name = region_names.get(region, region.upper())
        
        # Get wallet balance (db_user is internal user_id, not telegram_id)
        wallet_balance = await get_user_wallet_balance_by_id(db_user)
        
        # Create order
        order_uuid = await create_order_with_uuid(
            user_id=db_user,
            order_type='rdp_server',
            total_amount=Decimal(str(total_price)),
            currency='USD',
            metadata={
                'template_id': template_id,
                'plan_id': plan_id,
                'region': region,
                'billing_cycle': billing_cycle,
                'period_months': period_months
            }
        )
        
        context.user_data['rdp_order_uuid'] = order_uuid
        
        # Get localized strings
        title = await t_for_user('rdp.confirmation.title', user.id)
        specs_template = await t_for_user('rdp.confirmation.specs', user.id)
        os_template = await t_for_user('rdp.confirmation.os', user.id)
        price_billing = await t_for_user('rdp.confirmation.price_billing', user.id)
        payment_method = await t_for_user('rdp.confirmation.payment_method', user.id)
        total_template = await t_for_user('rdp.confirmation.total', user.id)
        wallet_balance_template = await t_for_user('rdp.confirmation.wallet_balance', user.id)
        confirm_pay_btn = await t_for_user('rdp.buttons.confirm_pay', user.id)
        edit_btn = await t_for_user('rdp.buttons.edit', user.id)
        cancel_btn = await t_for_user('rdp.buttons.cancel', user.id)
        
        # Format specs and other dynamic content
        specs = specs_template.format(
            cpu=plan['vcpu_count'],
            ram=plan['ram_mb']/1024,
            storage=plan['storage_gb']
        )
        
        os_text = os_template.format(
            version=template['windows_version'],
            edition=template['edition']
        )
        
        price_text = price_billing.format(
            price=f"{monthly_price:.2f}",
            billing=billing_cycle.capitalize()
        )
        
        total_text = total_template.format(price=f"{total_price:.2f}")
        wallet_text = wallet_balance_template.format(balance=f"{float(wallet_balance):.2f}")
        
        message = f"""
<b>{title}</b>

🖥️ <b>{plan['plan_name']}</b>
{specs}

📍 {region_name}
{os_text}

{price_text}
💳 {payment_method}

<b>{total_text}</b>

{wallet_text}
"""
        
        keyboard = []
        
        # Always show "Continue to Payment" button - creates order first, then shows payment selection
        continue_payment_btn = await t_for_user('rdp.buttons.confirm_pay', user.id)
        keyboard.append([InlineKeyboardButton(continue_payment_btn, callback_data="rdp_confirm_and_create_order")])
        
        # Add billing cycle button (shows if quarterly/yearly available)
        change_billing_btn = await t_for_user('rdp.buttons.change_billing', user.id)
        keyboard.append([InlineKeyboardButton(change_billing_btn, callback_data=f"rdp_change_billing_{region}")])
        
        keyboard.append([
            InlineKeyboardButton(edit_btn, callback_data="rdp_customize_start"),
            InlineKeyboardButton(cancel_btn, callback_data="rdp_purchase_start")
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in compact confirmation: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.confirmation_error', user.id))

async def handle_rdp_quick_confirm(query, context):
    """Quick Deploy - instant deployment without confirmation screen"""
    try:
        user = query.from_user
        logger.info(f"⚡ Quick Deploy - instant deployment for user {user.id}")
        
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        wizard = context.user_data.get('rdp_wizard', {})
        template_id = wizard.get('template_id')
        plan_id = wizard.get('plan_id')
        region = wizard.get('region')
        billing_cycle = wizard.get('billing_cycle', 'monthly')
        
        if not all([template_id, plan_id, region]):
            logger.warning(f"❌ Incomplete RDP wizard data")
            await safe_edit_message(query, await t_for_user('rdp.errors.config_incomplete', user.id))
            return
        
        # Get plan details with markup pricing
        plan = await execute_query("""
            SELECT plan_name, our_monthly_price
            FROM rdp_plans
            WHERE id = %s
        """, (plan_id,))
        
        if not plan or len(plan) == 0:
            logger.error(f"❌ Plan not found")
            await safe_edit_message(query, await t_for_user('rdp.errors.plan_not_found', user.id))
            return
        
        plan = plan[0]
        monthly_price = Decimal(str(plan['our_monthly_price']))
        
        # Calculate total price and period based on billing cycle
        if billing_cycle == 'monthly':
            total_price = monthly_price
            period_months = 1
        elif billing_cycle == 'quarterly':
            total_price = monthly_price * 3 * Decimal('0.94')  # 6% discount
            period_months = 3
        elif billing_cycle == 'yearly':
            total_price = monthly_price * 12 * Decimal('0.89')  # 11% discount
            period_months = 12
        else:
            total_price = monthly_price
            period_months = 1
        
        # Check wallet balance
        wallet_balance = await get_user_wallet_balance_by_id(db_user)
        
        # If insufficient balance, show error
        if wallet_balance < total_price:
            shortfall = total_price - wallet_balance
            
            # Get localized strings for insufficient balance error
            title = await t_for_user('rdp.payment.insufficient_title', user.id)
            required = await t_for_user('rdp.payment.required', user.id)
            your_balance = await t_for_user('rdp.payment.your_balance', user.id)
            shortfall_text = await t_for_user('rdp.payment.shortfall', user.id)
            add_funds_text = await t_for_user('rdp.payment.add_funds', user.id)
            
            message = f"""
❌ <b>{title}</b>

{required.format(amount=f"{float(total_price):.2f}")}
{your_balance.format(balance=f"{float(wallet_balance):.2f}")}
{shortfall_text.format(amount=f"{float(shortfall):.2f}")}

{add_funds_text}
"""
            await safe_edit_message(query, message, parse_mode='HTML')
            return
        
        # Create order
        order_uuid = await create_order_with_uuid(
            user_id=db_user,
            order_type='rdp_server',
            total_amount=total_price,
            currency='USD',
            metadata={
                'template_id': template_id,
                'plan_id': plan_id,
                'region': region,
                'billing_cycle': billing_cycle,
                'period_months': period_months
            }
        )
        
        # Get order ID
        order = await execute_query("""
            SELECT id, metadata
            FROM orders
            WHERE uuid_id = %s
        """, (order_uuid,))
        
        if not order:
            await safe_edit_message(query, await t_for_user('rdp.errors.deployment_error', user.id))
            return
        
        order = order[0]
        
        # Debit wallet
        debit_success = await debit_wallet_balance(
            db_user,
            total_price,
            description=f"Windows RDP Server purchase ({billing_cycle})"
        )
        
        if not debit_success:
            await safe_edit_message(query, await t_for_user('rdp.errors.payment_error', user.id))
            return
        
        # Update order status
        await execute_update("""
            UPDATE orders
            SET status = 'completed', completed_at = NOW()
            WHERE id = %s
        """, (order['id'],))
        
        logger.info(f"💰 Payment processed: ${float(total_price):.2f} ({billing_cycle}, {period_months} months) from user {db_user}")
        
        # Show provisioning message
        provision_title = await t_for_user('rdp.provision.title', user.id)
        provision_msg = await t_for_user('rdp.provision.message', user.id)
        
        await safe_edit_message(query, f"""
⏳ <b>{provision_title}</b>

{provision_msg}
""", parse_mode='HTML')
        
        # Provision server asynchronously
        asyncio.create_task(provision_rdp_server(user.id, order['id'], order['metadata']))
        
    except Exception as e:
        logger.error(f"Error in Quick Deploy: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.deployment_error', user.id))

async def handle_rdp_template_selection(query, context, template_id: str):
    """Handle Windows template selection and show plans"""
    try:
        user = query.from_user
        
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, await t_for_user('rdp.purchase.loading_plans', user.id))
        
        # Store selected template in context
        if not context.user_data:
            context.user_data = {}
        context.user_data['rdp_template_id'] = int(template_id)
        
        # Get template details
        template = await execute_query("""
            SELECT windows_version, edition, display_name
            FROM rdp_templates
            WHERE id = %s
        """, (int(template_id),))
        
        if not template:
            await safe_edit_message(query, await t_for_user('rdp.errors.template_not_found', user.id))
            return
        
        template = template[0]
        
        # Get available plans
        plans = await execute_query("""
            SELECT id, plan_name, vcpu_count, ram_mb, storage_gb, bandwidth_tb, our_monthly_price
            FROM rdp_plans
            WHERE is_active = true
            ORDER BY our_monthly_price ASC
        """)
        
        if not plans:
            await safe_edit_message(query, await t_for_user('rdp.errors.no_plans', user.id))
            return
        
        title = await t_for_user('rdp.purchase.select_plan_title', user.id)
        windows_label = await t_for_user('rdp.purchase.windows_server', user.id)
        prompt = await t_for_user('rdp.purchase.choose_plan', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
💻 <b>{title}</b>

<b>{windows_label}:</b> {template['windows_version']} {template['edition']}

{prompt}
"""
        
        keyboard = []
        for plan in plans:
            vcpu = plan['vcpu_count']
            ram_gb = plan['ram_mb'] / 1024
            storage = plan['storage_gb']
            price = float(plan['our_monthly_price'])
            
            button_text = f"{plan['plan_name']} - ${price}/mo ({vcpu}c/{ram_gb:.0f}GB RAM/{storage}GB)"
            keyboard.append([InlineKeyboardButton(button_text, callback_data=f"rdp_plan_{plan['id']}")])
        
        keyboard.append([InlineKeyboardButton(back_btn, callback_data="rdp_purchase_start")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in RDP template selection: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.plans_error', user.id))

async def handle_rdp_plan_selection(query, context, plan_id: str):
    """Handle plan selection and show regions"""
    try:
        user = query.from_user
        
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, await t_for_user('rdp.region.loading', user.id))
        
        # Store selected plan
        if not context.user_data:
            context.user_data = {}
        context.user_data['rdp_plan_id'] = int(plan_id)
        
        # Get plan details
        plan = await execute_query("""
            SELECT plan_name, vcpu_count, ram_mb, storage_gb, our_monthly_price
            FROM rdp_plans
            WHERE id = %s
        """, (int(plan_id),))
        
        if not plan:
            await safe_edit_message(query, await t_for_user('rdp.errors.plan_not_found', user.id))
            return
        
        plan = plan[0]
        
        # Get regions from Vultr API
        regions = vultr_service.get_regions()
        
        if not regions:
            await safe_edit_message(query, await t_for_user('rdp.errors.regions_error', user.id))
            return
        
        # Store regions in context for later use
        context.user_data['rdp_regions'] = regions
        
        title = await t_for_user('rdp.region.datacenter_title', user.id)
        plan_label = await t_for_user('rdp.region.plan_label', user.id)
        prompt = await t_for_user('rdp.region.choose_datacenter', user.id)
        more_regions_btn = await t_for_user('rdp.region.more_regions', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
🌍 <b>{title}</b>

<b>{plan_label}:</b> {plan['plan_name']} - ${float(plan['our_monthly_price'])}/mo

{prompt}
"""
        
        keyboard = []
        # Group regions by continent for better UX
        na_regions = [r for r in regions if r.get('continent') == 'North America']
        eu_regions = [r for r in regions if r.get('continent') == 'Europe']
        asia_regions = [r for r in regions if r.get('continent') == 'Asia']
        others = [r for r in regions if r.get('continent') not in ['North America', 'Europe', 'Asia']]
        
        # Add North America regions
        if na_regions:
            for region in na_regions[:6]:  # Limit to top 6
                city = region.get('city', 'Unknown')
                country = region.get('country', '')
                region_id = region.get('id', '')
                keyboard.append([InlineKeyboardButton(f"🇺🇸 {city}, {country}", callback_data=f"rdp_region_{region_id}")])
        
        # Add Europe regions
        if eu_regions:
            for region in eu_regions[:6]:
                city = region.get('city', 'Unknown')
                country = region.get('country', '')
                region_id = region.get('id', '')
                keyboard.append([InlineKeyboardButton(f"🇪🇺 {city}, {country}", callback_data=f"rdp_region_{region_id}")])
        
        # Add "More Regions" button if there are many
        if len(regions) > 12:
            keyboard.append([InlineKeyboardButton(more_regions_btn, callback_data="rdp_regions_all")])
        
        keyboard.append([InlineKeyboardButton(back_btn, callback_data=f"rdp_template_{context.user_data.get('rdp_template_id')}")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in RDP plan selection: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.regions_error', user.id))

async def handle_rdp_region_selection(query, context, region_id: str):
    """Handle region selection and show billing cycles"""
    try:
        user = query.from_user
        
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, await t_for_user('rdp.billing.loading', user.id))
        
        # Store selected region
        if not context.user_data:
            context.user_data = {}
        context.user_data['rdp_region'] = region_id
        
        # Get plan details for pricing
        plan_id = context.user_data.get('rdp_plan_id')
        plan = await execute_query("""
            SELECT plan_name, our_monthly_price
            FROM rdp_plans
            WHERE id = %s
        """, (plan_id,))
        
        if not plan:
            await safe_edit_message(query, await t_for_user('rdp.errors.plan_not_found', user.id))
            return
        
        plan = plan[0]
        monthly_price = float(plan['our_monthly_price'])
        
        # Calculate discounted prices
        quarterly_price = monthly_price * 3 * 0.94  # 6% discount
        yearly_price = monthly_price * 12 * 0.89  # 11% discount
        
        title = await t_for_user('rdp.billing.title', user.id)
        plan_label = await t_for_user('rdp.billing.plan_label', user.id)
        region_label = await t_for_user('rdp.billing.region_label', user.id)
        prompt = await t_for_user('rdp.billing.prompt', user.id)
        monthly_btn = await t_for_user('rdp.billing.monthly', user.id)
        quarterly_btn = await t_for_user('rdp.billing.quarterly', user.id)
        yearly_btn = await t_for_user('rdp.billing.yearly', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
📅 <b>{title}</b>

<b>{plan_label}:</b> {plan['plan_name']}
<b>{region_label}:</b> {region_id}

{prompt}
"""
        
        keyboard = [
            [InlineKeyboardButton(monthly_btn.format(price=f"{monthly_price:.2f}"), callback_data="rdp_billing_monthly")],
            [InlineKeyboardButton(quarterly_btn.format(price=f"{quarterly_price/3:.2f}"), callback_data="rdp_billing_quarterly")],
            [InlineKeyboardButton(yearly_btn.format(price=f"{yearly_price/12:.2f}"), callback_data="rdp_billing_yearly")],
            [InlineKeyboardButton(back_btn, callback_data=f"rdp_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in RDP region selection: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.billing_error', user.id))

async def handle_rdp_billing_selection(query, context, billing_cycle: str):
    """Handle billing cycle selection and show payment options"""
    try:
        user = query.from_user
        
        # ⚡ INSTANT FEEDBACK: Show immediate response
        await safe_edit_message(query, await t_for_user('rdp.payment.preparing', user.id))
        
        # Store billing cycle
        if not context.user_data:
            context.user_data = {}
        context.user_data['rdp_billing_cycle'] = billing_cycle
        
        # Get all stored data
        template_id = context.user_data.get('rdp_template_id')
        plan_id = context.user_data.get('rdp_plan_id')
        region = context.user_data.get('rdp_region')
        
        # Get plan and template details
        plan = await execute_query("""
            SELECT plan_name, our_monthly_price, vultr_plan_id
            FROM rdp_plans
            WHERE id = %s
        """, (plan_id,))
        
        template = await execute_query("""
            SELECT windows_version, edition, vultr_os_id
            FROM rdp_templates
            WHERE id = %s
        """, (template_id,))
        
        # Check if queries returned data
        if not plan or len(plan) == 0 or not template or len(template) == 0:
            logger.error(f"❌ Failed to load RDP billing configuration - plan: {bool(plan)}, template: {bool(template)}")
            await safe_edit_message(query, await t_for_user('rdp.errors.config_incomplete', user.id))
            return
        
        plan = plan[0]
        template = template[0]
        monthly_price = float(plan['our_monthly_price'])
        
        # Calculate total based on billing cycle
        if billing_cycle == 'monthly':
            total_price = monthly_price
            period_months = 1
        elif billing_cycle == 'quarterly':
            total_price = monthly_price * 3 * 0.94
            period_months = 3
        elif billing_cycle == 'yearly':
            total_price = monthly_price * 12 * 0.89
            period_months = 12
        else:
            total_price = monthly_price
            period_months = 1
        
        # Get user wallet balance
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        # Get wallet balance (db_user is internal user_id, not telegram_id)
        wallet_balance = await get_user_wallet_balance_by_id(db_user)
        
        # Create order (db_user is already the integer user_id)
        order_uuid = await create_order_with_uuid(
            user_id=db_user,
            order_type='rdp_server',
            total_amount=Decimal(str(total_price)),
            currency='USD',
            metadata={
                'template_id': template_id,
                'plan_id': plan_id,
                'region': region,
                'billing_cycle': billing_cycle,
                'period_months': period_months
            }
        )
        
        # Store order UUID in context
        context.user_data['rdp_order_uuid'] = order_uuid
        
        # Get localized strings
        title = await t_for_user('rdp.payment.method_title', user.id)
        windows_server = await t_for_user('rdp.payment.windows_server', user.id)
        plan_label = await t_for_user('rdp.payment.plan_label', user.id)
        region_label = await t_for_user('rdp.payment.region_label', user.id)
        billing_label = await t_for_user('rdp.payment.billing_label', user.id)
        total_label = await t_for_user('rdp.payment.total_label', user.id)
        wallet_balance_label = await t_for_user('rdp.payment.wallet_balance_label', user.id)
        choose_method = await t_for_user('rdp.payment.choose_method', user.id)
        wallet_button = await t_for_user('rdp.payment.wallet_button', user.id)
        wallet_insufficient = await t_for_user('rdp.payment.wallet_insufficient', user.id)
        crypto_button = await t_for_user('rdp.payment.crypto_button', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
💳 <b>{title}</b>

<b>{windows_server.format(version=template['windows_version'], edition=template['edition'])}</b>
<b>{plan_label}:</b> {plan['plan_name']}
<b>{region_label}:</b> {region}
<b>{billing_label}:</b> {billing_cycle.capitalize()}

<b>{total_label}:</b> ${total_price:.2f}
<b>{wallet_balance_label}:</b> ${float(wallet_balance):.2f}

{choose_method}
"""
        
        keyboard = []
        
        # Wallet payment if sufficient balance
        if wallet_balance >= Decimal(str(total_price)):
            keyboard.append([InlineKeyboardButton(wallet_button.format(price=f"{total_price:.2f}"), callback_data=f"rdp_pay_wallet")])
        else:
            shortfall = Decimal(str(total_price)) - wallet_balance
            keyboard.append([InlineKeyboardButton(wallet_insufficient.format(shortfall=f"{float(shortfall):.2f}"), callback_data="rdp_wallet_insufficient")])
        
        # Crypto payment
        keyboard.append([InlineKeyboardButton(crypto_button, callback_data="rdp_pay_crypto")])
        
        keyboard.append([InlineKeyboardButton(back_btn, callback_data=f"rdp_region_{region}")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in RDP billing selection: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.billing_error', user.id))

async def handle_rdp_confirm_and_create_order(query, context):
    """Create RDP order before showing payment method selection"""
    try:
        user = query.from_user
        user_lang = await resolve_user_language(user.id, user.language_code if hasattr(user, 'language_code') else None)
        
        # Show loading message
        await safe_edit_message(query, await t_for_user('rdp.payment.creating_order', user.id))
        
        # Get user ID
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        # Get wizard data
        wizard = context.user_data.get('rdp_wizard', {})
        template_id = wizard.get('template_id')
        plan_id = wizard.get('plan_id')
        region = wizard.get('region')
        billing_cycle = wizard.get('billing_cycle', 'monthly')
        
        if not all([template_id, plan_id, region]):
            logger.warning(f"❌ Incomplete RDP wizard data: template={template_id}, plan={plan_id}, region={region}")
            await safe_edit_message(query, await t_for_user('rdp.errors.config_incomplete', user.id))
            return
        
        # Get plan details to calculate total with markup pricing
        plan = await execute_query("""
            SELECT our_monthly_price FROM rdp_plans WHERE id = %s
        """, (plan_id,))
        
        if not plan or len(plan) == 0:
            await safe_edit_message(query, await t_for_user('rdp.errors.plan_not_found', user.id))
            return
        
        monthly_price = float(plan[0]['our_monthly_price'])
        
        # Calculate total price based on billing cycle
        if billing_cycle == 'monthly':
            total_price = monthly_price
            period_months = 1
        elif billing_cycle == 'quarterly':
            total_price = monthly_price * 3 * 0.94  # 6% discount
            period_months = 3
        elif billing_cycle == 'yearly':
            total_price = monthly_price * 12 * 0.89  # 11% discount
            period_months = 12
        else:
            total_price = monthly_price
            period_months = 1
        
        # Create the RDP order
        from database import create_order_with_uuid
        order_uuid = await create_order_with_uuid(
            user_id=db_user,
            order_type='rdp',
            total_amount=str(total_price),
            currency='USD',
            metadata={
                'template_id': template_id,
                'plan_id': plan_id,
                'region': region,
                'billing_cycle': billing_cycle,
                'period_months': period_months
            }
        )
        
        if not order_uuid:
            logger.error(f"❌ Failed to create RDP order for user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.order_creation_failed', user.id))
            return
        
        # Store order UUID in context
        context.user_data['rdp_order_uuid'] = order_uuid
        logger.info(f"✅ Created RDP order {order_uuid} for user {user.id}, total: ${total_price:.2f}")
        
        # Now show payment method selection
        await handle_rdp_select_payment_method(query, context)
        
    except Exception as e:
        logger.error(f"Error creating RDP order: {e}")
        import traceback
        traceback.print_exc()
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.order_creation_failed', user.id))

async def handle_rdp_select_payment_method(query, context):
    """Show payment method selection (Wallet vs Crypto)"""
    try:
        user = query.from_user
        
        # Get order from context
        order_uuid = context.user_data.get('rdp_order_uuid')
        if not order_uuid:
            await safe_edit_message(query, await t_for_user('rdp.errors.order_not_found', user.id))
            return
        
        # Get order details
        order = await get_order_by_uuid(order_uuid)
        if not order:
            await safe_edit_message(query, await t_for_user('rdp.errors.order_not_found', user.id))
            return
        
        total_amount = float(order['total_amount'])
        
        # Get user wallet balance
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        if db_user is None:
            await safe_edit_message(query, await t_for_user('rdp.errors.user_not_found', user.id))
            return
        wallet_balance = await get_user_wallet_balance_by_id(db_user)
        
        # Get localized strings
        title = await t_for_user('rdp.payment.method_title', user.id)
        choose_method = await t_for_user('rdp.payment.choose_method', user.id)
        total_label = await t_for_user('rdp.payment.total_label', user.id)
        wallet_balance_label = await t_for_user('rdp.payment.wallet_balance_label', user.id)
        wallet_btn = await t_for_user('rdp.payment.wallet_button', user.id)
        wallet_insufficient_btn = await t_for_user('rdp.payment.wallet_insufficient', user.id)
        crypto_btn = await t_for_user('rdp.payment.crypto_button', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        # Get plan details for display
        metadata = order['metadata']
        plan_id = metadata.get('plan_id')
        billing_cycle = metadata.get('billing_cycle', 'monthly')
        
        plan = await execute_query("""
            SELECT plan_name FROM rdp_plans WHERE id = %s
        """, (plan_id,))
        
        plan_name = plan[0]['plan_name'] if plan else "RDP Server"
        
        message = f"""
💳 <b>{title}</b>

🖥️ <b>{plan_name}</b>
📅 {billing_cycle.capitalize()} billing

<b>{total_label}</b> ${total_amount:.2f}
<b>{wallet_balance_label}</b> ${float(wallet_balance):.2f}

{choose_method}
"""
        
        keyboard = []
        
        # Show wallet payment button or insufficient balance message
        if wallet_balance >= Decimal(str(total_amount)):
            keyboard.append([InlineKeyboardButton(wallet_btn, callback_data="rdp_pay_wallet")])
        else:
            shortfall = Decimal(str(total_amount)) - wallet_balance
            keyboard.append([InlineKeyboardButton(wallet_insufficient_btn.format(shortfall=f"{float(shortfall):.2f}"), callback_data="rdp_wallet_topup")])
        
        # Crypto payment always available
        keyboard.append([InlineKeyboardButton(crypto_btn, callback_data="rdp_pay_crypto")])
        keyboard.append([InlineKeyboardButton(back_btn, callback_data="rdp_back_to_confirmation")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in payment method selection: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.payment_error', user.id))

async def handle_rdp_pay_crypto(query, context):
    """Show cryptocurrency selection for RDP payment - unified with domain/hosting"""
    try:
        user = query.from_user
        
        # Get order from context
        order_uuid = context.user_data.get('rdp_order_uuid')
        if not order_uuid:
            await safe_edit_message(query, await t_for_user('rdp.errors.order_not_found', user.id))
            return
        
        # Get order details
        order = await get_order_by_uuid(order_uuid)
        if not order:
            await safe_edit_message(query, await t_for_user('rdp.errors.order_not_found', user.id))
            return
        
        total_amount = float(order['total_amount'])
        
        # Get localized strings
        title = await t_for_user('rdp.payment.crypto_title', user.id)
        select_currency = await t_for_user('rdp.payment.select_currency', user.id)
        total_label = await t_for_user('rdp.payment.total_label', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
{title}

<b>{total_label}</b> ${total_amount:.2f}

{select_currency}
"""
        
        # Use unified crypto_config for all supported currencies
        from crypto_config import crypto_config
        
        keyboard = []
        for currency in crypto_config.get_supported_currencies():
            label = f"{currency['icon']} {currency['name']}"
            callback_data = f"rdp_crypto_{currency['code']}"
            keyboard.append([InlineKeyboardButton(label, callback_data=callback_data)])
        
        # Add back button
        keyboard.append([InlineKeyboardButton(back_btn, callback_data="rdp_select_payment_method")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing crypto currencies: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.payment_error', user.id))

async def handle_rdp_crypto_currency(query, context, currency: str):
    """Generate crypto payment address - unified with domain/hosting infrastructure"""
    try:
        user = query.from_user
        
        # Show preparing message
        await safe_edit_message(query, await t_for_user('rdp.payment.crypto_preparing', user.id))
        
        # Get order from context
        order_uuid = context.user_data.get('rdp_order_uuid')
        if not order_uuid:
            await safe_edit_message(query, await t_for_user('rdp.errors.order_not_found', user.id))
            return
        
        # Get order details
        order = await get_order_by_uuid(order_uuid)
        if not order:
            await safe_edit_message(query, await t_for_user('rdp.errors.order_not_found', user.id))
            return
        
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        if db_user is None:
            await safe_edit_message(query, await t_for_user('rdp.errors.user_not_found', user.id))
            return
        total_amount = float(order['total_amount'])
        
        # CRITICAL FIX: Cancel any existing payment intents for this order before creating a new one
        # This allows users to change payment methods without unique constraint violations
        await execute_update("""
            UPDATE payment_intents
            SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
            WHERE order_id = %s AND user_id = %s AND status IN ('pending', 'creating_address', 'address_created')
        """, (order_uuid, db_user))
        
        logger.info(f"✅ Cancelled any existing payment intents for order {order_uuid} to allow payment method change")
        
        # Use unified payment infrastructure with fallback
        from services.payment_provider import create_payment_address
        from crypto_config import crypto_config
        
        # Get currency display name
        currency_info = crypto_config.get_currency_by_code(currency)
        crypto_name = currency_info.get('name', currency.upper())
        
        # Skip $2 padding for USDT (stablecoin, no volatility)
        original_amount = Decimal(str(total_amount))
        is_stablecoin = currency.lower() in ('usdt', 'usdt_trc20', 'usdt_erc20')
        gateway_amount = original_amount if is_stablecoin else original_amount + Decimal('2')
        
        # Create payment address using unified infrastructure
        payment_result = await create_payment_address(
            currency=currency,
            order_id=order_uuid,
            value=gateway_amount,
            user_id=db_user
        )
        
        if not payment_result or not payment_result.get('address'):
            logger.error(f"Failed to create payment address for RDP order {order_uuid}")
            await safe_edit_message(query, await t_for_user('rdp.payment.crypto_error', user.id))
            return
        
        payment_address = payment_result['address']
        crypto_amount = payment_result.get('crypto_amount')
        
        # Use unified render_crypto_payment for consistent UI (matching domain pattern)
        from message_utils import render_crypto_payment
        
        # Calculate expiration based on currency (from crypto timeout config)
        expires_minutes = 45  # Default for Ethereum
        if currency == 'btc':
            expires_minutes = 60
        elif currency in ['usdt_trc20', 'usdt_erc20', 'ltc', 'doge']:
            expires_minutes = 30
        
        # Render base payment UI using unified infrastructure with RDP context
        payment_message, copy_keyboard = render_crypto_payment(
            address=payment_address,
            crypto_name=crypto_name,
            usd_amount=total_amount,
            crypto_amount=crypto_amount,
            order_id=order_uuid,
            expires_minutes=expires_minutes,
            payment_context='rdp'
        )
        
        # Add RDP-specific context (matching domain payment pattern)
        metadata = order['metadata']
        plan_id = metadata.get('plan_id')
        billing_cycle = metadata.get('billing_cycle', 'monthly')
        
        # Get plan name
        plan = await execute_query("SELECT plan_name FROM rdp_plans WHERE id = %s", (plan_id,))
        plan_name = plan[0]['plan_name'] if plan else "Windows RDP Server"
        
        # Format billing info
        if billing_cycle == 'monthly':
            billing_display = "Monthly"
        elif billing_cycle == 'quarterly':
            billing_display = "Quarterly (3 months)"
        elif billing_cycle == 'yearly':
            billing_display = "Yearly (12 months)"
        else:
            billing_display = billing_cycle.capitalize()
        
        # Add RDP server info and auto-provision message
        rdp_info = f"\n🖥️ <b>RDP Server:</b> {plan_name}\n📅 <b>Billing:</b> {billing_display}\n\n✅ Server will be provisioned automatically once payment is received!"
        payment_message += rdp_info
        
        # Add additional action buttons (matching domain payment pattern)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        change_btn = await t_for_user('rdp.payment.change_payment', user.id)
        cancel_btn = await t_for_user('rdp.buttons.cancel', user.id)
        
        additional_buttons = [
            [InlineKeyboardButton(change_btn, callback_data="rdp_pay_crypto")],
            [InlineKeyboardButton(cancel_btn, callback_data=f"rdp_cancel_order:{order_uuid}")],
            [InlineKeyboardButton(back_btn, callback_data="rdp_main")]
        ]
        
        # Combine QR button with action buttons (matching domain payment pattern)
        combined_keyboard = list(copy_keyboard.inline_keyboard) + additional_buttons
        final_keyboard = InlineKeyboardMarkup(combined_keyboard)
        
        await safe_edit_message(query, payment_message, reply_markup=final_keyboard, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error generating crypto payment for RDP: {e}")
        import traceback
        traceback.print_exc()
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.payment.crypto_error', user.id))

async def handle_rdp_crypto_from_qr(query, context, order_uuid: str):
    """Handle navigation from RDP QR code photo to crypto selection (matching wallet deposit pattern)"""
    user = query.from_user
    
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Store order UUID in context for crypto selection
        context.user_data['rdp_order_uuid'] = order_uuid
        
        # Get order details
        order = await get_order_by_uuid(order_uuid)
        if not order:
            await context.bot.send_message(
                chat_id=user.id,
                text=await t_for_user('rdp.errors.order_not_found', user.id)
            )
            return
        
        total_amount = float(order['total_amount'])
        
        # Get localized strings
        title = await t_for_user('rdp.payment.crypto_title', user.id)
        select_currency = await t_for_user('rdp.payment.select_currency', user.id)
        total_label = await t_for_user('rdp.payment.total_label', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
{title}

<b>{total_label}</b> ${total_amount:.2f}

{select_currency}
"""
        
        # Use unified crypto_config for all supported currencies (6 cryptos)
        from crypto_config import crypto_config
        
        keyboard = []
        for currency in crypto_config.get_supported_currencies():
            label = f"{currency['icon']} {currency['name']}"
            callback_data = f"rdp_crypto_{currency['code']}"
            keyboard.append([InlineKeyboardButton(label, callback_data=callback_data)])
        
        # Add back button
        keyboard.append([InlineKeyboardButton(back_btn, callback_data="rdp_select_payment_method")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send new message with crypto selection (since we deleted the QR photo)
        await context.bot.send_message(
            chat_id=user.id,
            text=message,
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        
    except Exception as e:
        logger.error(f"Error handling RDP crypto from QR: {e}")
        import traceback
        traceback.print_exc()
        # Fallback: just send a simple message
        await context.bot.send_message(
            chat_id=user.id,
            text=await t_for_user('rdp.errors.payment_error', user.id)
        )

async def handle_rdp_payment_back(query, context, order_uuid: str):
    """Go back from RDP QR code to crypto currency selection screen"""
    try:
        user = query.from_user
        
        # Delete the QR code photo message
        try:
            await query.message.delete()
        except Exception as e:
            logger.warning(f"Could not delete RDP QR code message: {e}")
        
        # Store order UUID in context for crypto selection
        context.user_data['rdp_order_uuid'] = order_uuid
        
        # Get order details
        order = await get_order_by_uuid(order_uuid)
        if not order:
            await context.bot.send_message(
                chat_id=user.id,
                text=await t_for_user('rdp.errors.order_not_found', user.id)
            )
            return
        
        total_amount = float(order['total_amount'])
        
        # Get localized strings
        title = await t_for_user('rdp.payment.crypto_title', user.id)
        select_currency = await t_for_user('rdp.payment.select_currency', user.id)
        total_label = await t_for_user('rdp.payment.total_label', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
{title}

<b>{total_label}</b> ${total_amount:.2f}

{select_currency}
"""
        
        # Use unified crypto_config for all supported currencies
        from crypto_config import crypto_config
        
        keyboard = []
        for currency in crypto_config.get_supported_currencies():
            label = f"{currency['icon']} {currency['name']}"
            callback_data = f"rdp_crypto_{currency['code']}"
            keyboard.append([InlineKeyboardButton(label, callback_data=callback_data)])
        
        # Add back button
        keyboard.append([InlineKeyboardButton(back_btn, callback_data="rdp_select_payment_method")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send new message with crypto selection (since we deleted the QR photo)
        await context.bot.send_message(
            chat_id=user.id,
            text=message,
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        
    except Exception as e:
        logger.error(f"Error going back from RDP QR: {e}")
        import traceback
        traceback.print_exc()
        user = query.from_user
        await context.bot.send_message(
            chat_id=user.id,
            text=await t_for_user('rdp.errors.payment_error', user.id)
        )

async def handle_rdp_cancel_order(query, context, order_uuid: str):
    """Cancel RDP order"""
    try:
        user = query.from_user
        
        # Cancel the order by updating its status
        await execute_update("""
            UPDATE orders
            SET status = 'cancelled', updated_at = NOW()
            WHERE uuid_id = %s AND status = 'pending'
        """, (order_uuid,))
        
        # Also cancel any associated payment intents
        await execute_update("""
            UPDATE payment_intents
            SET status = 'cancelled'
            WHERE order_id = %s AND status IN ('pending', 'address_created')
        """, (order_uuid,))
        
        logger.info(f"Cancelled RDP order {order_uuid} for user {user.id}")
        
        # Show cancellation message
        cancel_msg = await t_for_user('rdp.payment.order_cancelled', user.id)
        back_btn = await t_for_user('buttons.back_to_menu', user.id)
        
        keyboard = [[InlineKeyboardButton(back_btn, callback_data="rdp_main")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, cancel_msg, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error cancelling RDP order: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.payment_error', user.id))

async def handle_rdp_pay_wallet(query, context):
    """Process wallet payment for RDP server - OPTIMIZED with parallel DB queries"""
    try:
        user = query.from_user
        
        # Get order details
        order_uuid = context.user_data.get('rdp_order_uuid')
        if not order_uuid:
            logger.warning(f"❌ No order UUID found in context for user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.order_not_found', user.id))
            return
        
        # PERFORMANCE OPTIMIZATION: Fetch order and user ID in parallel
        order_task = execute_query("""
            SELECT id, user_id, total_amount, metadata, status
            FROM orders
            WHERE uuid_id = %s
        """, (order_uuid,))
        user_id_task = get_internal_user_id_from_telegram_id(user.id)
        
        order_result, db_user_id = await asyncio.gather(order_task, user_id_task)
        
        # Check if order exists
        if not order_result or len(order_result) == 0:
            logger.error(f"❌ Order not found in database: {order_uuid}")
            await safe_edit_message(query, await t_for_user('rdp.errors.order_not_found', user.id))
            return
        
        order = order_result[0]
        
        if order['status'] != 'pending':
            logger.warning(f"⚠️ Order {order['id']} already processed: {order['status']}")
            await safe_edit_message(query, await t_for_user('rdp.errors.order_processed', user.id))
            return
        
        total_amount = Decimal(str(order['total_amount']))
        
        # Check if user lookup failed
        if not db_user_id:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.payment_error', user.id))
            return
        
        # Get wallet balance (db_user_id is internal user_id, not telegram_id)
        wallet_balance = await get_user_wallet_balance_by_id(db_user_id)
        
        # Verify sufficient balance
        if wallet_balance < total_amount:
            logger.warning(f"❌ Insufficient balance for user {db_user_id}: {wallet_balance} < {total_amount}")
            
            # Get localized strings for insufficient balance error
            title = await t_for_user('rdp.payment.insufficient_title', user.id)
            required = await t_for_user('rdp.payment.required', user.id)
            your_balance = await t_for_user('rdp.payment.your_balance', user.id)
            shortfall_text = await t_for_user('rdp.payment.shortfall', user.id)
            add_funds_text = await t_for_user('rdp.payment.add_funds', user.id)
            
            message = f"""
❌ <b>{title}</b>

{required.format(amount=f"{float(total_amount):.2f}")}
{your_balance.format(balance=f"{float(wallet_balance):.2f}")}
{shortfall_text.format(amount=f"{float(total_amount - wallet_balance):.2f}")}

{add_funds_text}
"""
            await safe_edit_message(query, message, parse_mode='HTML')
            return
        
        # Debit wallet
        debit_success = await debit_wallet_balance(
            db_user_id,
            total_amount,
            description=f"Windows RDP Server purchase"
        )
        
        if not debit_success:
            await safe_edit_message(query, await t_for_user('rdp.errors.payment_error', user.id))
            return
        
        # Update order status
        await execute_update("""
            UPDATE orders
            SET status = 'completed', completed_at = NOW()
            WHERE id = %s
        """, (order['id'],))
        
        # Show provisioning message
        provision_title = await t_for_user('rdp.provision.title', user.id)
        provision_msg = await t_for_user('rdp.provision.message', user.id)
        
        await safe_edit_message(query, f"""
⏳ <b>{provision_title}</b>

{provision_msg}
""", parse_mode='HTML')
        
        # Provision server asynchronously
        asyncio.create_task(provision_rdp_server(user.id, order['id'], order['metadata']))
        
    except Exception as e:
        logger.error(f"Error in RDP wallet payment: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.payment_support_error', user.id))

async def provision_rdp_server(telegram_id: int, order_id: int, metadata: dict):
    """Provision RDP server asynchronously after payment"""
    try:
        logger.info(f"🚀 Starting RDP server provisioning for order {order_id}")
        
        # Get user
        db_user = await get_internal_user_id_from_telegram_id(telegram_id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {telegram_id}")
            error_msg = await t_for_user('rdp.provision.error_user_data', telegram_id)
            await send_provisioning_error(telegram_id, error_msg)
            return
        
        # Extract metadata with defensive fallbacks
        template_id = metadata.get('template_id')
        plan_id = metadata.get('plan_id')
        region = metadata.get('region') or get_rdp_default('region')  # Fallback to default region
        billing_cycle = metadata.get('billing_cycle') or get_rdp_default('billing_cycle')  # Fallback to monthly
        period_months = metadata.get('period_months', 1)
        
        # Validate required parameters
        if not all([template_id, plan_id, region]):
            logger.error(f"❌ Missing required provisioning parameters: template={template_id}, plan={plan_id}, region={region}")
            error_msg = await t_for_user('rdp.provision.error_config', telegram_id)
            await send_provisioning_error(telegram_id, error_msg)
            return
        
        # Get template and plan details
        template = await execute_query("""
            SELECT vultr_os_id, windows_version, edition
            FROM rdp_templates
            WHERE id = %s
        """, (template_id,))
        
        plan = await execute_query("""
            SELECT vultr_plan_id, plan_name, our_monthly_price
            FROM rdp_plans
            WHERE id = %s
        """, (plan_id,))
        
        # Check if queries returned data
        if not template or len(template) == 0 or not plan or len(plan) == 0:
            logger.error(f"❌ Template or plan not found for order {order_id}: template={bool(template)}, plan={bool(plan)}")
            error_msg = await t_for_user('rdp.provision.error_not_found', telegram_id)
            await send_provisioning_error(telegram_id, error_msg)
            return
        
        template = template[0]
        plan = plan[0]
        
        # Generate hostname and label
        hostname = f"rdp-{db_user}-{int(time.time())}"
        label = f"HostBay RDP - User {db_user}"
        
        logger.info(f"📋 Provisioning RDP: region={region}, plan={plan['vultr_plan_id']}, os={template['vultr_os_id']}")
        
        # Validate region before creating instance
        if not region:
            logger.error(f"❌ No region specified for order {order_id}")
            error_msg = await t_for_user('rdp.provision.error_region', telegram_id)
            await send_provisioning_error(telegram_id, error_msg)
            return
        
        # Create Vultr instance
        instance = vultr_service.create_instance(
            region=region,
            plan=plan['vultr_plan_id'],
            os_id=template['vultr_os_id'],
            label=label,
            hostname=hostname
        )
        
        # Check if instance creation succeeded
        if not instance or not instance.get('id'):
            logger.error(f"❌ Failed to create Vultr instance for order {order_id}: {instance}")
            error_msg = await t_for_user('rdp.provision.error_failed_refund', telegram_id)
            await send_provisioning_error(telegram_id, error_msg)
            return
        
        instance_id = instance.get('id')
        
        # Calculate next renewal date using proper calendar months
        from datetime import datetime
        from dateutil.relativedelta import relativedelta
        next_renewal = datetime.now() + relativedelta(months=period_months)
        
        # Insert into rdp_servers table
        await execute_update("""
            INSERT INTO rdp_servers (
                user_id, vultr_instance_id, template_id, plan_id, region, hostname,
                status, monthly_price, billing_cycle, next_renewal_date, auto_renew
            ) VALUES (%s, %s, %s, %s, %s, %s, 'provisioning', %s, %s, %s, true)
        """, (
            db_user, instance_id, template_id, plan_id, region, hostname,
            plan['our_monthly_price'], billing_cycle, next_renewal
        ))
        
        # Get server ID
        server = await execute_query("""
            SELECT id FROM rdp_servers WHERE vultr_instance_id = %s
        """, (instance_id,))
        
        if server and len(server) > 0:
            server_id = server[0]['id']
            
            # Link to rdp_orders
            await execute_update("""
                INSERT INTO rdp_orders (order_id, rdp_server_id, renewal_number)
                VALUES (%s, %s, 0)
            """, (order_id, server_id))
        else:
            logger.warning(f"⚠️ Failed to get server ID for instance {instance_id}")
        
        # Validate instance_id before waiting
        if not instance_id:
            logger.error(f"❌ No instance ID received for order {order_id}")
            error_msg = await t_for_user('rdp.provision.error_failed', telegram_id)
            await send_provisioning_error(telegram_id, error_msg)
            return
        
        # Wait for instance to be ready
        logger.info(f"⏳ Waiting for instance {instance_id} to be ready...")
        instance_ready = await vultr_service.wait_for_instance_ready(instance_id, timeout=600)
        
        if not instance_ready:
            logger.error(f"❌ Instance {instance_id} did not become ready in time")
            # Update status
            await execute_update("""
                UPDATE rdp_servers
                SET status = 'failed'
                WHERE vultr_instance_id = %s
            """, (instance_id,))
            
            # Notify user
            error_msg = await t_for_user('rdp.provision.error_timeout', telegram_id)
            await send_provisioning_error(telegram_id, error_msg)
            return
        
        # Get instance details with credentials
        public_ip = instance_ready.get('main_ip', 'N/A')
        default_password = instance_ready.get('default_password', 'N/A')
        
        # Encrypt password
        encrypted_password = vultr_service.encrypt_password(default_password) if default_password != 'N/A' else None
        
        # Update server with details - set to 'starting' initially
        await execute_update("""
            UPDATE rdp_servers
            SET public_ip = %s,
                admin_password_encrypted = %s,
                power_status = 'starting',
                status = 'active',
                activated_at = NOW()
            WHERE vultr_instance_id = %s
        """, (public_ip, encrypted_password, instance_id))
        
        logger.info(f"✅ RDP server {instance_id} provisioned successfully")
        
        # Send admin success notification
        await send_info_alert(
            "RDPProvisioning",
            f"✅ RDP server provisioned: {plan['plan_name']} for user {telegram_id}",
            "hosting",
            {
                "order_id": order_id,
                "user_telegram_id": telegram_id,
                "instance_id": instance_id,
                "region": region,
                "plan": plan['plan_name'],
                "windows_version": template['windows_version'],
                "public_ip": public_ip
            }
        )
        
        # Launch async auto-start with smart retry (instance_id is validated above)
        if instance_id:
            asyncio.create_task(smart_auto_start_server(instance_id, server_id=None, is_new=True))
        
        # Send credentials to user
        bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        if not bot_token:
            logger.error("❌ TELEGRAM_BOT_TOKEN not set - cannot send credentials to user")
            return
        
        from telegram import Bot
        bot = Bot(token=bot_token)
        
        # Get localized credential strings
        title = await t_for_user('rdp.provision.success_title', telegram_id)
        ip_label = await t_for_user('rdp.provision.ip_label', telegram_id)
        username_label = await t_for_user('rdp.provision.username_label', telegram_id)
        password_label = await t_for_user('rdp.provision.password_label', telegram_id)
        renewal_text = await t_for_user('rdp.provision.next_renewal', telegram_id)
        connect_tip = await t_for_user('rdp.provision.connect_tip', telegram_id)
        save_warning = await t_for_user('rdp.provision.save_warning', telegram_id)
        
        credentials_message = f"""
✅ <b>{title}</b>

<b>{ip_label}:</b> <code>{public_ip}</code>
<b>{username_label}:</b> <code>Administrator</code>
<b>{password_label}:</b> <code>{default_password}</code>

{plan['plan_name']} • Windows Server {template['windows_version']} • {region}
{renewal_text.format(date=next_renewal.strftime('%Y-%m-%d'))}

💡 {connect_tip}
⚠️ {save_warning}
"""
        
        await bot.send_message(
            chat_id=telegram_id,
            text=credentials_message,
            parse_mode='HTML'
        )
        
    except Exception as e:
        logger.error(f"❌ Error provisioning RDP server: {e}")
        
        # Send admin error notification
        await send_error_alert(
            "RDPProvisioning",
            f"❌ RDP provisioning failed for order {order_id}: {str(e)}",
            "hosting",
            {
                "order_id": order_id,
                "user_telegram_id": telegram_id,
                "error": str(e),
                "metadata": metadata
            }
        )
        
        # Notify user of error
        try:
            from telegram import Bot
            bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
            if bot_token:
                bot = Bot(token=bot_token)
                error_msg = await t_for_user('rdp.provision.error_general', telegram_id)
                await bot.send_message(
                    chat_id=telegram_id,
                    text=error_msg,
                    parse_mode='HTML'
                )
        except:
            pass

async def handle_rdp_my_servers(query, context=None):
    """Show user's RDP servers"""
    try:
        user = query.from_user
        
        # Clear auto-refresh context when navigating away from server details
        if context:
            message_id = f"{query.from_user.id}_{query.message.message_id}"
            current_view_key = f"rdp_current_view_{message_id}"
            context.user_data[current_view_key] = "rdp_my_servers"
        
        # Get user's servers
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        servers = await execute_query("""
            SELECT rs.id, rs.vultr_instance_id, rs.hostname, rs.public_ip, rs.status, rs.region,
                   rs.created_at, rs.next_renewal_date, rs.billing_cycle,
                   rp.plan_name, rt.windows_version, rt.edition
            FROM rdp_servers rs
            LEFT JOIN rdp_plans rp ON rs.plan_id = rp.id
            LEFT JOIN rdp_templates rt ON rs.template_id = rt.id
            WHERE rs.user_id = %s AND rs.deleted_at IS NULL
            ORDER BY rs.created_at DESC
        """, (db_user,))
        
        if not servers:
            # Get localized strings for empty state
            title = await t_for_user('rdp.servers.title', user.id)
            empty_message = await t_for_user('rdp.servers.empty_message', user.id)
            empty_prompt = await t_for_user('rdp.servers.empty_prompt', user.id)
            purchase_btn = await t_for_user('rdp.buttons.purchase_server', user.id)
            back_btn = await t_for_user('rdp.buttons.back', user.id)
            
            message = f"""
📊 <b>{title}</b>

{empty_message}

{empty_prompt}
"""
            keyboard = [
                [InlineKeyboardButton(purchase_btn, callback_data="rdp_purchase_start")],
                [InlineKeyboardButton(back_btn, callback_data="rdp_main")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
            return
        
        # Format server list
        title = await t_for_user('rdp.servers.title', user.id)
        count_text = await t_for_user('rdp.servers.count', user.id)
        back_btn = await t_for_user('rdp.buttons.back', user.id)
        
        message = f"""
📊 <b>{title}</b>

{count_text.format(count=len(servers))}

"""
        
        keyboard = []
        for server in servers:
            status_icon = {
                'active': '🟢',
                'provisioning': '🟡',
                'suspended': '🔴',
                'failed': '❌'
            }.get(server['status'], '⚪')
            
            region_name = get_region_name(server['region'])
            server_info = f"{status_icon} {server['plan_name']} • {region_name}"
            keyboard.append([InlineKeyboardButton(server_info, callback_data=f"rdp_server_{server['id']}")])
        
        keyboard.append([InlineKeyboardButton(back_btn, callback_data="rdp_main")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing RDP servers: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.loading_servers', user.id))

async def handle_rdp_server_details(query, context, server_id: str):
    """Show RDP server details and control options"""
    try:
        user = query.from_user
        
        # Get server details
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        server = await execute_query("""
            SELECT rs.*, rp.plan_name, rp.our_monthly_price, rt.windows_version, rt.edition
            FROM rdp_servers rs
            LEFT JOIN rdp_plans rp ON rs.plan_id = rp.id
            LEFT JOIN rdp_templates rt ON rs.template_id = rt.id
            WHERE rs.id = %s AND rs.user_id = %s AND rs.deleted_at IS NULL
        """, (int(server_id), db_user))
        
        # Check if server exists
        if not server or len(server) == 0:
            logger.warning(f"❌ Server {server_id} not found for user {db_user}")
            await safe_edit_message(query, await t_for_user('rdp.errors.server_not_found', user.id))
            return
        
        server = server[0]
        
        # Get localized strings
        provisioning_text = await t_for_user('rdp.status.provisioning', user.id)
        status_active = await t_for_user('rdp.status.active', user.id)
        status_provisioning = await t_for_user('rdp.status.provisioning', user.id)
        status_suspended = await t_for_user('rdp.status.suspended', user.id)
        status_failed = await t_for_user('rdp.status.failed', user.id)
        status_unknown = await t_for_user('rdp.status.unknown', user.id)
        
        power_running = await t_for_user('rdp.status.power_running', user.id)
        power_stopped = await t_for_user('rdp.status.power_stopped', user.id)
        power_starting = await t_for_user('rdp.status.power_starting', user.id)
        power_stopping = await t_for_user('rdp.status.power_stopping', user.id)
        power_restarting = await t_for_user('rdp.status.power_restarting', user.id)
        power_reinstalling = await t_for_user('rdp.status.power_reinstalling', user.id)
        
        renews_label = await t_for_user('rdp.details.renews', user.id)
        auto_renew_on = await t_for_user('rdp.details.auto_renew_on', user.id)
        auto_renew_off = await t_for_user('rdp.details.auto_renew_off', user.id)
        created_label = await t_for_user('rdp.details.created', user.id)
        
        stop_btn = await t_for_user('rdp.buttons.stop_server', user.id)
        restart_btn = await t_for_user('rdp.buttons.restart_server', user.id)
        start_btn = await t_for_user('rdp.buttons.start_server', user.id)
        reinstall_btn = await t_for_user('rdp.buttons.reinstall_os', user.id)
        delete_btn = await t_for_user('rdp.buttons.delete_server', user.id)
        back_servers_btn = await t_for_user('rdp.buttons.back_to_servers', user.id)
        
        # Decrypt password if available
        password = provisioning_text if not server['admin_password_encrypted'] else vultr_service.decrypt_password(server['admin_password_encrypted'])
        
        # Format status
        status_icon = {
            'active': f'🟢 {status_active}',
            'provisioning': f'🟡 {status_provisioning}',
            'suspended': f'🔴 {status_suspended}',
            'failed': f'❌ {status_failed}'
        }.get(server['status'], f'⚪ {status_unknown}')
        
        # Format power status
        power_status_display = {
            'running': f'🟢 {power_running}',
            'stopped': f'🔴 {power_stopped}',
            'starting': f'⚡ {power_starting}',
            'stopping': f'🟡 {power_stopping}',
            'restarting': f'🔄 {power_restarting}',
            'reinstalling': f'🔧 {power_reinstalling}'
        }.get(server['power_status'], server['power_status'] or status_unknown)
        
        # Format next renewal
        next_renewal = server['next_renewal_date'].strftime('%Y-%m-%d') if server['next_renewal_date'] else 'N/A'
        
        region_name = get_region_name(server['region'])
        
        message = f"""💻 <code>{server['public_ip'] or provisioning_text}</code>

{status_icon} • {power_status_display}
{await t_for_user('rdp.server_details.display_format', user.id, version=server['windows_version'], edition=server['edition'], plan=server['plan_name'], region=region_name)}

👤 Administrator / <code>{password}</code>

💰 ${float(server['monthly_price']):.2f}/mo • {server['billing_cycle'].capitalize()} • {renews_label}: {next_renewal} • {auto_renew_on if server['auto_renew'] else auto_renew_off}

{created_label}: {server['created_at'].strftime('%Y-%m-%d %H:%M UTC')}"""
        
        keyboard = []
        
        # Control buttons based on status
        if server['status'] == 'active':
            if server['power_status'] == 'running':
                keyboard.append([InlineKeyboardButton(stop_btn, callback_data=f"rdp_stop_{server_id}")])
                keyboard.append([InlineKeyboardButton(restart_btn, callback_data=f"rdp_restart_{server_id}")])
            elif server['power_status'] == 'stopped':
                keyboard.append([InlineKeyboardButton(start_btn, callback_data=f"rdp_start_{server_id}")])
            elif server['power_status'] == 'starting':
                # Show no start/stop buttons while starting - auto-refresh will update
                pass
            
            keyboard.append([InlineKeyboardButton(reinstall_btn, callback_data=f"rdp_reinstall_confirm_{server_id}")])
            keyboard.append([InlineKeyboardButton(delete_btn, callback_data=f"rdp_delete_confirm_{server_id}")])
        
        keyboard.append([InlineKeyboardButton(back_servers_btn, callback_data="rdp_my_servers")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        # Auto-refresh if server is in transitioning state
        needs_refresh = (
            server['status'] == 'provisioning' or 
            server['power_status'] in ['starting', 'stopping', 'restarting', 'reinstalling'] or
            not server['public_ip']
        )
        
        if needs_refresh:
            # Store current view context to detect navigation
            message_id = f"{query.from_user.id}_{query.message.message_id}"
            current_view_key = f"rdp_current_view_{message_id}"
            context.user_data[current_view_key] = f"server_details_{server_id}"
            
            # Schedule auto-refresh after 5 seconds
            async def auto_refresh():
                await asyncio.sleep(5)
                try:
                    # Check if user is still on this server details page
                    if context.user_data.get(current_view_key) == f"server_details_{server_id}":
                        await handle_rdp_server_details(query, context, server_id)
                    # else: User navigated away - stop auto-refresh
                except:
                    pass  # Ignore errors during auto-refresh
            
            # Start background task
            asyncio.create_task(auto_refresh())
        
    except Exception as e:
        logger.error(f"Error showing RDP server details: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.loading_details', user.id))

async def handle_rdp_start_server(query, context, server_id: str):
    """Start RDP server"""
    try:
        user = query.from_user
        
        # Instant feedback
        await safe_edit_message(query, await t_for_user('rdp.control.starting', user.id))
        
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        # Get server
        server = await execute_query("""
            SELECT vultr_instance_id FROM rdp_servers
            WHERE id = %s AND user_id = %s AND deleted_at IS NULL
        """, (int(server_id), db_user))
        
        # Check if server exists
        if not server or len(server) == 0:
            logger.warning(f"❌ Server {server_id} not found for user {db_user}")
            await safe_edit_message(query, await t_for_user('rdp.errors.server_not_found', user.id))
            return
        
        instance_id = server[0]['vultr_instance_id']
        
        # Start server
        success = vultr_service.start_instance(instance_id)
        
        if success:
            await execute_update("""
                UPDATE rdp_servers SET power_status = 'running' WHERE id = %s
            """, (int(server_id),))
            
            await safe_edit_message(query, await t_for_user('rdp.control.start_success', user.id))
            await asyncio.sleep(2)
            await handle_rdp_server_details(query, context, server_id)
        else:
            await safe_edit_message(query, await t_for_user('rdp.control.start_failed', user.id))
        
    except Exception as e:
        logger.error(f"Error starting RDP server: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.start_error', user.id))

async def handle_rdp_stop_server(query, context, server_id: str):
    """Stop RDP server"""
    try:
        user = query.from_user
        
        # Instant feedback
        await safe_edit_message(query, await t_for_user('rdp.control.stopping', user.id))
        
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        # Get server
        server = await execute_query("""
            SELECT vultr_instance_id FROM rdp_servers
            WHERE id = %s AND user_id = %s AND deleted_at IS NULL
        """, (int(server_id), db_user))
        
        # Check if server exists
        if not server or len(server) == 0:
            logger.warning(f"❌ Server {server_id} not found for user {db_user}")
            await safe_edit_message(query, await t_for_user('rdp.errors.server_not_found', user.id))
            return
        
        instance_id = server[0]['vultr_instance_id']
        
        # Stop server
        success = vultr_service.stop_instance(instance_id)
        
        if success:
            await execute_update("""
                UPDATE rdp_servers SET power_status = 'stopped' WHERE id = %s
            """, (int(server_id),))
            
            await safe_edit_message(query, await t_for_user('rdp.control.stop_success', user.id))
            await asyncio.sleep(2)
            await handle_rdp_server_details(query, context, server_id)
        else:
            await safe_edit_message(query, await t_for_user('rdp.control.stop_failed', user.id))
        
    except Exception as e:
        logger.error(f"Error stopping RDP server: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.stop_error', user.id))

async def handle_rdp_restart_server(query, context, server_id: str):
    """Restart RDP server"""
    try:
        user = query.from_user
        
        # Instant feedback
        await safe_edit_message(query, await t_for_user('rdp.control.restarting', user.id))
        
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        # Get server
        server = await execute_query("""
            SELECT vultr_instance_id FROM rdp_servers
            WHERE id = %s AND user_id = %s AND deleted_at IS NULL
        """, (int(server_id), db_user))
        
        # Check if server exists
        if not server or len(server) == 0:
            logger.warning(f"❌ Server {server_id} not found for user {db_user}")
            await safe_edit_message(query, await t_for_user('rdp.errors.server_not_found', user.id))
            return
        
        instance_id = server[0]['vultr_instance_id']
        
        # Restart server
        success = vultr_service.reboot_instance(instance_id)
        
        if success:
            await safe_edit_message(query, await t_for_user('rdp.control.restart_success', user.id))
            await asyncio.sleep(2)
            await handle_rdp_server_details(query, context, server_id)
        else:
            await safe_edit_message(query, await t_for_user('rdp.control.restart_failed', user.id))
        
    except Exception as e:
        logger.error(f"Error restarting RDP server: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.restart_error', user.id))

async def handle_rdp_reinstall_confirm(query, context, server_id: str):
    """Show reinstall OS confirmation"""
    user = query.from_user
    
    # Get localized strings
    title = await t_for_user('rdp.reinstall.confirm_title', user.id)
    will_title = await t_for_user('rdp.reinstall.will_title', user.id)
    wipe_server = await t_for_user('rdp.reinstall.wipe_server', user.id)
    reinstall_windows = await t_for_user('rdp.reinstall.reinstall_windows', user.id)
    generate_password = await t_for_user('rdp.reinstall.generate_password', user.id)
    cause_downtime = await t_for_user('rdp.reinstall.cause_downtime', user.id)
    data_lost = await t_for_user('rdp.reinstall.data_lost', user.id)
    confirm_prompt = await t_for_user('rdp.reinstall.confirm_prompt', user.id)
    yes_btn = await t_for_user('rdp.buttons.yes_reinstall', user.id)
    cancel_btn = await t_for_user('rdp.buttons.cancel', user.id)
    
    message = f"""
⚠️ <b>{title}</b>

{will_title}
• {wipe_server}
• {reinstall_windows}
• {generate_password}
• {cause_downtime}

<b>{data_lost}</b>

{confirm_prompt}
"""
    
    keyboard = [
        [InlineKeyboardButton(yes_btn, callback_data=f"rdp_reinstall_{server_id}")],
        [InlineKeyboardButton(cancel_btn, callback_data=f"rdp_server_{server_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def handle_rdp_reinstall(query, context, server_id: str):
    """Reinstall OS on RDP server"""
    try:
        user = query.from_user
        
        # Instant feedback
        await safe_edit_message(query, await t_for_user('rdp.reinstall.in_progress', user.id))
        
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        # Get server
        server = await execute_query("""
            SELECT vultr_instance_id FROM rdp_servers
            WHERE id = %s AND user_id = %s AND deleted_at IS NULL
        """, (int(server_id), db_user))
        
        # Check if server exists
        if not server or len(server) == 0:
            logger.warning(f"❌ Server {server_id} not found for user {db_user}")
            await safe_edit_message(query, await t_for_user('rdp.errors.server_not_found', user.id))
            return
        
        instance_id = server[0]['vultr_instance_id']
        
        # Reinstall OS
        success = vultr_service.reinstall_instance(instance_id)
        
        if success:
            await execute_update("""
                UPDATE rdp_servers 
                SET status = 'provisioning', admin_password_encrypted = NULL, power_status = 'reinstalling'
                WHERE id = %s
            """, (int(server_id),))
            
            # Get localized strings
            title = await t_for_user('rdp.reinstall.progress_title', user.id)
            message_text = await t_for_user('rdp.reinstall.progress_message', user.id)
            completion_text = await t_for_user('rdp.reinstall.completion_notice', user.id)
            
            await safe_edit_message(query, f"""
⏳ <b>{title}</b>

{message_text}

{completion_text}
""", parse_mode='HTML')
            
            # Wait for reinstall to complete and update credentials
            asyncio.create_task(wait_for_reinstall_complete(user.id, int(server_id), instance_id))
        else:
            await safe_edit_message(query, await t_for_user('rdp.reinstall.failed', user.id))
        
    except Exception as e:
        logger.error(f"Error reinstalling RDP server: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.reinstall_error', user.id))

async def smart_auto_start_server(instance_id: str, server_id: Optional[int], is_new: bool):
    """
    Smart auto-start with exponential backoff retry logic to handle Vultr's post-install stabilization period
    
    Args:
        instance_id: Vultr instance ID
        server_id: Database server ID (None for new servers, use instance_id lookup)
        is_new: True for newly created servers, False for reinstalled servers
    """
    try:
        logger.info(f"🚀 Smart auto-start initiated for {'new' if is_new else 'reinstalled'} server {instance_id}")
        
        # Give Vultr 10 seconds to stabilize after provisioning/reinstall
        logger.info(f"⏳ Waiting 10s for server stabilization...")
        await asyncio.sleep(10)
        
        # Exponential backoff delays: 5s, 10s, 20s (total ~45s over 4 attempts)
        retry_delays = [5, 10, 20]
        
        # Try to start with retries (4 attempts with exponential backoff)
        for attempt in range(1, 5):
            logger.info(f"🔄 Auto-start attempt {attempt}/4 for {instance_id}")
            
            start_success = vultr_service.start_instance(instance_id)
            
            if start_success:
                # Update power status to running
                if server_id:
                    # Reinstalled server - we have server_id
                    await execute_update("""
                        UPDATE rdp_servers 
                        SET power_status = 'running'
                        WHERE id = %s
                    """, (server_id,))
                else:
                    # New server - look up by instance_id
                    await execute_update("""
                        UPDATE rdp_servers 
                        SET power_status = 'running'
                        WHERE vultr_instance_id = %s
                    """, (instance_id,))
                
                logger.info(f"✅ Server {instance_id} successfully auto-started on attempt {attempt}")
                return True
            
            # If failed and not last attempt, wait before retry with exponential backoff
            if attempt < 4:
                delay = retry_delays[attempt - 1]
                logger.info(f"⏳ Start failed, retrying in {delay}s with exponential backoff (attempt {attempt}/4)")
                await asyncio.sleep(delay)
        
        # All retries failed
        logger.warning(f"⚠️ Auto-start failed after 4 attempts for {instance_id}")
        return False
        
    except Exception as e:
        logger.error(f"❌ Error in smart auto-start for {instance_id}: {e}")
        return False

async def wait_for_reinstall_complete(telegram_id: int, server_id: int, instance_id: str):
    """Wait for OS reinstall to complete and send new credentials"""
    try:
        # Wait for instance to be ready
        instance_ready = await vultr_service.wait_for_instance_ready(instance_id, timeout=900)  # 15 min timeout
        
        if not instance_ready:
            logger.error(f"❌ Instance {instance_id} reinstall timed out")
            return
        
        # Get new password
        new_password = instance_ready.get('default_password', 'N/A')
        encrypted_password = vultr_service.encrypt_password(new_password) if new_password != 'N/A' else None
        
        # Update server - set to 'starting' initially for auto-start
        await execute_update("""
            UPDATE rdp_servers
            SET admin_password_encrypted = %s,
                power_status = 'starting',
                status = 'active'
            WHERE id = %s
        """, (encrypted_password, server_id))
        
        logger.info(f"✅ Reinstalled server ready, launching auto-start")
        
        # Launch async auto-start with smart retry
        asyncio.create_task(smart_auto_start_server(instance_id, server_id=server_id, is_new=False))
        
        # Send new credentials
        server = await execute_query("""
            SELECT hostname, public_ip FROM rdp_servers WHERE id = %s
        """, (server_id,))
        
        # Check if server exists
        if server and len(server) > 0:
            server = server[0]
            
            bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
            if not bot_token:
                logger.error("❌ TELEGRAM_BOT_TOKEN not set - cannot send reinstall credentials")
                return
            
            from telegram import Bot
            bot = Bot(token=bot_token)
            
            # Get localized strings
            title = await t_for_user('rdp.reinstall.complete_title', telegram_id)
            server_reinstalled = await t_for_user('rdp.reinstall.server_reinstalled', telegram_id)
            new_creds_title = await t_for_user('rdp.reinstall.new_credentials', telegram_id)
            ip_label = await t_for_user('rdp.provision.ip_label', telegram_id)
            username_label = await t_for_user('rdp.provision.username_label', telegram_id)
            password_label = await t_for_user('rdp.provision.password_label', telegram_id)
            save_warning = await t_for_user('rdp.reinstall.save_credentials', telegram_id)
            
            await bot.send_message(
                chat_id=telegram_id,
                text=f"""
✅ <b>{title}</b>

{server_reinstalled.format(hostname=server['hostname'])}

<b>{new_creds_title}</b>
━━━━━━━━━━━━━━━━━━━
<b>{ip_label}:</b> <code>{server['public_ip']}</code>
<b>{username_label}:</b> <code>Administrator</code>
<b>{password_label}:</b> <code>{new_password}</code>
━━━━━━━━━━━━━━━━━━━

⚠️ {save_warning}
""",
                parse_mode='HTML'
            )
        
    except Exception as e:
        logger.error(f"❌ Error waiting for reinstall: {e}")

async def handle_rdp_delete_confirm(query, context, server_id: str):
    """Show delete server confirmation"""
    user = query.from_user
    
    # Get localized strings
    title = await t_for_user('rdp.delete.confirm_title', user.id)
    will_title = await t_for_user('rdp.delete.will_title', user.id)
    permanently_delete = await t_for_user('rdp.delete.permanently_delete', user.id)
    remove_data = await t_for_user('rdp.delete.remove_data', user.id)
    stop_billing = await t_for_user('rdp.delete.stop_billing', user.id)
    cannot_undo = await t_for_user('rdp.delete.cannot_undo', user.id)
    confirm_prompt = await t_for_user('rdp.delete.confirm_prompt', user.id)
    yes_btn = await t_for_user('rdp.buttons.yes_delete', user.id)
    cancel_btn = await t_for_user('rdp.buttons.cancel', user.id)
    
    message = f"""
⚠️ <b>{title}</b>

{will_title}
• {permanently_delete}
• {remove_data}
• {stop_billing}
• {cannot_undo}

{confirm_prompt}
"""
    
    keyboard = [
        [InlineKeyboardButton(yes_btn, callback_data=f"rdp_delete_{server_id}")],
        [InlineKeyboardButton(cancel_btn, callback_data=f"rdp_server_{server_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def handle_rdp_delete(query, context, server_id: str):
    """Delete RDP server"""
    try:
        user = query.from_user
        
        # Clear auto-refresh context to prevent refresh after deletion
        message_id = f"{query.from_user.id}_{query.message.message_id}"
        current_view_key = f"rdp_current_view_{message_id}"
        context.user_data[current_view_key] = "rdp_deleting"
        
        db_user = await get_internal_user_id_from_telegram_id(user.id)
        
        # Check if user lookup failed
        if not db_user:
            logger.error(f"❌ Failed to get user ID for telegram user {user.id}")
            await safe_edit_message(query, await t_for_user('rdp.errors.user_data_error', user.id))
            return
        
        # Get server
        server = await execute_query("""
            SELECT vultr_instance_id, hostname FROM rdp_servers
            WHERE id = %s AND user_id = %s AND deleted_at IS NULL
        """, (int(server_id), db_user))
        
        # Check if server exists
        if not server or len(server) == 0:
            logger.warning(f"❌ Server {server_id} not found for user {db_user}")
            await safe_edit_message(query, await t_for_user('rdp.errors.server_not_found', user.id))
            return
        
        instance_id = server[0]['vultr_instance_id']
        hostname = server[0]['hostname']
        
        # Delete from Vultr
        success = vultr_service.delete_instance(instance_id)
        
        if success:
            # Mark as deleted in database
            await execute_update("""
                UPDATE rdp_servers 
                SET deleted_at = NOW(), status = 'deleted', auto_renew = false
                WHERE id = %s
            """, (int(server_id),))
            
            # Get localized strings
            title = await t_for_user('rdp.delete.success_title', user.id)
            message_text = await t_for_user('rdp.delete.success_message', user.id)
            billing_stopped = await t_for_user('rdp.delete.billing_stopped', user.id)
            
            await safe_edit_message(query, f"""
✅ <b>{title}</b>

{message_text.format(hostname=hostname)}

{billing_stopped}
""", parse_mode='HTML')
            
            await asyncio.sleep(3)
            await handle_rdp_my_servers(query, context)
        else:
            await safe_edit_message(query, await t_for_user('rdp.delete.failed', user.id))
        
    except Exception as e:
        logger.error(f"Error deleting RDP server: {e}")
        user = query.from_user
        await safe_edit_message(query, await t_for_user('rdp.errors.delete_error', user.id))
