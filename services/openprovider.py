"""
OpenProvider domain registration API integration
Handles domain availability, registration, and management
Enhanced with high-performance caching for 20+ ops/sec target
"""

import os
import logging
import httpx
import time
import asyncio
import socket
from decimal import Decimal
from typing import Dict, List, Optional, Union, Any, Callable, Tuple
# Base64 no longer needed - using Bearer token authentication
from pricing_utils import calculate_marked_up_price, format_price_display
from performance_cache import cache_get, cache_set, cache_invalidate
from performance_monitor import monitor_performance, OperationTimer  # type: ignore[misc]
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert, send_info_alert

logger = logging.getLogger(__name__)

# Import TLD requirements validation system
try:
    from services.tld_requirements import TLDRequirementsValidator, TLDValidationResult
    TLD_VALIDATION_AVAILABLE = True
    # Initialize global TLD validator instance
    _tld_validator = TLDRequirementsValidator()
    logger.info("✅ TLD requirements validation system loaded")
except ImportError as e:
    logger.warning(f"⚠️ TLD requirements validation not available: {e}")
    TLD_VALIDATION_AVAILABLE = False
    _tld_validator = None

class IPDetectionService:
    """Robust IP detection service with multiple fallback providers and caching"""
    
    # IP detection services in order of preference
    IP_SERVICES = [
        {
            'url': 'https://api.ipify.org',
            'name': 'IPify',
            'timeout': 5,
            'response_type': 'text'
        },
        {
            'url': 'https://ifconfig.me/ip',
            'name': 'ifconfig.me',
            'timeout': 5,
            'response_type': 'text'
        },
        {
            'url': 'https://httpbin.org/ip',
            'name': 'HTTPBin',
            'timeout': 5,
            'response_type': 'json',
            'json_key': 'origin'
        },
        {
            'url': 'https://icanhazip.com',
            'name': 'CanHazIP',
            'timeout': 5,
            'response_type': 'text'
        }
    ]
    
    # Cache duration in seconds (10 minutes)
    CACHE_DURATION = 600
    
    def __init__(self):
        self._cached_ip = None
        self._cache_timestamp = 0
        self._detection_history = []  # Track success/failure patterns
    
    def _is_cache_valid(self) -> bool:
        """Check if cached IP is still valid"""
        if not self._cached_ip:
            return False
        
        current_time = time.time()
        cache_age = current_time - self._cache_timestamp
        is_valid = cache_age < self.CACHE_DURATION
        
        if is_valid:
            logger.debug(f"🔄 Using cached IP: {self._cached_ip} (age: {cache_age:.1f}s)")
        else:
            logger.debug(f"⏰ IP cache expired (age: {cache_age:.1f}s), fetching new IP")
        
        return is_valid
    
    def _cache_ip(self, ip_address: str) -> None:
        """Cache the detected IP address"""
        self._cached_ip = ip_address
        self._cache_timestamp = time.time()
        logger.debug(f"💾 Cached IP address: {ip_address}")
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Basic IP address validation"""
        if not ip_str or not isinstance(ip_str, str):
            return False
        
        ip_str = ip_str.strip()
        
        # Basic IPv4 validation
        parts = ip_str.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        
        # Basic IPv6 validation (simplified)
        if ':' in ip_str and len(ip_str) > 2:
            return True
        
        return False
    
    async def _try_ip_service(self, service: Dict, client: httpx.AsyncClient) -> Optional[str]:
        """Try a single IP detection service"""
        service_name = service['name']
        url = service['url']
        timeout = service['timeout']
        
        try:
            logger.debug(f"🌐 Trying IP service: {service_name} ({url})")
            start_time = time.time()
            
            response = await client.get(url, timeout=timeout)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                # Parse response based on type
                if service['response_type'] == 'text':
                    ip_address = response.text.strip()
                elif service['response_type'] == 'json':
                    json_data = response.json()
                    json_key = service.get('json_key', 'ip')
                    ip_address = json_data.get(json_key, '').strip()
                    # Handle cases where HTTPBin returns multiple IPs
                    if ',' in ip_address:
                        ip_address = ip_address.split(',')[0].strip()
                else:
                    logger.error(f"❌ Unknown response type for {service_name}")
                    return None
                
                # Validate the IP address
                if self._is_valid_ip(ip_address):
                    logger.info(f"✅ {service_name} returned valid IP: {ip_address} ({response_time:.2f}s)")
                    self._detection_history.append({
                        'service': service_name,
                        'success': True,
                        'ip': ip_address,
                        'response_time': response_time,
                        'timestamp': time.time()
                    })
                    return ip_address
                else:
                    logger.warning(f"⚠️ {service_name} returned invalid IP: '{ip_address}'")
                    
            else:
                logger.warning(f"⚠️ {service_name} returned HTTP {response.status_code}")
                
        except asyncio.TimeoutError:
            error_msg = f"Timed out after {timeout}s"
            logger.warning(f"⏰ {service_name} {error_msg}")
        except Exception as e:
            error_msg = str(e)
            logger.warning(f"❌ {service_name} failed: {e}")
        else:
            error_msg = "HTTP error or invalid response"
        
        # Record failure
        self._detection_history.append({
            'service': service_name,
            'success': False,
            'error': error_msg,
            'timestamp': time.time()
        })
        
        return None
    
    async def detect_public_ip(self, force_refresh: bool = False) -> Optional[str]:
        """
        Detect public IP using multiple fallback services with caching
        
        Args:
            force_refresh: If True, bypass cache and fetch fresh IP
            
        Returns:
            IP address string or None if all services fail
        """
        # Check manual override first (highest priority)
        manual_ip = os.getenv('OPENPROVIDER_IP')
        if manual_ip:
            logger.info(f"🎯 Using manually configured IP: {manual_ip}")
            return manual_ip
        
        # Check cache if not forcing refresh
        if not force_refresh and self._is_cache_valid():
            return self._cached_ip
        
        logger.info("🔍 Detecting public IP address using fallback services...")
        start_time = time.time()
        
        # Try each service in order with optimized HTTP client
        timeout_config = httpx.Timeout(connect=3.0, read=8.0, write=5.0, pool=10.0)
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            for i, service in enumerate(self.IP_SERVICES):
                ip_address = await self._try_ip_service(service, client)
                
                if ip_address:
                    # Success! Cache and return
                    self._cache_ip(ip_address)
                    total_time = time.time() - start_time
                    logger.info(f"🎉 IP detection successful: {ip_address} (took {total_time:.2f}s, service #{i+1})")
                    return ip_address
                
                # Small delay between services to be respectful
                if i < len(self.IP_SERVICES) - 1:
                    await asyncio.sleep(0.5)
        
        # All services failed
        total_time = time.time() - start_time
        logger.error(f"❌ All IP detection services failed after {total_time:.2f}s")
        
        # Log recent detection history for debugging
        if self._detection_history:
            recent_history = self._detection_history[-5:]  # Last 5 attempts
            logger.error("📊 Recent IP detection history:")
            for entry in recent_history:
                status = "✅" if entry['success'] else "❌"
                timestamp = time.strftime('%H:%M:%S', time.localtime(entry['timestamp']))
                if entry['success']:
                    logger.error(f"   {status} {entry['service']}: {entry['ip']} ({entry['response_time']:.2f}s) at {timestamp}")
                else:
                    logger.error(f"   {status} {entry['service']}: {entry.get('error', 'Failed')} at {timestamp}")
        
        return None
    
    def get_cache_status(self) -> Dict:
        """Get current cache status for debugging"""
        if not self._cached_ip:
            return {'cached': False, 'ip': None, 'age': 0}
        
        cache_age = time.time() - self._cache_timestamp
        return {
            'cached': True,
            'ip': self._cached_ip,
            'age': cache_age,
            'valid': self._is_cache_valid(),
            'expires_in': max(0, self.CACHE_DURATION - cache_age)
        }

# Global IP detection service instance
_ip_detector = IPDetectionService()

class DomainIDCache:
    """Thread-safe cache for domain IDs with TTL support"""
    
    def __init__(self, ttl_seconds: int = 3600):  # 1 hour TTL
        self._cache = {}
        self._timestamps = {}
        self._ttl = ttl_seconds
    
    def get(self, domain_name: str) -> Optional[int]:
        """Get cached domain ID if valid"""
        domain_key = domain_name.lower().strip()
        current_time = time.time()
        
        if domain_key in self._cache:
            cache_age = current_time - self._timestamps[domain_key]
            if cache_age < self._ttl:
                logger.debug(f"💾 Using cached domain ID for {domain_name}: {self._cache[domain_key]} (age: {cache_age:.1f}s)")
                return self._cache[domain_key]
            else:
                # Cache expired, remove it
                logger.debug(f"⏰ Cache expired for {domain_name} (age: {cache_age:.1f}s)")
                self._remove(domain_key)
        
        return None
    
    def set(self, domain_name: str, domain_id: int) -> None:
        """Cache domain ID with timestamp"""
        domain_key = domain_name.lower().strip()
        self._cache[domain_key] = domain_id
        self._timestamps[domain_key] = time.time()
        logger.debug(f"💾 Cached domain ID for {domain_name}: {domain_id}")
    
    def _remove(self, domain_key: str) -> None:
        """Remove domain from cache"""
        self._cache.pop(domain_key, None)
        self._timestamps.pop(domain_key, None)
    
    def invalidate(self, domain_name: str) -> None:
        """Invalidate cached domain ID"""
        domain_key = domain_name.lower().strip()
        self._remove(domain_key)
        logger.debug(f"🗑️ Invalidated cache for {domain_name}")
    
    def clear(self) -> None:
        """Clear all cached domain IDs"""
        self._cache.clear()
        self._timestamps.clear()
        logger.debug("🗑️ Cleared all domain ID cache")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics for debugging"""
        current_time = time.time()
        valid_entries = 0
        expired_entries = 0
        
        for domain_key, timestamp in self._timestamps.items():
            cache_age = current_time - timestamp
            if cache_age < self._ttl:
                valid_entries += 1
            else:
                expired_entries += 1
        
        return {
            'total_entries': len(self._cache),
            'valid_entries': valid_entries,
            'expired_entries': expired_entries,
            'cache_ttl_seconds': self._ttl
        }

# Global domain ID cache instance
_domain_id_cache = DomainIDCache()

class TLDPriceCache:
    """Cache for TLD pricing to avoid repeated API calls"""
    
    def __init__(self, ttl_seconds: int = 1800):  # 30 minutes TTL
        self._cache = {}
        self._timestamps = {}
        self._ttl = ttl_seconds
    
    def get(self, tld: str) -> Optional[Dict]:
        """Get cached pricing for TLD if valid"""
        tld_key = tld.lower().strip()
        current_time = time.time()
        
        if tld_key in self._cache:
            cache_age = current_time - self._timestamps[tld_key]
            if cache_age < self._ttl:
                logger.debug(f"💾 Using cached TLD pricing for {tld}: age {cache_age:.1f}s")
                return self._cache[tld_key]
            else:
                # Cache expired, remove it
                self._remove(tld_key)
        
        return None
    
    def set(self, tld: str, pricing_data: Dict) -> None:
        """Cache TLD pricing with timestamp"""
        tld_key = tld.lower().strip()
        self._cache[tld_key] = pricing_data
        self._timestamps[tld_key] = time.time()
        logger.debug(f"💾 Cached TLD pricing for {tld}")
    
    def _remove(self, tld_key: str) -> None:
        """Remove TLD from cache"""
        self._cache.pop(tld_key, None)
        self._timestamps.pop(tld_key, None)
    
    def clear(self) -> None:
        """Clear all cached TLD pricing"""
        self._cache.clear()
        self._timestamps.clear()
        logger.debug("🗑️ Cleared all TLD pricing cache")

# Global TLD price cache instance
_tld_price_cache = TLDPriceCache()

class DomainAvailabilityCache:
    """Cache for domain availability results to avoid duplicate API calls during registration flow"""
    
    def __init__(self, ttl_seconds: int = 1800):  # 30 minutes TTL - optimized for better hit rate (domain availability rarely changes)
        self._cache = {}
        self._timestamps = {}
        self._ttl = ttl_seconds
    
    def get(self, domain_name: str) -> Optional[Dict]:
        """Get cached availability result if valid"""
        domain_key = domain_name.lower().strip()
        current_time = time.time()
        
        if domain_key in self._cache:
            cache_age = current_time - self._timestamps[domain_key]
            if cache_age < self._ttl:
                logger.debug(f"💾 Using cached availability for {domain_name}: age {cache_age:.1f}s")
                return self._cache[domain_key]
            else:
                # Cache expired, remove it
                logger.debug(f"⏰ Availability cache expired for {domain_name} (age: {cache_age:.1f}s)")
                self._remove(domain_key)
        
        return None
    
    def set(self, domain_name: str, availability_result: Dict) -> None:
        """Cache domain availability result with timestamp"""
        domain_key = domain_name.lower().strip()
        self._cache[domain_key] = availability_result
        self._timestamps[domain_key] = time.time()
        logger.debug(f"💾 Cached availability for {domain_name}: available={availability_result.get('available')}, price={availability_result.get('price')}")
    
    def _remove(self, domain_key: str) -> None:
        """Remove domain from cache"""
        self._cache.pop(domain_key, None)
        self._timestamps.pop(domain_key, None)
    
    def invalidate(self, domain_name: str) -> None:
        """Invalidate cached availability (useful if domain status changes)"""
        domain_key = domain_name.lower().strip()
        self._remove(domain_key)
        logger.debug(f"🗑️ Invalidated availability cache for {domain_name}")
    
    def clear(self) -> None:
        """Clear all cached availability results"""
        self._cache.clear()
        self._timestamps.clear()
        logger.debug("🗑️ Cleared all domain availability cache")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics for debugging"""
        current_time = time.time()
        valid_entries = 0
        expired_entries = 0
        
        for domain_key, timestamp in self._timestamps.items():
            cache_age = current_time - timestamp
            if cache_age < self._ttl:
                valid_entries += 1
            else:
                expired_entries += 1
        
        return {
            'total_entries': len(self._cache),
            'valid_entries': valid_entries,
            'expired_entries': expired_entries,
            'cache_ttl_seconds': self._ttl
        }

# Global domain availability cache instance  
_availability_cache = DomainAvailabilityCache()

class DomainStatusRetryManager:
    """Manages intelligent retry logic for domain operations with exponential backoff"""
    
    def __init__(self):
        self.max_retries = 5
        self.base_delay = 60  # 1 minute base delay
        self.max_delay = 1800  # 30 minutes max delay
        self.transitional_states = ['pending', 'pending-create', 'pending-update', 'pending-transfer']
        self.prohibited_states = ['client-hold', 'server-hold', 'client-update-prohibited', 'server-update-prohibited']
    
    def calculate_retry_delay(self, attempt: int, error_type: str = 'general') -> int:
        """Calculate retry delay with exponential backoff"""
        if error_type == 'transitional':
            # Longer delays for transitional states
            delay = min(self.base_delay * (2 ** attempt), self.max_delay)
        elif error_type == 'rate_limit':
            # Shorter delays for rate limiting
            delay = min(30 * (2 ** attempt), 300)  # Max 5 minutes for rate limits
        else:
            # Standard exponential backoff
            delay = min(self.base_delay * (1.5 ** attempt), self.max_delay)
        
        return int(delay)
    
    def should_retry(self, error_code: Optional[int], error_type: str, current_attempt: int) -> bool:
        """Determine if an operation should be retried"""
        if current_attempt >= self.max_retries:
            return False
        
        # Always retry transitional states
        if error_type == 'transitional':
            return True
        
        # Retry certain API error codes
        retryable_codes = [429, 500, 502, 503, 504, 365, 367]
        if error_code and error_code in retryable_codes:
            return True
        
        # Never retry prohibited states or critical errors
        if error_type in ['prohibited', 'critical'] or error_code == 366:
            return False
        
        return current_attempt < 3  # Default: retry up to 3 times

# Initialize global retry manager instance
_retry_manager: DomainStatusRetryManager = DomainStatusRetryManager()

class OptimizedOpenProviderService:
    """High-performance OpenProvider API service with connection pooling and caching"""
    
    _instance: Optional['OptimizedOpenProviderService'] = None
    _client: Optional[httpx.AsyncClient] = None
    _token_cache_time: float = 0
    _token_ttl: int = 3600  # 1 hour token cache
    
    def __new__(cls):
        """Singleton pattern for shared connections and auth"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        # SECURITY: Check TEST_MODE to prevent live credential usage during tests
        if os.getenv('TEST_MODE') == '1':
            logger.info("🔒 TEST_MODE active - using mock OpenProvider configuration")
            self.username = 'test_user'
            self.password = 'test_password'
            self.base_url = "https://api.test.openprovider.eu"
            self.bearer_token = 'test_bearer_token'
            self.headers = {'Content-Type': 'application/json'}
            self._account_id: Optional[int] = None
            self._initialized = True
            return
            
        # Backward compatibility for credential variable names
        self.username = os.getenv('OPENPROVIDER_USERNAME') or os.getenv('OPENPROVIDER_EMAIL')
        self.password = os.getenv('OPENPROVIDER_PASSWORD')
        self.base_url = "https://api.openprovider.eu"
        self.bearer_token = None
        self.headers = {'Content-Type': 'application/json'}
        self._account_id: Optional[int] = None
        
        # Initialize persistent HTTP client with optimizations
        self._init_client()
        self._initialized = True
    
    def _get_platform_name(self) -> str:
        """Get platform name from BrandConfig for dynamic User-Agent"""
        try:
            import os
            return os.getenv('PLATFORM_NAME', 'HostBay')
        except Exception:
            return 'HostBay'
    
    def _format_phone_for_openprovider(self, phone: str) -> dict:
        """Format phone number for OpenProvider REST API v1beta requirements
        
        CRITICAL: OpenProvider REST API v1beta REQUIRES '+' prefix in countryCode!
        Legacy SOAP/v1 API auto-prefixed it, but v1beta enforces it explicitly.
        Documentation: https://doc.openprovider.eu/API_Format_Phone
        """
        try:
            # Clean the phone number - remove all non-digits except +
            phone_clean = ''.join(char for char in phone if char.isdigit() or char == '+')
            
            if not phone_clean:
                # Default fallback phone number
                return {
                    'country_code': '+1',  # v1beta REST API requires + prefix (snake_case!)
                    'area_code': '555',
                    'subscriber_number': '1234567'
                }
            
            # Parse phone number based on common patterns
            if phone_clean.startswith('+'):
                # International format like +15551234567
                if phone_clean.startswith('+1') and len(phone_clean) >= 11:
                    # US/Canada format: +1AAANNNNNNN (12 chars total)
                    if len(phone_clean) != 12:
                        # Invalid length for US/Canada number
                        logger.warning(f"📞 Invalid length for +1 number: {phone_clean} (expected 12, got {len(phone_clean)})")
                    return {
                        'country_code': '+1',  # snake_case for v1beta REST API
                        'area_code': phone_clean[2:5],
                        'subscriber_number': phone_clean[5:]
                    }
                elif phone_clean.startswith('+33') and len(phone_clean) >= 11:
                    # France format: +33NNNNNNNNN
                    return {
                        'country_code': '+33',  # snake_case for v1beta REST API
                        'area_code': phone_clean[3:4],
                        'subscriber_number': phone_clean[4:]
                    }
                elif phone_clean.startswith('+32') and len(phone_clean) >= 10:
                    # Belgium format: +32NNNNNNNNN
                    return {
                        'country_code': '+32',  # snake_case for v1beta REST API
                        'area_code': phone_clean[3:4],
                        'subscriber_number': phone_clean[4:]
                    }
                elif phone_clean.startswith('+39') and len(phone_clean) >= 11:
                    # Italy format: Landline +39 0A NNNNNNNN or Mobile +39 3XX NNNNNNN
                    # Landline: +39 02 45678901 (Milan), +39 06 45678901 (Rome)
                    # Mobile: +39 333 4567890, +39 320 9876543
                    # Mobile numbers start with 3 and use 3-digit prefix
                    if phone_clean[3] == '3':
                        # Mobile format: 3-digit prefix
                        return {
                            'country_code': '+39',  # snake_case for v1beta REST API
                            'area_code': phone_clean[3:6],  # Extract 3 digits for mobile prefix (e.g., 333)
                            'subscriber_number': phone_clean[6:]  # Remaining 7 digits
                        }
                    else:
                        # Landline format: 2-digit area code
                        return {
                            'country_code': '+39',  # snake_case for v1beta REST API
                            'area_code': phone_clean[3:5],  # Extract 2 digits for area code
                            'subscriber_number': phone_clean[5:]  # Remaining digits
                        }
                elif phone_clean.startswith('+65') and len(phone_clean) == 11:
                    # Singapore format: +65NNNNNNNN (no area codes in Singapore)
                    return {
                        'country_code': '+65',  # snake_case for v1beta REST API
                        'area_code': '',
                        'subscriber_number': phone_clean[3:]
                    }
                else:
                    # Generic international format - assume first 1-3 digits are country code
                    country_code_len = 2 if phone_clean[1:3].isdigit() else 1
                    return {
                        'country_code': phone_clean[:country_code_len+1],  # snake_case for v1beta REST API
                        'area_code': phone_clean[country_code_len+1:country_code_len+4],
                        'subscriber_number': phone_clean[country_code_len+4:]
                    }
            elif len(phone_clean) == 10:
                # US format without country code: AAANNNNNNN
                return {
                    'country_code': '+1',  # snake_case for v1beta REST API
                    'area_code': phone_clean[:3],
                    'subscriber_number': phone_clean[3:]
                }
            else:
                # Default fallback with provided number as subscriber
                return {
                    'country_code': '+1',  # snake_case for v1beta REST API
                    'area_code': '555',
                    'subscriber_number': phone_clean[-7:] if len(phone_clean) >= 7 else phone_clean
                }
                
        except Exception as e:
            logger.warning(f"📞 Phone number parsing failed for '{phone}': {e}")
            # Safe fallback
            return {
                'country_code': '+1',  # snake_case for v1beta REST API
                'area_code': '555',
                'subscriber_number': '1234567'
            }
    
    def _init_client(self):
        """Initialize optimized HTTP client with connection pooling"""
        if self._client is None:
            # HTTP/2 and connection pooling for optimal performance
            limits = httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
                keepalive_expiry=30.0
            )
            
            # PERFORMANCE OPTIMIZED: Balanced timeouts for faster response
            timeout = httpx.Timeout(
                connect=3.0,   # Reduced from 5s for faster connection
                read=15.0,     # Reduced from 30s for better UX  
                write=6.0,     # Reduced from 10s for faster response
                pool=3.0       # Reduced from 5s for better pool management
            )
            
            self._client = httpx.AsyncClient(
                http2=False,  # Disabled to avoid hyperframe dependency issues in deployment
                limits=limits,
                timeout=timeout,
                headers={'User-Agent': f'{self._get_platform_name()}-Bot/1.0'},
                follow_redirects=True  # Handle redirects automatically
            )
            logger.info("🚀 Initialized HTTP client with OPTIMIZED timeouts: 15s read, 3s connect for faster domain operations")
    
    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure HTTP client is initialized and available"""
        if self._client is None or self._client.is_closed:
            self._init_client()
        assert self._client is not None, "HTTP client initialization failed"
        return self._client
    
    def _is_token_valid(self) -> bool:
        """Check if cached bearer token is still valid"""
        if not self.bearer_token:
            return False
        
        token_age = time.time() - self._token_cache_time
        is_valid = token_age < self._token_ttl
        
        if is_valid:
            logger.debug(f"🔄 Using cached auth token (age: {token_age:.1f}s)")
        else:
            logger.debug(f"⏰ Auth token expired (age: {token_age:.1f}s)")
        
        return is_valid
    
    def _cache_token(self, token: str) -> None:
        """Cache authentication token"""
        self.bearer_token = token
        self._token_cache_time = time.time()
        self.headers['Authorization'] = f'Bearer {token}'
        logger.debug("🔐 Cached authentication token")

    async def authenticate(self) -> bool:
        """Get bearer token from OpenProvider API with caching"""
        try:
            if not self.username or not self.password:
                logger.warning("⚠️ OpenProvider credentials not configured")
                return False
            
            # Check if we have a valid cached token first
            if self._is_token_valid():
                return True
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client")
                return False
                
            logger.info("🔐 Authenticating with OpenProvider API...")
            
            login_data = {
                "username": self.username,
                "password": self.password
            }
            
            # Detect current public IP using robust fallback service
            current_ip = await _ip_detector.detect_public_ip()
            
            if current_ip:
                login_data["ip"] = current_ip
                logger.info(f"🌐 Using detected IP for OpenProvider: {current_ip}")
            else:
                logger.warning("⚠️ Could not detect public IP - will try authentication without IP field")
            
            response = await self._client.post(
                f"{self.base_url}/v1beta/auth/login",
                headers={'Content-Type': 'application/json'},
                json=login_data
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('code', 0) == 0:
                    token = data.get('data', {}).get('token')
                    if token:
                        self._cache_token(token)
                        logger.info("✅ OpenProvider authentication successful")
                        return True
                    else:
                        logger.error("❌ No authentication token received")
                else:
                    logger.error(f"❌ OpenProvider authentication failed: {data}")
            else:
                logger.error(f"❌ Authentication request failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Error authenticating with OpenProvider: {e}")
        
        return False
    
    async def test_connection(self) -> tuple[bool, str]:
        """Test OpenProvider API connectivity"""
        try:
            if not self.username or not self.password:
                return False, "OpenProvider credentials not configured"
            
            await self._ensure_client()
            if self._client is None:
                return False, "Failed to initialize HTTP client"
            
            # Test authentication first
            auth_success = await self.authenticate()
            if not auth_success:
                return False, "Authentication failed - check credentials"
            
            # Test with minimal domain check to verify API access
            response = await self._client.post(
                f"{self.base_url}/v1beta/domains/check",
                headers=self.headers,
                json={
                    "domains": [{"name": "example", "extension": "com"}],
                    "with_price": False
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    return True, "API connected - domain check successful"
                else:
                    return False, f"API error: {data.get('desc', 'Unknown error')}"
            else:
                return False, f"HTTP {response.status_code}: API not reachable"
                
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    async def _resolve_nameserver_ips(self, nameserver: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Resolve IPv4 and IPv6 addresses for a nameserver with timeout.
        
        Returns:
            Tuple of (ipv4, ipv6) where either can be None if not resolvable
        """
        ipv4 = None
        ipv6 = None
        
        try:
            # Run DNS resolution in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            
            # Try IPv4 (A record)
            try:
                ipv4_result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None, 
                        socket.getaddrinfo,
                        nameserver, None, socket.AF_INET
                    ),
                    timeout=5.0
                )
                if ipv4_result:
                    ipv4 = ipv4_result[0][4][0]
                    logger.info(f"✅ Resolved {nameserver} (IPv4): {ipv4}")
            except (socket.gaierror, asyncio.TimeoutError) as e:
                logger.debug(f"⚠️ Could not resolve IPv4 for {nameserver}: {e}")
            
            # Try IPv6 (AAAA record)
            try:
                ipv6_result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        socket.getaddrinfo,
                        nameserver, None, socket.AF_INET6
                    ),
                    timeout=5.0
                )
                if ipv6_result:
                    ipv6 = ipv6_result[0][4][0]
                    logger.info(f"✅ Resolved {nameserver} (IPv6): {ipv6}")
            except (socket.gaierror, asyncio.TimeoutError) as e:
                logger.debug(f"⚠️ Could not resolve IPv6 for {nameserver}: {e}")
                
        except Exception as e:
            logger.error(f"❌ Error resolving IPs for {nameserver}: {e}")
        
        return ipv4, ipv6
    
    def _is_glue_record(self, nameserver: str, domain_name: str) -> bool:
        """
        Detect if a nameserver requires glue records.
        
        A glue record is needed when the nameserver is a subdomain of the domain itself.
        For example: ns1.example.com is a glue record for example.com
        
        Args:
            nameserver: The nameserver hostname (e.g., ns1.example.com)
            domain_name: The domain being updated (e.g., example.com)
        
        Returns:
            True if glue record is needed, False otherwise
        """
        # Normalize both to lowercase and remove trailing dots
        ns_normalized = nameserver.lower().rstrip('.')
        domain_normalized = domain_name.lower().rstrip('.')
        
        # Check if nameserver ends with the domain name
        # Example: ns1.example.com ends with example.com
        if ns_normalized.endswith('.' + domain_normalized) or ns_normalized == domain_normalized:
            logger.info(f"🔍 Glue record detected: {nameserver} is subdomain of {domain_name}")
            return True
        
        return False
    
    async def _build_nameserver_payload(self, nameservers: List[str], domain_name: str) -> Tuple[List[Dict], List[str]]:
        """
        Build nameserver payload with IP addresses for glue records.
        
        Args:
            nameservers: List of nameserver hostnames
            domain_name: The domain being updated
        
        Returns:
            Tuple of (nameserver_payload, errors) where:
                - nameserver_payload: List of nameserver dicts for OpenProvider API
                - errors: List of error messages if IP resolution failed
        """
        payload = []
        errors = []
        
        for i, ns in enumerate(nameservers):
            ns_entry = {
                'name': ns,
                'seq_nr': i + 1
            }
            
            # Check if this is a glue record
            if self._is_glue_record(ns, domain_name):
                # Glue record detected - need to resolve IPs
                logger.info(f"📍 Resolving IP addresses for glue record: {ns}")
                ipv4, ipv6 = await self._resolve_nameserver_ips(ns)
                
                if ipv4:
                    ns_entry['ip'] = ipv4
                    logger.info(f"✅ Added IPv4 to glue record: {ns} -> {ipv4}")
                
                if ipv6:
                    ns_entry['ip6'] = ipv6
                    logger.info(f"✅ Added IPv6 to glue record: {ns} -> {ipv6}")
                
                # If we couldn't resolve any IP for a glue record, this is an error
                if not ipv4 and not ipv6:
                    error_msg = f"Could not resolve IP address for glue record: {ns}"
                    errors.append(error_msg)
                    logger.error(f"❌ {error_msg}")
            else:
                # Regular nameserver - no IP needed
                logger.debug(f"✅ Regular nameserver (no glue record needed): {ns}")
            
            payload.append(ns_entry)
        
        return payload, errors

    async def check_domain_registration_eligibility(self, domain_name: str, contact_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Enhanced domain eligibility check with duplicate prevention and similarity detection.
        
        This method performs comprehensive pre-registration validation to prevent
        OpenProvider error 346 and other registration failures.
        
        Returns:
            Dict with eligibility status, warnings, and recommendations
        """
        try:
            logger.info(f"🔍 ELIGIBILITY CHECK: Analyzing {domain_name} for potential registration issues")
            
            result = {
                'eligible': True,
                'warnings': [],
                'recommendations': [],
                'risk_factors': [],
                'availability_result': None
            }
            
            # Step 1: Basic domain format validation
            if not self._validate_domain_format(domain_name):
                result['eligible'] = False
                result['warnings'].append('Invalid domain format')
                return result
            
            # Step 2: Check for potential similarity issues that might trigger duplicate detection
            similarity_risks = await self._check_domain_similarity_risks(domain_name)
            if similarity_risks:
                result['risk_factors'].extend(similarity_risks)
                result['warnings'].append('Domain similarity patterns detected that may trigger duplicate restrictions')
                result['recommendations'].append('Consider using a more unique domain name')
            
            # Step 3: Perform standard availability check
            availability_result = await self.check_domain_availability(domain_name, contact_data)
            result['availability_result'] = availability_result
            
            if not availability_result:
                result['eligible'] = False
                result['warnings'].append('Could not verify domain availability')
                return result
            
            if not availability_result.get('available', False):
                result['eligible'] = False
                result['warnings'].append('Domain is not available for registration')
                return result
            
            # Step 4: Check for registry-specific restrictions
            registry_warnings = await self._check_registry_restrictions(domain_name)
            if registry_warnings:
                result['warnings'].extend(registry_warnings)
            
            # Step 5: Analyze TLD-specific risks
            tld_risks = self._analyze_tld_risks(domain_name)
            if tld_risks:
                result['risk_factors'].extend(tld_risks)
            
            # Step 6: Provide recommendations based on analysis
            if result['risk_factors'] or result['warnings']:
                result['recommendations'].append('Consider alternative domain names to avoid potential registration issues')
                result['recommendations'].append('Ensure domain name is unique and not similar to existing registrations')
            
            logger.info(f"✅ ELIGIBILITY CHECK: {domain_name} analysis complete - Eligible: {result['eligible']}, Warnings: {len(result['warnings'])}, Risks: {len(result['risk_factors'])}")
            return result
            
        except Exception as e:
            logger.error(f"❌ ELIGIBILITY CHECK: Failed for {domain_name}: {e}")
            return {
                'eligible': False,
                'warnings': [f'Eligibility check failed: {str(e)}'],
                'recommendations': ['Contact support for assistance'],
                'risk_factors': ['System error during validation'],
                'availability_result': None
            }
    
    def _validate_domain_format(self, domain_name: str) -> bool:
        """
        Validate basic domain format requirements.
        """
        try:
            if not domain_name or not isinstance(domain_name, str):
                return False
            
            domain_name = domain_name.lower().strip()
            
            # Basic format validation
            if len(domain_name) < 3 or len(domain_name) > 253:
                return False
            
            if not '.' in domain_name:
                return False
            
            # Check for invalid characters
            import re
            if not re.match(r'^[a-z0-9.-]+$', domain_name):
                return False
            
            # Check for consecutive dots or dashes
            if '..' in domain_name or '--' in domain_name:
                return False
            
            # Check if starts or ends with invalid characters
            if domain_name.startswith('.') or domain_name.endswith('.') or domain_name.startswith('-') or domain_name.endswith('-'):
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Domain format validation error: {e}")
            return False
    
    async def _check_domain_similarity_risks(self, domain_name: str) -> List[str]:
        """
        Check for domain patterns that might trigger OpenProvider's duplicate detection.
        
        This addresses the core issue: '1roadhoppie.sbs' vs 'roadhoppie.sbs'
        """
        risks = []
        
        try:
            domain_parts = domain_name.lower().split('.')
            if len(domain_parts) < 2:
                return risks
            
            domain_base = domain_parts[0]
            tld = '.'.join(domain_parts[1:])
            
            # Pattern 1: Numeric prefix patterns (e.g., '1roadhoppie' vs 'roadhoppie')
            if len(domain_base) > 1 and domain_base[0].isdigit():
                base_without_number = domain_base.lstrip('0123456789')
                if len(base_without_number) > 0:
                    risks.append(f'Numeric prefix pattern detected: "{domain_base}" similar to "{base_without_number}"')
                    logger.warning(f"🚨 SIMILARITY RISK: {domain_name} has numeric prefix that may conflict with {base_without_number}.{tld}")
            
            # Pattern 2: Common character substitutions
            substitution_patterns = {
                '0': 'o',
                '1': 'l',
                '3': 'e',
                '4': 'a',
                '5': 's',
                '7': 't'
            }
            
            for char, replacement in substitution_patterns.items():
                if char in domain_base:
                    alternative = domain_base.replace(char, replacement)
                    if alternative != domain_base:
                        risks.append(f'Character substitution pattern: "{domain_base}" vs "{alternative}"')
            
            # Pattern 3: Common prefix/suffix additions
            common_prefixes = ['www', 'my', 'get', 'new', 'the', 'best', 'top']
            common_suffixes = ['app', 'site', 'web', 'net', 'online', 'shop']
            
            for prefix in common_prefixes:
                if domain_base.startswith(prefix) and len(domain_base) > len(prefix):
                    base_without_prefix = domain_base[len(prefix):]
                    risks.append(f'Common prefix pattern: "{domain_base}" vs "{base_without_prefix}"')
            
            for suffix in common_suffixes:
                if domain_base.endswith(suffix) and len(domain_base) > len(suffix):
                    base_without_suffix = domain_base[:-len(suffix)]
                    risks.append(f'Common suffix pattern: "{domain_base}" vs "{base_without_suffix}"')
            
            return risks
            
        except Exception as e:
            logger.error(f"❌ Similarity risk check failed: {e}")
            return ['Error analyzing domain similarity patterns']
    
    async def _check_registry_restrictions(self, domain_name: str) -> List[str]:
        """
        Check for TLD-specific or registry-specific restrictions.
        """
        warnings = []
        
        try:
            tld = domain_name.split('.')[-1].lower()
            
            # SBS TLD specific warnings (based on the original issue)
            if tld == 'sbs':
                warnings.append('.sbs domains may have stricter similarity detection')
                warnings.append('Ensure domain name is completely unique in .sbs registry')
            
            # Other TLD-specific warnings
            restricted_tlds = {
                'tv': 'Tuvalu domains may have geographic restrictions',
                'me': 'Montenegro domains may have identity verification requirements',
                'ly': 'Libya domains have strict content restrictions',
                'io': 'British Indian Ocean Territory domains are premium priced'
            }
            
            if tld in restricted_tlds:
                warnings.append(restricted_tlds[tld])
            
            return warnings
            
        except Exception as e:
            logger.error(f"❌ Registry restriction check failed: {e}")
            return ['Error checking registry restrictions']
    
    def _analyze_tld_risks(self, domain_name: str) -> List[str]:
        """
        Analyze TLD-specific risk factors for registration.
        """
        risks = []
        
        try:
            tld = domain_name.split('.')[-1].lower()
            
            # Premium TLDs with higher rejection rates
            premium_tlds = ['app', 'dev', 'page', 'new', 'nexus']
            if tld in premium_tlds:
                risks.append(f'.{tld} is a premium TLD with strict validation')
            
            # New TLDs with evolving policies
            new_tlds = ['sbs', 'store', 'online', 'site', 'tech']
            if tld in new_tlds:
                risks.append(f'.{tld} is a newer TLD with evolving registration policies')
            
            return risks
            
        except Exception as e:
            logger.error(f"❌ TLD risk analysis failed: {e}")
            return ['Error analyzing TLD risks']
    
    @monitor_performance("domain_availability_check")
    async def check_domain_availability(self, domain_name: str, contact_data: Optional[Dict[str, Any]] = None) -> Optional[Dict]:
        """Check if a domain is available for registration - OPTIMIZED VERSION with TLD validation and CACHING"""
        try:
            # CRITICAL: Check if TLD is supported before making any API calls
            # This prevents 500 errors from unsupported extensions like .sms
            from services.supported_tlds import is_supported_tld, get_unsupported_tld_message
            
            if not is_supported_tld(domain_name):
                logger.warning(f"🚫 BLOCKED: Unsupported TLD for domain {domain_name} - preventing API call")
                return {
                    'available': False,
                    'error': 'unsupported_tld',
                    'error_message': get_unsupported_tld_message(domain_name),
                    'premium': False,
                    'price_info': {
                        'create_price': 0,
                        'currency': 'USD',
                        'source': 'blocked_unsupported_tld'
                    }
                }
            
            # PERFORMANCE OPTIMIZATION: Check cache first to avoid duplicate API calls
            cached_result = _availability_cache.get(domain_name)
            if cached_result is not None:
                logger.info(f"⚡ CACHE HIT: Using cached availability for '{domain_name}' (avoiding 3+ second API call)")
                return cached_result
            
            if not self.username or not self.password:
                logger.warning("⚠️ OpenProvider credentials not configured")
                return None
            
            # Authenticate first to get bearer token (with caching)
            auth_success = await self.authenticate()
            if not auth_success:
                logger.error("❌ Failed to authenticate with OpenProvider")
                return None
            
            # Parse domain into name and extension
            try:
                domain_parts = self._parse_domain(domain_name)
            except ValueError as e:
                logger.error(f"❌ Domain parsing error: {e}")
                return None
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client")
                return None
                
            start_time = time.time()
            
            request_data = {
                'domains': [domain_parts],
                'with_price': True  # Request price in the same call
            }
            
            # Singapore .com.sg domains require additional data even for availability checks
            if domain_name.lower().endswith('.com.sg'):
                logger.info("🇸🇬 SINGAPORE DOMAIN: Including additional data for .com.sg availability check")
                singapore_additional_data = await self._build_singapore_additional_data(domain_name)
                if singapore_additional_data:
                    request_data['additional_data'] = singapore_additional_data
                else:
                    logger.error("❌ Failed to build Singapore additional data for availability check")
                    return {
                        'available': False,
                        'error': 'singapore_credentials_missing',
                        'error_message': 'Singapore .com.sg domains require company credentials (UEN, SingPass ID). Please contact support.'
                    }
            
            # USER INTERACTION LOG: Domain search query for anomaly detection
            logger.info(f"🔍 USER_DOMAIN_SEARCH: Checking availability for '{domain_name}' - potential user search activity")
            logger.info(f"📝 OpenProvider API: Checking domain availability for: {domain_name}")
            logger.debug(f"🌐 API URL: {self.base_url}/v1beta/domains/check")
            logger.debug(f"📤 Request data: {request_data}")
            
            response = await self._client.post(
                f"{self.base_url}/v1beta/domains/check",
                headers=self.headers,
                json=request_data
            )
            
            api_time = time.time() - start_time
            logger.info(f"📥 OpenProvider response status: {response.status_code} (took {api_time:.2f}s)")
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('code', 0) == 0:
                    domains_data = data.get('data', {}).get('results', [])
                    
                    if domains_data:
                        domain_info = domains_data[0]
                        available = domain_info.get('status') == 'free'
                        is_premium = domain_info.get('premium', False)
                        
                        # Extract pricing using optimized method
                        price_info = self._extract_price_from_domain_check(domain_info, domain_name)
                        
                        # Fallback to pricing API if domains/check didn't return pricing
                        if not price_info or price_info.get('create_price', 0) <= 0:
                            logger.info("💰 No price in domains/check; using pricing API fallback")
                            fallback = await self.get_domain_pricing(domain_name)
                            if fallback and fallback.get('create_price', 0) > 0:
                                price_info = {
                                    'create_price': fallback['create_price'],
                                    'currency': fallback.get('currency', 'USD'),
                                    'base_price_eur': fallback.get('base_price_eur', 0),
                                    'base_price_usd': fallback.get('base_price_usd', 0),
                                    'markup_applied': fallback.get('markup_applied', True),
                                    'minimum_enforced': fallback.get('minimum_enforced', False),
                                    'source': 'pricing_api_fallback'
                                }
                        
                        logger.info(f"✅ Domain {domain_name} - Available: {available}, Premium: {is_premium}, Price: ${price_info['create_price']:.2f}")
                        
                        # Run TLD-specific validation if available and contact data provided
                        tld_validation_info = {}
                        if TLD_VALIDATION_AVAILABLE and contact_data and _tld_validator is not None:
                            try:
                                tld = domain_name.split('.')[-1].lower()
                                if _tld_validator.has_specific_requirements(tld):
                                    logger.info(f"🔍 Running TLD validation for .{tld} domain availability check")
                                    validation_result = await _tld_validator.validate_tld_requirements(
                                        domain_name, contact_data
                                    )
                                    tld_validation_info = {
                                        'tld_validation': {
                                            'required': True,
                                            'tld': tld,
                                            'valid': validation_result.is_valid,
                                            'errors': validation_result.errors,
                                            'warnings': validation_result.warnings
                                        }
                                    }
                                    if not validation_result.is_valid:
                                        logger.warning(f"⚠️ TLD validation issues for {domain_name}: {validation_result.errors}")
                                else:
                                    tld_validation_info = {
                                        'tld_validation': {
                                            'required': False,
                                            'tld': tld
                                        }
                                    }
                            except Exception as e:
                                logger.error(f"❌ TLD validation error during availability check: {e}")
                                tld_validation_info = {
                                    'tld_validation': {
                                        'error': str(e)
                                    }
                                }
                        
                        result = {
                            'available': available,
                            'premium': is_premium,
                            'price_info': price_info
                        }
                        
                        # Add TLD validation info if available
                        if tld_validation_info:
                            result.update(tld_validation_info)
                        
                        # PERFORMANCE OPTIMIZATION: Cache the successful result for future use
                        _availability_cache.set(domain_name, result)
                        logger.info(f"💾 CACHE STORED: Availability result for '{domain_name}' cached (30min TTL) - future lookups will be instant")
                        
                        return result
                    else:
                        logger.warning(f"⚠️ No domain results returned for {domain_name}")
                        return None
                else:
                    error_message = data.get('desc', 'Unknown API error')
                    logger.error(f"❌ OpenProvider API error: {error_message}")
                    return None
            else:
                logger.error(f"❌ HTTP error {response.status_code} from OpenProvider API")
                try:
                    error_data = response.json()
                    logger.error(f"❌ Error details: {error_data}")
                except:
                    logger.error(f"❌ Error response: {response.text}")
                return None
                
        except asyncio.TimeoutError:
            logger.error(f"❌ OpenProvider API timeout after 15s for domain: {domain_name}")
            logger.error("❌ OpenProvider API performance is degraded - check API status at https://status.openprovider.eu")
            return None
        except httpx.TimeoutException as e:
            logger.error(f"❌ HTTP timeout in domain availability check for {domain_name}: {type(e).__name__}")
            logger.error(f"❌ Timeout details: connect={e}, read timeout likely exceeded")
            return None
        except Exception as e:
            logger.error(f"❌ Exception in domain availability check for {domain_name}: {type(e).__name__} - {str(e)}")
            logger.error(f"❌ Exception type: {type(e)}")
            return None
    
    async def check_domain_with_enhanced_validation(self, domain_name: str, contact_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Enhanced domain checking that combines availability and eligibility validation.
        
        This is the recommended method for checking domains before registration
        to prevent OpenProvider error 346 and similar issues.
        
        Returns:
            Dict with comprehensive domain analysis and recommendations
        """
        logger.info(f"🔍 ENHANCED CHECK: Starting comprehensive validation for {domain_name}")
        
        try:
            # Step 1: Check eligibility first (includes similarity detection)
            eligibility_result = await self.check_domain_registration_eligibility(domain_name, contact_data)
            
            # Step 2: Combine with availability data
            availability_data = eligibility_result.get('availability_result')
            
            # Step 3: Create comprehensive result
            result = {
                'domain_name': domain_name,
                'available': availability_data.get('available', False) if availability_data else False,
                'eligible_for_registration': eligibility_result.get('eligible', False),
                'price_info': availability_data.get('price_info') if availability_data else None,
                'premium': availability_data.get('premium', False) if availability_data else False,
                'warnings': eligibility_result.get('warnings', []),
                'recommendations': eligibility_result.get('recommendations', []),
                'risk_factors': eligibility_result.get('risk_factors', []),
                'validation_passed': True,
                'tld_validation': availability_data.get('tld_validation') if availability_data else None
            }
            
            # Step 4: Overall registration recommendation
            if result['available'] and result['eligible_for_registration'] and not result['warnings']:
                result['registration_recommendation'] = 'recommended'
                result['recommendation_message'] = 'Domain appears safe for registration'
            elif result['available'] and result['eligible_for_registration'] and result['warnings']:
                result['registration_recommendation'] = 'proceed_with_caution'
                result['recommendation_message'] = 'Domain available but has potential risk factors'
            else:
                result['registration_recommendation'] = 'not_recommended'
                result['recommendation_message'] = 'Domain not recommended for registration'
            
            logger.info(f"✅ ENHANCED CHECK: {domain_name} complete - Recommendation: {result['registration_recommendation']}")
            return result
            
        except Exception as e:
            logger.error(f"❌ ENHANCED CHECK: Failed for {domain_name}: {e}")
            return {
                'domain_name': domain_name,
                'available': False,
                'eligible_for_registration': False,
                'price_info': None,
                'premium': False,
                'warnings': [f'Enhanced validation failed: {str(e)}'],
                'recommendations': ['Contact support for assistance'],
                'risk_factors': ['System error during validation'],
                'validation_passed': False,
                'registration_recommendation': 'not_recommended',
                'recommendation_message': 'Unable to validate domain due to system error'
            }

    def _extract_price_from_domain_check(self, domain_info: Dict, domain_name: str, telegram_username: Optional[str] = None) -> Dict:
        """Extract and process pricing from domains/check response"""
        pricing_result = {
            'create_price': 0,
            'currency': 'USD',
            'base_price_eur': 0,
            'base_price_usd': 0,
            'markup_applied': False,
            'minimum_enforced': False,
            'source': 'domains_check_fallback'
        }
        
        try:
            # DEBUG: Log the entire domain_info to see what we're getting
            logger.info(f"🔍 DEBUG: Full domain_info for {domain_name}: {domain_info}")
            
            # Extract price from the actual OpenProvider response structure
            price_data = None
            
            # OpenProvider domains/check response has pricing in domain_info['price']
            if 'price' in domain_info and isinstance(domain_info['price'], dict):
                price_data = domain_info['price']
                logger.info(f"💰 Found price data in domain_info['price']: {price_data}")
            else:
                logger.warning(f"⚠️ No 'price' key found in domain_info. Available keys: {list(domain_info.keys())}")
                return pricing_result
            
            # OpenProvider price structure: price.reseller.price or price.product.price
            if price_data:
                base_price = 0
                currency = 'EUR'
                
                # Try reseller price first (preferred), then product price
                if 'reseller' in price_data and isinstance(price_data['reseller'], dict):
                    reseller_data = price_data['reseller']
                    if 'price' in reseller_data:
                        base_price = float(reseller_data['price'])
                        currency = reseller_data.get('currency', 'EUR')
                        logger.info(f"💰 Using reseller price from domains/check: {base_price} {currency}")
                elif 'product' in price_data and isinstance(price_data['product'], dict):
                    product_data = price_data['product']
                    if 'price' in product_data:
                        base_price = float(product_data['price'])
                        currency = product_data.get('currency', 'EUR')
                        logger.info(f"💰 Using product price from domains/check: {base_price} {currency}")
                
                if base_price > 0:
                    # Apply markup calculations directly with TLD-specific pricing
                    from pricing_utils import calculate_marked_up_price
                    # Extract TLD from domain name for TLD-specific surcharges
                    tld = domain_name.split('.')[-1] if '.' in domain_name else None
                    markup_result = calculate_marked_up_price(Decimal(str(base_price)), currency, tld=tld, telegram_username=telegram_username)
                    
                    pricing_result.update({
                        'create_price': markup_result['final_price'],
                        'currency': 'USD',  # Always return USD after markup
                        'base_price_eur': markup_result['base_price_eur'],
                        'base_price_usd': markup_result['base_price_usd'],
                        'markup_applied': markup_result['markup_applied'],
                        'minimum_enforced': markup_result['minimum_enforced'],
                        'tld_surcharge': markup_result.get('tld_surcharge', 0),
                        'source': 'domains_check_direct'
                    })
                    
                    logger.info(f"✅ Successfully extracted pricing from domains/check: ${pricing_result['create_price']:.2f} USD")
                    return pricing_result
                else:
                    logger.warning(f"⚠️ Price data found but no valid price extracted from: {price_data}")
            else:
                logger.warning(f"⚠️ Price data is None or empty")
            
        except Exception as e:
            logger.warning(f"⚠️ Error extracting price from domains/check response: {e}")
        
        logger.debug(f"💡 No price found in domains/check response, will use fallback pricing API")
        return pricing_result

    @monitor_performance("domain_pricing_check")
    async def get_domain_pricing(self, domain_name: str, is_api_purchase: bool = False, telegram_username: Optional[str] = None) -> Optional[Dict]:
        """Get pricing information for a domain - OPTIMIZED with caching
        
        Args:
            domain_name: Domain name to get pricing for
            is_api_purchase: If True, apply 10% API discount
        """
        try:
            if not self.username or not self.password:
                return None
            
            # Parse domain into name and extension
            try:
                domain_parts = self._parse_domain(domain_name)
            except ValueError as e:
                logger.error(f"❌ Domain parsing error: {e}")
                return None
            
            # Check TLD price cache first (but only if not API purchase, as we need to apply discount)
            tld = domain_parts['extension']
            if not is_api_purchase:
                cached_pricing = _tld_price_cache.get(tld)
                if cached_pricing:
                    logger.info(f"🚀 Using cached TLD pricing for {tld}: ${cached_pricing['create_price']:.2f}")
                    return {
                        'domain': domain_name,
                        **cached_pricing
                    }
            
            # Authenticate first to get bearer token (with caching)
            auth_success = await self.authenticate()
            if not auth_success:
                return None
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client")
                return None
            
            # Use dedicated pricing endpoint with optimized client
            response = await self._client.get(
                f"{self.base_url}/v1beta/domains/prices",
                headers=self.headers,
                params={
                    'domain.name': domain_parts['name'],
                    'domain.extension': domain_parts['extension'],
                    'operation': 'create',
                    'period': 1
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"🔍 Pricing API response: {data}")
                if data.get('code', 0) == 0:
                    price_data = data.get('data', {})
                    if 'price' in price_data:
                        # Extract price from dedicated pricing endpoint
                        price_info = price_data['price']
                        
                        # Try reseller price first, then product price
                        create_price = 0
                        currency = 'EUR'
                        
                        if 'reseller' in price_info and price_info['reseller']:
                            create_price = float(price_info['reseller']['price'])
                            currency = price_info['reseller'].get('currency', 'EUR')
                            logger.info(f"💰 Using reseller pricing: {create_price} {currency}")
                        elif 'product' in price_info and price_info['product']:
                            create_price = float(price_info['product']['price'])
                            currency = price_info['product'].get('currency', 'EUR')
                            logger.info(f"💰 Using product pricing: {create_price} {currency}")
                        
                        if create_price > 0:
                            # Apply markup calculations with TLD-specific pricing and API discount
                            from pricing_utils import calculate_marked_up_price
                            markup_result = calculate_marked_up_price(
                                Decimal(str(create_price)), 
                                currency, 
                                tld=tld,
                                is_api_purchase=is_api_purchase
                            )
                            
                            # Cache TLD pricing for future use (only for bot purchases, not API)
                            cache_data = {
                                'create_price': markup_result['final_price'],
                                'currency': 'USD',
                                'base_price_eur': markup_result['base_price_eur'],
                                'base_price_usd': markup_result['base_price_usd'],
                                'markup_applied': markup_result['markup_applied'],
                                'minimum_enforced': markup_result['minimum_enforced'],
                                'tld_surcharge': markup_result.get('tld_surcharge', 0),
                                'api_discount': markup_result.get('api_discount', 0),
                                'source': 'pricing_api'
                            }
                            
                            # Only cache non-API purchases
                            if not is_api_purchase:
                                _tld_price_cache.set(tld, cache_data)
                            
                            return {
                                'domain': domain_name,
                                **cache_data
                            }
            else:
                logger.error(f"❌ Pricing API request failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ Error getting domain pricing: {e}")
        
        return None

    def _parse_domain(self, domain_name: str) -> Dict[str, str]:
        """Parse domain name into name and extension parts with comprehensive RFC validation"""
        # First perform comprehensive validation
        validation_result = self.validate_domain_rfc_compliant(domain_name)
        if not validation_result['valid']:
            raise ValueError(validation_result['error'])
        
        parts = domain_name.strip().lower().split('.')
        if len(parts) < 2:
            raise ValueError(f"Domain must contain at least 2 parts separated by dots: {domain_name}")
        
        # List of known compound/second-level TLDs
        compound_tlds = [
            'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg', 'per.sg',  # Singapore
            'co.uk', 'org.uk', 'me.uk', 'ac.uk',  # UK
            'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',  # Australia
            'co.nz', 'net.nz', 'org.nz', 'ac.nz', 'govt.nz',  # New Zealand
            'com.br', 'net.br', 'org.br', 'gov.br',  # Brazil
            'co.za', 'org.za', 'net.za', 'ac.za', 'gov.za',  # South Africa
            'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in',  # India
        ]
        
        # Check if this domain uses a compound TLD
        domain_lower = domain_name.strip().lower()
        for compound_tld in compound_tlds:
            if domain_lower.endswith('.' + compound_tld):
                # Split at the compound TLD boundary
                name = domain_lower[:-len(compound_tld)-1]  # Remove .compound_tld
                extension = compound_tld
                if not name:
                    raise ValueError(f"Invalid domain: name part is empty for {domain_name}")
                return {
                    'name': name,
                    'extension': extension
                }
        
        # Standard TLD handling (single-level like .com, .net, .org)
        name = '.'.join(parts[:-1])
        extension = parts[-1]
        
        return {
            'name': name,
            'extension': extension
        }
    
    def validate_domain_rfc_compliant(self, domain_name: str) -> Dict[str, Any]:
        """Comprehensive RFC-compliant domain validation with detailed error reporting"""
        import re
        import idna
        
        if not domain_name or not isinstance(domain_name, str):
            return {'valid': False, 'error': 'Domain name is required and must be a string'}
        
        # Clean and normalize input
        domain_name = domain_name.strip()
        if not domain_name:
            return {'valid': False, 'error': 'Domain name cannot be empty'}
        
        # Handle IDN (Internationalized Domain Names) conversion
        try:
            # Convert Unicode domain to ASCII (punycode)
            ascii_domain = idna.encode(domain_name, uts46=True).decode('ascii')
        except (idna.core.IDNAError, UnicodeError, UnicodeDecodeError) as e:
            return {'valid': False, 'error': f'Invalid internationalized domain name: {str(e)}'}
        
        # Use ASCII version for all subsequent checks
        domain_to_validate = ascii_domain.lower()
        
        # RFC 1035/1123 total length limit (253 characters)
        if len(domain_to_validate) > 253:
            return {
                'valid': False, 
                'error': f'Domain name too long: {len(domain_to_validate)} characters (maximum: 253)'
            }
        
        # Check for minimum length
        if len(domain_to_validate) < 3:
            return {'valid': False, 'error': 'Domain name too short (minimum: 3 characters like "a.b")'}
        
        # Check for invalid characters or patterns
        if '..' in domain_to_validate:
            return {'valid': False, 'error': 'Domain name cannot contain consecutive dots'}
        
        if domain_to_validate.startswith('.') or domain_to_validate.endswith('.'):
            return {'valid': False, 'error': 'Domain name cannot start or end with a dot'}
        
        # Split into labels (parts between dots)
        labels = domain_to_validate.split('.')
        
        if len(labels) < 2:
            return {'valid': False, 'error': 'Domain must have at least 2 parts (e.g., "example.com")'}
        
        # Validate each label individually
        for i, label in enumerate(labels):
            label_type = 'TLD' if i == len(labels) - 1 else f'Label {i+1}'
            
            # RFC 1123 label length limit (63 characters per label)
            if len(label) > 63:
                return {
                    'valid': False,
                    'error': f'{label_type} too long: "{label}" ({len(label)} characters, maximum: 63)'
                }
            
            # Labels cannot be empty
            if len(label) == 0:
                return {'valid': False, 'error': f'{label_type} cannot be empty'}
            
            # Labels cannot start or end with hyphens
            if label.startswith('-') or label.endswith('-'):
                return {
                    'valid': False,
                    'error': f'{label_type} cannot start or end with hyphen: "{label}"'
                }
            
            # Check for valid characters only (a-z, 0-9, hyphens)
            if not re.match(r'^[a-z0-9-]+$', label):
                invalid_chars = [c for c in label if not re.match(r'[a-z0-9-]', c)]
                return {
                    'valid': False,
                    'error': f'{label_type} contains invalid characters: "{label}" (invalid: {", ".join(set(invalid_chars))})'
                }
        
        # TLD-specific validation
        tld = labels[-1]
        
        # TLD cannot be all numeric
        if tld.isdigit():
            return {'valid': False, 'error': f'TLD cannot be all numeric: "{tld}"'}
        
        # TLD should be at least 2 characters
        if len(tld) < 2:
            return {'valid': False, 'error': f'TLD too short: "{tld}" (minimum: 2 characters)'}
        
        # Additional domain-specific checks for common patterns
        if domain_to_validate.count('.') > 10:
            return {'valid': False, 'error': 'Domain has too many subdomains (maximum: 10 levels)'}
        
        # All validations passed
        return {
            'valid': True,
            'domain': domain_to_validate,
            'ascii_domain': ascii_domain,
            'original_domain': domain_name,
            'labels': labels,
            'tld': tld
        }
    
    async def _make_request_with_retry(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make HTTP request with retry logic and fallback mechanisms for domain operations"""
        max_retries = 3
        base_delay = 2.0
        
        for attempt in range(max_retries):
            try:
                await self._ensure_client()
                if self._client is None:
                    raise Exception("HTTP client initialization failed")
                
                # PERFORMANCE OPTIMIZATION: For domain registration, use fast timeout
                if 'domains.json' in url and method.upper() == 'POST':
                    custom_timeout = httpx.Timeout(
                        connect=3.0,   # Reduced from 5s to 3s for faster response
                        read=12.0,     # Reduced from 30s to 12s for better UX
                        write=6.0,     # Reduced from 10s to 6s
                        pool=4.0       # Reduced from 8s to 4s
                    )
                    kwargs['timeout'] = custom_timeout
                    logger.info(f"🕐 Using optimized 12s timeout for domain registration operation")
                
                # Make the request
                if method.upper() == 'GET':
                    response = await self._client.get(url, **kwargs)
                elif method.upper() == 'POST':
                    response = await self._client.post(url, **kwargs)
                elif method.upper() == 'PUT':
                    response = await self._client.put(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Success - return response
                return response
                
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout) as e:
                attempt_num = attempt + 1
                if attempt_num >= max_retries:
                    logger.error(f"❌ Request failed after {max_retries} attempts: {str(e)}")
                    raise
                
                delay = base_delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"⚠️ Request timeout (attempt {attempt_num}/{max_retries}), retrying in {delay}s...")
                await asyncio.sleep(delay)
                
                # Try HTTP/1.1 fallback on final attempt
                if attempt_num == 2:
                    logger.info("🔄 Falling back to HTTP/1.1 for compatibility")
                    await self._fallback_to_http1()
                    
            except Exception as e:
                logger.error(f"❌ Unexpected error during request: {str(e)}")
                raise
        
        # This should never be reached due to the raise statements above
        # but adding for type safety
        raise Exception("Request failed after all retries")
    
    async def _fallback_to_http1(self):
        """Fallback to HTTP/1.1 for compatibility issues"""
        try:
            if self._client and not self._client.is_closed:
                await self._client.aclose()
            
            # Reinitialize with HTTP/1.1
            limits = httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
                keepalive_expiry=30.0
            )
            
            timeout = httpx.Timeout(
                connect=6.0,     # Reduced from 10s to 6s
                read=45.0,       # Reduced from 90s to 45s for faster fallback
                write=10.0,      # Reduced from 15s to 10s
                pool=8.0         # Reduced from 10s to 8s
            )
            
            self._client = httpx.AsyncClient(
                http2=False,  # Disable HTTP/2
                limits=limits,
                timeout=timeout,
                headers={'User-Agent': f'{self._get_platform_name()}-Bot/1.0'},
                follow_redirects=True
            )
            logger.info("🔄 Switched to HTTP/1.1 client with 90s timeout for improved compatibility")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize HTTP/1.1 fallback: {str(e)}")
    
    async def register_domain(
        self, 
        domain_name: str, 
        contact_handle: str, 
        nameservers: Optional[List[str]] = None,
        contact_data: Optional[Dict[str, Any]] = None,
        tld_additional_params: Optional[Dict[str, Any]] = None,
        period: int = 1,
        auto_renew: bool = False,
        privacy_protection: bool = False
    ) -> Optional[Dict]:
        """Register a domain - CRITICAL METHOD with TLD-specific validation and additional data support"""
        try:
            if not self.username or not self.password:
                logger.error("❌ OpenProvider credentials not configured for domain registration")
                return None
            
            # Authenticate first to get bearer token
            if not self.bearer_token:
                auth_success = await self.authenticate()
                if not auth_success:
                    logger.error("❌ Failed to authenticate with OpenProvider for domain registration")
                    return None
            
            # Validate nameservers - should be Cloudflare nameservers
            if not nameservers or not isinstance(nameservers, list) or len(nameservers) == 0:
                logger.error(f"❌ No valid nameservers provided for {domain_name}")
                logger.error(f"   Received nameservers: {nameservers}")
                return None
            
            # Log nameservers being used for registration
            logger.info(f"🌐 Registering {domain_name} with nameservers: {nameservers}")
            
            # Validate nameservers are not dummy ones
            dummy_ns = ['ns1.example.com', 'ns2.example.com']
            if any(ns in dummy_ns for ns in nameservers):
                logger.error(f"❌ Dummy nameservers detected for {domain_name}: {nameservers}")
                return None
            
            # Validate Cloudflare nameservers format
            valid_cloudflare_patterns = ['.ns.cloudflare.com']
            is_cloudflare_ns = any(any(pattern in ns for pattern in valid_cloudflare_patterns) for ns in nameservers)
            if not is_cloudflare_ns:
                logger.warning(f"⚠️ Non-Cloudflare nameservers detected for {domain_name}: {nameservers}")
                # Continue anyway as they might be valid nameservers
            
            # Parse domain into name and extension
            try:
                domain_parts = self._parse_domain(domain_name)
                tld = domain_name.split('.')[-1].lower()
            except ValueError as e:
                logger.error(f"❌ Domain parsing error: {e}")
                return None
            
            # OPTIMIZATION: Fetch contact handles once for TLD-specific contact creation
            # This prevents duplicate API calls for .ca and .it domains
            cached_contact_handles = None
            needs_contact_fetch = (
                domain_name.lower().endswith('.ca') or 
                domain_name.lower().endswith('.it')
            )
            
            if needs_contact_fetch:
                logger.info(f"♻️ Pre-fetching contact handles for TLD-specific contact selection")
                cached_contact_handles = await self.get_contact_handles()
                logger.info(f"✅ Cached {len(cached_contact_handles) if cached_contact_handles else 0} contact handles")
            
            # CANADA .ca SPECIAL HANDLING
            is_canada_domain = domain_name.lower().endswith('.ca')
            canada_contact_handle = None
            
            if is_canada_domain:
                logger.info(f"🇨🇦 CANADIAN DOMAIN DETECTED: {domain_name} - using Canadian contact")
                canada_contact_handle = await self.get_or_create_canada_contact_handle(cached_contact_handles)
                
                if canada_contact_handle:
                    contact_handle = canada_contact_handle
                    logger.info(f"✅ Using Canadian contact handle for .ca registration: {contact_handle}")
                    logger.info(f"   • Address: 443 University Ave, Toronto, ON M5G 2H6")
                    logger.info(f"   • Meets CIRA Canadian presence requirement")
                else:
                    logger.error(f"❌ Failed to create Canadian contact handle for .ca domain")
                    return {
                        'success': False,
                        'error': 'CA_CONTACT_CREATION_FAILED',
                        'message': 'Failed to create Canadian contact handle for .ca domain registration'
                    }
            
            # SINGAPORE .com.sg/.sg SPECIAL HANDLING
            is_singapore_domain = domain_name.lower().endswith('.com.sg') or domain_name.lower().endswith('.sg')
            singapore_additional_data = None
            use_trustee_service = False
            
            if is_singapore_domain:
                logger.info(f"🇸🇬 SINGAPORE DOMAIN DETECTED: {domain_name} - checking registration method")
                
                # Check if direct registration is explicitly enabled
                use_direct_registration = os.environ.get('SINGAPORE_DIRECT_REGISTRATION', 'false').lower() == 'true'
                
                if use_direct_registration:
                    # Attempt direct registration with Singapore credentials
                    singapore_contact_handle = await self.get_or_create_singapore_contact_handle()
                    singapore_additional_data = await self._build_singapore_additional_data(domain_name)
                    
                    if singapore_contact_handle and singapore_additional_data:
                        # Direct registration successful
                        contact_handle = singapore_contact_handle
                        logger.info(f"✅ DIRECT REGISTRATION: Using Singapore-specific contact handle: {contact_handle}")
                        logger.info(f"✅ Singapore additional data prepared: {singapore_additional_data}")
                    else:
                        # Direct registration failed, fallback to trustee
                        use_trustee_service = True
                        logger.warning(f"⚠️ DIRECT REGISTRATION FAILED: Missing credentials, falling back to trustee service")
                        logger.info(f"🏢 TRUSTEE SERVICE: Using OpenProvider's free trustee service")
                        logger.info(f"   • OpenProvider will act as legal domain holder")
                        logger.info(f"   • You retain full control and usage rights")
                        logger.info(f"   • No additional charges for .com.sg/.sg trustee service")
                else:
                    # DEFAULT: Use trustee service (recommended for most users)
                    use_trustee_service = True
                    logger.info(f"🏢 TRUSTEE SERVICE (DEFAULT): Using OpenProvider's free trustee service")
                    logger.info(f"   • OpenProvider will act as legal domain holder")
                    logger.info(f"   • You retain full control and usage rights (DNS, nameservers, technical settings)")
                    logger.info(f"   • No additional charges for .com.sg/.sg trustee service")
                    logger.info(f"   • To use direct registration, set SINGAPORE_DIRECT_REGISTRATION=true")
            
            # ITALY .it SPECIAL HANDLING - Use trustee service
            is_italy_domain = domain_name.lower().endswith('.it')
            italy_contact_handle = None
            
            if is_italy_domain:
                logger.info(f"🇮🇹 ITALIAN DOMAIN DETECTED: {domain_name} - using trustee service")
                
                # Get or create Italian contact handle with trustee fiscal code (reuse cached handles)
                italy_contact_handle = await self.get_or_create_italy_contact_handle(cached_contact_handles)
                
                if italy_contact_handle:
                    contact_handle = italy_contact_handle
                    use_trustee_service = True
                    logger.info(f"✅ Using Italian contact handle for .it registration: {contact_handle}")
                    logger.info(f"🏢 ITALIAN COMPANY REGISTRATION: Using Vetrerie Riunite S.p.A. credentials")
                    logger.info(f"   • Company: Vetrerie Riunite S.p.A.")
                    logger.info(f"   • VAT/Fiscal Code: IT04126990961")
                    logger.info(f"   • Address: Via Calcinese 60, 37030 Colognola ai Colli (VR), Italy")
                    logger.info(f"   • All .it domains registered under this Italian company")
                else:
                    logger.error(f"❌ Failed to create Italian contact handle for .it domain")
                    return {
                        'success': False,
                        'error': 'IT_CONTACT_CREATION_FAILED',
                        'message': 'Failed to create Italian contact handle for .it domain registration'
                    }
            
            # FRANCE .fr SPECIAL HANDLING - Use Italian EU contact (confirmed working)
            is_france_domain = domain_name.lower().endswith('.fr')
            
            if is_france_domain:
                logger.info(f"🇫🇷 FRENCH DOMAIN DETECTED: {domain_name} - using Italian EU contact")
                # Get or create Italian contact handle
                italy_contact_handle = await self.get_or_create_italy_contact_handle(cached_contact_handles)
                
                if italy_contact_handle:
                    contact_handle = italy_contact_handle
                    logger.info(f"✅ Using Italian contact handle for .fr registration: {contact_handle}")
                    logger.info(f"🏢 ITALIAN COMPANY REGISTRATION: Using Vetrerie Riunite S.p.A. credentials")
                    logger.info(f"   • Company: Vetrerie Riunite S.p.A.")
                    logger.info(f"   • Fiscal Code: IT04126990961")
                    logger.info(f"   • Address: Via Caduti di Sabbiuno 29, 40011 Anzola dell'Emilia (BO), Italy")
                    logger.info(f"   • Valid EU company address accepted by .fr registry")
                    logger.info(f"   • No trustee service required")
                else:
                    logger.error(f"❌ Failed to get Italian contact handle for .fr domain")
                    return {
                        'success': False,
                        'error': 'CONTACT_CREATION_FAILED',
                        'message': f"Failed to create Italian contact for .fr domain registration"
                    }
            
            # CRITICAL: Run TLD-specific validation before registration
            tld_additional_data = None
            
            # Skip TLD validation for domains using trustee service or pre-validated contacts
            skip_tld_validation = use_trustee_service and (is_italy_domain or is_singapore_domain or is_france_domain)
            
            if skip_tld_validation:
                if is_italy_domain:
                    logger.info(f"⏭️ Skipping TLD validation for .it domain - fiscal code embedded in contact handle")
                else:
                    logger.info(f"⏭️ Skipping TLD validation for .{tld} domain - trustee service handles all requirements")
            
            if TLD_VALIDATION_AVAILABLE and not skip_tld_validation:
                try:
                    logger.info(f"🔍 Running comprehensive TLD validation for .{tld} domain registration")
                    
                    # Use provided contact data or fetch default contact for validation
                    validation_contact_data = contact_data
                    if not validation_contact_data:
                        # Use TLD-specific default contact data
                        if is_canada_domain:
                            # Canadian address for .ca domains (with US phone number)
                            validation_contact_data = {
                                'first_name': 'Hostbay',
                                'last_name': 'Services', 
                                'email': 'admin@hostbay.sbs',
                                'address': '443 University Ave',
                                'city': 'Toronto',
                                'state': 'ON',
                                'postal_code': 'M5G 2H6',
                                'country': 'CA',
                                'phone': '+15551234567',  # US phone - Canadian format rejected by OpenProvider
                                'organization': 'Hostbay Services'
                            }
                            logger.info(f"📝 Using Canadian contact data for .ca TLD validation")
                        else:
                            # Default US address for other domains
                            validation_contact_data = {
                                'first_name': 'Hostbay',
                                'last_name': 'Admin', 
                                'email': 'admin@hostbay.sbs',
                                'address': '123 Main Street',
                                'city': 'New York',
                                'state': 'NY',
                                'postal_code': '10001',
                                'country': 'US',
                                'phone': '+15551234567',
                                'organization': 'Hostbay Services'
                            }
                            logger.info(f"📝 Using default contact data for TLD validation")
                    
                    # Prepare additional parameters for TLD validation
                    validation_params = tld_additional_params or {}
                    
                    # Run TLD-specific validation using new instance-based approach
                    if _tld_validator is not None:
                        validation_result = await _tld_validator.validate(
                            tld,  # Pass TLD only, not full domain name
                            validation_contact_data,
                            nameservers,
                            validation_params  # This becomes 'extras' parameter
                        )
                    else:
                        # Fallback if validator is not available - create mock validation result
                        from services.tld_requirements import TLDValidationResult
                        validation_result = TLDValidationResult(
                            is_valid=True,
                            errors=[],
                            warnings=["TLD validator not available - skipping validation"],
                            additional_data=None
                        )
                        logger.warning(f"⚠️ TLD validator not available for domain {domain_name}, proceeding without validation")
                    
                    # Check validation results
                    if not validation_result.is_valid:
                        error_msg = f"TLD validation failed for {domain_name}: {'; '.join(validation_result.errors)}"
                        logger.error(f"❌ {error_msg}")
                        
                        # Send admin alert for TLD validation failure
                        await send_critical_alert(
                            "TLD_Validation",
                            f"TLD validation failed before registration: {domain_name}",
                            "domain_registration",
                            {
                                "domain": domain_name,
                                "tld": tld,
                                "validation_errors": validation_result.errors,
                                "validation_warnings": validation_result.warnings,
                                "contact_data": validation_contact_data,
                                "nameservers": nameservers
                            }
                        )
                        
                        return {
                            'success': False,
                            'error': 'TLD_VALIDATION_FAILED',
                            'message': error_msg,
                            'validation_errors': validation_result.errors,
                            'validation_warnings': validation_result.warnings
                        }
                    
                    # Log successful validation
                    logger.info(f"✅ TLD validation passed for .{tld} domain: {domain_name}")
                    if validation_result.warnings:
                        logger.warning(f"⚠️ TLD validation warnings: {validation_result.warnings}")
                    
                    # Extract additional data for registration if provided
                    if validation_result.additional_data:
                        tld_additional_data = validation_result.additional_data
                        logger.info(f"📦 TLD additional data for registration: {tld_additional_data}")
                    
                except Exception as e:
                    logger.error(f"❌ TLD validation exception for {domain_name}: {e}")
                    
                    # Send admin alert for TLD validation exception
                    await send_error_alert(
                        "TLD_Validation",
                        f"TLD validation exception during registration: {domain_name}",
                        "domain_registration", 
                        {
                            "domain": domain_name,
                            "exception": str(e),
                            "contact_handle": contact_handle,
                            "nameservers": nameservers
                        }
                    )
                    
                    # Depending on TLD, we might want to fail hard or continue
                    if tld == 'de':  # Critical nameserver validation for .de
                        return {
                            'success': False,
                            'error': 'TLD_VALIDATION_EXCEPTION',
                            'message': f"Critical TLD validation failed for .{tld} domain: {str(e)}"
                        }
                    else:
                        logger.warning(f"⚠️ Continuing registration despite TLD validation exception for .{tld}")
            else:
                logger.info(f"📝 TLD validation not available - proceeding with standard registration")
            
            # Build registration data with TLD-specific additional data
            # Allow tld_additional_params to override contact handles for custom WHOIS data
            owner_handle = tld_additional_params.get('owner_handle', contact_handle) if tld_additional_params else contact_handle
            admin_handle = tld_additional_params.get('admin_handle', contact_handle) if tld_additional_params else contact_handle
            tech_handle = tld_additional_params.get('tech_handle', contact_handle) if tld_additional_params else contact_handle
            billing_handle = tld_additional_params.get('billing_handle', contact_handle) if tld_additional_params else contact_handle
            
            registration_data = {
                'domain': domain_parts,
                'period': period,  # Registration period in years
                'autorenew': 'on' if auto_renew else 'off',  # Auto-renewal setting
                'unit': 'y',  # Yearly registration
                'owner_handle': owner_handle,
                'admin_handle': admin_handle,
                'tech_handle': tech_handle,
                'billing_handle': billing_handle,
                'name_servers': [{'name': ns, 'seq_nr': i + 1} for i, ns in enumerate(nameservers)],
                'use_domicile': use_trustee_service,  # Enable trustee service for .fr, .it, .sg domains
                'is_private_whois_enabled': privacy_protection  # WHOIS privacy protection
            }
            
            # FRANCE .fr: Using Italian contact, no trustee service needed
            # Italian EU company address is accepted by .fr registry without domicile service
            if is_france_domain:
                logger.info(f"✅ FRANCE .fr: Using Italian EU contact (no trustee service required)")
                logger.info(f"   • Contact: {contact_handle}")
                logger.info(f"   • Trustee service: Disabled (using real EU company address)")
            
            # Add Singapore additional data if this is a .com.sg domain
            elif is_singapore_domain and singapore_additional_data:
                registration_data['additional_data'] = singapore_additional_data
                logger.info(f"🇸🇬 Added Singapore additional data for .com.sg: {singapore_additional_data}")
            
            # Add Canadian .ca domain additional data (uses direct additional_data, not extension)
            elif is_canada_domain and tld_additional_data:
                registration_data['additional_data'] = tld_additional_data
                logger.info(f"🇨🇦 Added Canadian additional data for .ca: {tld_additional_data}")
            
            # For .it domains, fiscal code is embedded in the contact handle (not registration payload)
            # OpenProvider requires social_security_number to be set at contact creation time
            if is_italy_domain:
                logger.info(f"🇮🇹 .it domain registration - fiscal code is in contact handle, not additional_data")
                logger.info(f"🏢 Contact handle includes Italian company fiscal code (IT04126990961)")
                logger.info(f"   • Company: Vetrerie Riunite S.p.A.")
                logger.info(f"   • Fiscal code validated by OpenProvider at contact level")
            
            # Add TLD-specific extension additional data if available (.us, etc.)
            if tld_additional_data and 'extension_additional_data' in tld_additional_data:
                registration_data['extension_additional_data'] = tld_additional_data['extension_additional_data']
                logger.info(f"🔧 Added extension_additional_data for .{tld}: {registration_data['extension_additional_data']}")
            
            # Log complete registration data for debugging (with TLD validation info)
            logger.info(f"🔍 OPENPROVIDER REGISTRATION DATA (TLD-VALIDATED):")
            logger.info(f"   Domain: {domain_name} (TLD: .{tld})")
            logger.info(f"   Domain Parts: {domain_parts}")
            logger.info(f"   Contact Handle: {contact_handle}")
            logger.info(f"   Nameservers: {nameservers}")
            logger.info(f"   Singapore Domain: {is_singapore_domain}")
            logger.info(f"   Trustee Service Enabled: {use_trustee_service}")
            logger.info(f"   Singapore Additional Data: {singapore_additional_data}")
            logger.info(f"   TLD Additional Data: {tld_additional_data}")
            logger.info(f"   Full Payload: {registration_data}")
            
            # Use retry mechanism with extended timeout for domain registration
            response = await self._make_request_with_retry(
                'POST',
                f"{self.base_url}/v1beta/domains",
                headers=self.headers,
                json=registration_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    domain_data = data.get('data', {})
                    logger.info(f"✅ Domain registered successfully: {domain_name}")
                    logger.info(f"   OpenProvider ID: {domain_data.get('id')}")
                    logger.info(f"   Status: {domain_data.get('status')}")
                    
                    registration_method = "trustee service" if use_trustee_service else "direct registration"
                    return {
                        'success': True,
                        'domain_id': domain_data.get('id'),
                        'status': domain_data.get('status'),
                        'nameservers': nameservers,
                        'tld': tld,
                        'tld_validation_passed': True,
                        'tld_additional_data_used': bool(tld_additional_data),
                        'trustee_service_used': use_trustee_service,
                        'message': f"Domain {domain_name} registered successfully via {registration_method}"
                    }
                else:
                    errors = data.get('desc', 'Unknown registration error')
                    logger.error(f"❌ Domain registration failed: {errors}")
                    # Send admin alert for domain registration failure
                    await send_critical_alert(
                        "OpenProvider",
                        f"Domain registration failed for {domain_name}: {errors}",
                        "domain_registration",
                        {
                            "domain": domain_name,
                            "contact_handle": contact_handle,
                            "nameservers": nameservers,
                            "api_error": errors,
                            "api_response": data
                        }
                    )
                    return {
                        'success': False,
                        'error': errors,
                        'message': f"Failed to register {domain_name}: {errors}"
                    }
            else:
                error_text = response.text
                logger.error(f"❌ Domain registration API failed: HTTP {response.status_code}")
                logger.error(f"   Raw response body: {error_text}")
                
                # Parse error response for specific handling
                error_details = {}
                duplicate_domain_error = False
                domicile_error = False
                try:
                    error_json = response.json()
                    error_details = error_json
                    error_code = error_json.get('code', 'N/A')
                    error_desc = error_json.get('desc', 'No description available')
                    
                    # Log full error details from OpenProvider
                    logger.error(f"   OpenProvider error code: {error_code}")
                    logger.error(f"   OpenProvider error description: {error_desc}")
                    
                    # Check for duplicate domain error (code 346) - code alone is sufficient
                    if error_json.get('code') == 346:
                        duplicate_domain_error = True
                        logger.warning(f"⚠️ Duplicate domain registration attempt for {domain_name} - domain may already be registered")
                    # Fallback: check description text only if code is missing (for robustness)
                    elif not error_json.get('code') and 'duplicate domain' in str(error_json.get('desc', '')).lower():
                        duplicate_domain_error = True
                        logger.warning(f"⚠️ Duplicate domain registration detected via description text for {domain_name}")
                    
                    # Check for domicile/trustee service errors (code 1944)
                    if error_json.get('code') == 1944 and is_france_domain:
                        domicile_error = True
                        logger.warning(f"⚠️ Domicile service error for .fr domain {domain_name} (code 1944)")
                except Exception as parse_error:
                    # Log JSON parsing failures for debugging
                    logger.error(f"   Failed to parse JSON error response: {parse_error}")
                    logger.error(f"   Response content type: {response.headers.get('content-type', 'unknown')}")
                
                # FRANCE .fr ERROR: This should not happen with Italian contact
                # Italian EU company address is confirmed working for .fr domains
                if domicile_error:
                    logger.error(f"❌ FRANCE .fr REGISTRATION ERROR: Failed to register {domain_name}")
                    logger.error(f"   Error code 1944 received (unexpected with Italian EU contact)")
                    logger.error(f"   Using Italian company: Vetrerie Riunite S.p.A.")
                    logger.error(f"   This may indicate an OpenProvider API issue")
                
                # Handle duplicate domain error specifically
                if duplicate_domain_error:
                    # CRITICAL FIX: Check if we actually own this domain in OpenProvider
                    # This handles the case where registration succeeded but response timed out/was retried
                    logger.info(f"🔍 Duplicate domain error - checking if {domain_name} exists in our OpenProvider account...")
                    try:
                        existing_domain = await self.get_domain_details(domain_name)
                        if existing_domain:
                            # Domain exists in our account - this IS a success!
                            domain_id = existing_domain.get('id')
                            domain_status = existing_domain.get('status', 'unknown')
                            expires_at = existing_domain.get('expiration_date')
                            
                            logger.info(f"✅ DUPLICATE DOMAIN RECOVERY: {domain_name} found in our account!")
                            logger.info(f"   Domain ID: {domain_id}, Status: {domain_status}, Expires: {expires_at}")
                            
                            # Send info alert about recovered registration
                            await send_info_alert(
                                "OpenProvider",
                                f"Recovered duplicate domain registration: {domain_name}",
                                "domain_registration",
                                {
                                    "domain": domain_name,
                                    "domain_id": domain_id,
                                    "status": domain_status,
                                    "expires_at": expires_at,
                                    "recovery_reason": "duplicate_domain_error_346_but_domain_exists_in_account",
                                    "contact_handle": contact_handle,
                                    "nameservers": nameservers
                                }
                            )
                            
                            # Return SUCCESS since we own the domain
                            return {
                                'success': True,
                                'domain_id': domain_id,
                                'domain_name': domain_name,
                                'status': domain_status,
                                'expiration_date': expires_at,
                                'nameservers': nameservers,
                                'registration_method': 'duplicate_recovery',
                                'message': f"Domain {domain_name} confirmed in account (recovered from duplicate error)"
                            }
                    except Exception as check_error:
                        logger.warning(f"⚠️ Could not verify domain ownership during duplicate check: {check_error}")
                    
                    # If we can't verify ownership, fall back to failure (original behavior)
                    await send_warning_alert(
                        "OpenProvider",
                        f"Duplicate domain registration attempt for {domain_name}",
                        "domain_registration",
                        {
                            "domain": domain_name,
                            "error_code": error_details.get('code'),
                            "error_description": error_details.get('desc'),
                            "contact_handle": contact_handle,
                            "nameservers": nameservers,
                            "ownership_verified": False
                        }
                    )
                    return {
                        'success': False,
                        'error': 'DUPLICATE_DOMAIN',
                        'error_code': 346,
                        'message': f"Domain {domain_name} appears to already be registered. Please check domain status or contact support."
                    }
                else:
                    # Send critical alert for other API failures
                    await send_critical_alert(
                        "OpenProvider",
                        f"Domain registration API failure for {domain_name}",
                        "external_api",
                        {
                            "domain": domain_name,
                            "http_status": response.status_code,
                            "api_response": error_text,
                            "error_details": error_details,
                            "contact_handle": contact_handle,
                            "nameservers": nameservers
                        }
                    )
                    return {
                        'success': False,
                        'error': f"HTTP {response.status_code}",
                        'message': f"API request failed for {domain_name}"
                    }
                
        except Exception as e:
            logger.error(f"❌ Error during domain registration for {domain_name}: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            # Send admin alert for domain registration exception
            await send_critical_alert(
                "OpenProvider",
                f"Domain registration exception for {domain_name}: {str(e)}",
                "domain_registration",
                {
                    "domain": domain_name,
                    "exception": str(e),
                    "traceback": traceback.format_exc(),
                    "contact_handle": contact_handle,
                    "nameservers": nameservers
                }
            )
            return {
                'success': False,
                'error': str(e),
                'message': f"Registration exception for {domain_name}"
            }

    async def get_domain_details(self, domain_name: str) -> Optional[Dict]:
        """Get domain details including the numerical ID required for updates"""
        try:
            if not self.username or not self.password:
                logger.error("❌ OpenProvider credentials not configured")
                return None
            
            # Authenticate first to get bearer token
            if not self.bearer_token:
                auth_success = await self.authenticate()
                if not auth_success:
                    logger.error("❌ Failed to authenticate with OpenProvider")
                    return None
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client")
                return None
            
            # Search for domain in domain list
            response = await self._client.get(
                f"{self.base_url}/v1beta/domains",
                headers=self.headers,
                params={'full_name': domain_name, 'limit': 1}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    results = data.get('data', {}).get('results', [])
                    if results:
                        domain_info = results[0]
                        logger.info(f"✅ Found domain details for {domain_name}: ID={domain_info.get('id')}")
                        return domain_info
                    else:
                        logger.error(f"❌ Domain {domain_name} not found in OpenProvider account")
                        return None
                else:
                    logger.error(f"❌ OpenProvider API error: {data.get('desc', 'Unknown error')}")
                    return None
            else:
                logger.error(f"❌ Failed to fetch domain details: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error fetching domain details for {domain_name}: {e}")
            return None

    async def get_domain_status(self, domain_name: str) -> Optional[Dict]:
        """Get current domain status from OpenProvider API"""
        try:
            domain_info = await self.get_domain_details(domain_name)
            if not domain_info:
                logger.error(f"❌ Could not fetch domain details for status check: {domain_name}")
                return None
            
            status = domain_info.get('status', 'unknown').lower()
            logger.info(f"📊 Domain {domain_name} current status: {status}")
            
            return {
                'domain_name': domain_name,
                'status': status,
                'is_active': status in ['active', 'ok', 'ready', 'act'],
                'is_transitional': status in ['pending', 'pending-create', 'pending-update', 'pending-transfer'],
                'is_prohibited': status in ['client-hold', 'server-hold', 'client-update-prohibited', 'server-update-prohibited'],
                'can_update_nameservers': status in ['active', 'ok', 'ready', 'act'],
                'raw_info': domain_info
            }
        except Exception as e:
            logger.error(f"❌ Error getting domain status for {domain_name}: {e}")
            await send_error_alert(
                "OpenProvider Status Check",
                f"Failed to get domain status: {domain_name}",
                "domain_registration",
                {
                    "domain": domain_name,
                    "error": str(e)
                }
            )
            return None
    
    async def update_nameservers(self, domain_name: str, nameservers: List[str], domain_id: Optional[str] = None) -> Optional[Dict]:
        """Update nameservers for an existing domain via OpenProvider API with status checking and retry logic"""
        try:
            if not self.username or not self.password:
                logger.error("❌ OpenProvider credentials not configured for nameserver update")
                return None
            
            if not nameservers or not isinstance(nameservers, list) or len(nameservers) == 0:
                logger.error(f"❌ No valid nameservers provided for {domain_name}")
                return None
            
            # Log nameserver update attempt
            logger.info(f"🌐 Updating nameservers for {domain_name} to: {nameservers}")
            
            # CRITICAL FIX: Check domain status before attempting update
            logger.info(f"🔍 Checking domain status before nameserver update: {domain_name}")
            domain_status = await self.get_domain_status(domain_name)
            if not domain_status:
                return {
                    'success': False,
                    'error': 'DOMAIN_STATUS_CHECK_FAILED',
                    'message': f"Could not verify domain status for {domain_name}. Please try again later.",
                    'user_action': "Contact support if this issue persists."
                }
            
            current_status = domain_status['status']
            
            # Check if domain is in a prohibited state
            if domain_status['is_prohibited']:
                logger.warning(f"⚠️ Domain {domain_name} is in prohibited state: {current_status}")
                
                # AUTO-DETECT RESTRICTION: Save to database for ALL TLDs
                try:
                    from database import set_domain_restriction
                    await set_domain_restriction(
                        domain_name, 
                        'status_prohibited',
                        f"Domain status: {current_status} - cannot update nameservers"
                    )
                    logger.info(f"🔒 Auto-saved restriction for {domain_name} (prohibited status: {current_status})")
                except Exception as restrict_err:
                    logger.warning(f"⚠️ Could not save restriction for {domain_name}: {restrict_err}")
                
                await send_warning_alert(
                    "OpenProvider Domain Status",
                    f"Domain nameserver update blocked - prohibited status: {domain_name}",
                    "domain_registration",
                    {
                        "domain": domain_name,
                        "current_status": current_status,
                        "attempted_nameservers": nameservers,
                        "is_prohibited": True
                    }
                )
                return {
                    'success': False,
                    'error': 'DOMAIN_STATUS_PROHIBITED',
                    'message': f"Cannot update nameservers for {domain_name} because the domain is in a restricted state ({current_status}).",
                    'user_action': f"Your domain is currently {current_status}. Please wait for the domain to become active or contact support.",
                    'current_status': current_status,
                    'retry_suggested': False
                }
            
            # Check if domain is ready for nameserver updates
            if not domain_status['can_update_nameservers']:
                logger.info(f"⏳ Domain {domain_name} is not ready for updates: {current_status}")
                
                # If domain is transitional, suggest retry with backoff
                if domain_status['is_transitional']:
                    return {
                        'success': False,
                        'error': 'DOMAIN_STATUS_TRANSITIONAL',
                        'message': f"Domain {domain_name} is currently being processed ({current_status}). Please wait a few minutes and try again.",
                        'user_action': f"Your domain is being processed ({current_status}). This usually takes 5-15 minutes. Please try again later.",
                        'current_status': current_status,
                        'retry_suggested': True,
                        'retry_delay_seconds': 300  # 5 minutes
                    }
                else:
                    return {
                        'success': False,
                        'error': 'DOMAIN_STATUS_INVALID',
                        'message': f"Domain {domain_name} status does not allow nameserver updates: {current_status}",
                        'user_action': f"Your domain status ({current_status}) does not allow nameserver changes. Please contact support.",
                        'current_status': current_status,
                        'retry_suggested': False
                    }
            
            logger.info(f"✅ Domain {domain_name} status OK for nameserver update: {current_status}")
            
            # CRITICAL: For .de domains, DENIC requires NS consistency checks
            # We must handle both directions:
            # 1. Switching TO external Cloudflare: delete our zone first
            # 2. Switching BACK to our Cloudflare: create zone first
            if domain_name.lower().endswith('.de'):
                logger.info(f"🇩🇪 German .de domain detected: {domain_name} - checking for Cloudflare zone requirements")
                try:
                    from services.cloudflare import cloudflare
                    
                    # Check if target nameservers are external Cloudflare (different account)
                    # Use async version to ensure nameserver cache is primed
                    if await cloudflare.is_external_cloudflare_nameserver_async(nameservers):
                        logger.info(f"🔄 External Cloudflare NS detected for .de domain, initiating zone handoff")
                        
                        # Perform zone handoff (export records, delete our zone)
                        handoff_result = await cloudflare.prepare_zone_handoff(domain_name, nameservers)
                        
                        if handoff_result.get('handoff_required'):
                            if handoff_result.get('success') and handoff_result.get('zone_deleted'):
                                logger.info(f"✅ Zone handoff successful for {domain_name}")
                                logger.info(f"   Exported {handoff_result.get('exported_count', 0)} DNS records as backup")
                                
                                # Send admin notification about zone handoff
                                await send_info_alert(
                                    "Cloudflare Zone Handoff",
                                    f"Zone deleted for .de domain transfer to external Cloudflare: {domain_name}",
                                    "domain_registration",
                                    {
                                        "domain": domain_name,
                                        "new_nameservers": nameservers,
                                        "exported_records_count": handoff_result.get('exported_count', 0),
                                        "previous_nameservers": handoff_result.get('previous_nameservers', []),
                                        "reason": "DENIC NS consistency requirement for .de domains"
                                    }
                                )
                            else:
                                # Zone handoff failed - cannot proceed
                                error_msg = handoff_result.get('error', 'Zone deletion failed')
                                logger.error(f"❌ Zone handoff failed for {domain_name}: {error_msg}")
                                
                                await send_error_alert(
                                    "Cloudflare Zone Handoff Failed",
                                    f"Could not delete zone for .de domain transfer: {domain_name}",
                                    "external_api",
                                    {
                                        "domain": domain_name,
                                        "target_nameservers": nameservers,
                                        "error": error_msg,
                                        "issue": "DENIC will reject NS update due to inconsistent NS records"
                                    }
                                )
                                
                                return {
                                    'success': False,
                                    'error': 'CLOUDFLARE_ZONE_HANDOFF_FAILED',
                                    'message': f"Cannot update .de domain to external Cloudflare nameservers. Zone cleanup required.",
                                    'user_action': "Please contact support - the system needs to remove the existing DNS zone before switching to your Cloudflare account.",
                                    'technical_details': error_msg,
                                    'retry_suggested': False
                                }
                        else:
                            logger.info(f"ℹ️ No zone handoff needed: {handoff_result.get('reason', 'N/A')}")
                    
                    # Check if switching BACK to our Cloudflare nameservers (use async to prime cache)
                    elif await cloudflare.is_our_cloudflare_nameserver_async(nameservers):
                        logger.info(f"🔄 HostBay Cloudflare NS detected for .de domain, initiating zone return")
                        
                        # Perform zone return (create zone if needed)
                        return_result = await cloudflare.prepare_zone_return(domain_name, nameservers)
                        
                        if return_result.get('zone_return_required'):
                            if return_result.get('success'):
                                if return_result.get('zone_created'):
                                    logger.info(f"✅ Zone return successful - zone created for {domain_name}")
                                    
                                    # Send admin notification about zone recreation
                                    await send_info_alert(
                                        "Cloudflare Zone Restored",
                                        f"Zone created for .de domain returning to HostBay Cloudflare: {domain_name}",
                                        "domain_registration",
                                        {
                                            "domain": domain_name,
                                            "new_nameservers": nameservers,
                                            "zone_id": return_result.get('zone_id'),
                                            "reason": "DENIC NS consistency requirement - zone recreated for return to HostBay"
                                        }
                                    )
                                else:
                                    logger.info(f"✅ Zone already exists for {domain_name}")
                            else:
                                # Zone return failed - cannot proceed
                                error_msg = return_result.get('error', 'Zone creation failed')
                                logger.error(f"❌ Zone return failed for {domain_name}: {error_msg}")
                                
                                await send_error_alert(
                                    "Cloudflare Zone Return Failed",
                                    f"Could not create zone for .de domain returning to HostBay: {domain_name}",
                                    "external_api",
                                    {
                                        "domain": domain_name,
                                        "target_nameservers": nameservers,
                                        "error": error_msg,
                                        "issue": "DENIC will reject NS update if zone doesn't exist"
                                    }
                                )
                                
                                return {
                                    'success': False,
                                    'error': 'CLOUDFLARE_ZONE_RETURN_FAILED',
                                    'message': f"Cannot update .de domain to HostBay Cloudflare nameservers. Zone creation required.",
                                    'user_action': "Please contact support - the system needs to create a DNS zone before switching back.",
                                    'technical_details': error_msg,
                                    'retry_suggested': False
                                }
                        else:
                            logger.info(f"ℹ️ No zone return needed: {return_result.get('reason', 'N/A')}")
                            
                except ImportError:
                    logger.warning("⚠️ Cloudflare service not available for zone handoff check")
                except Exception as e:
                    logger.error(f"❌ Zone handoff/return check error for {domain_name}: {e}")
                    # Continue with update attempt - may fail with DENIC error but that's handled below
            
            # Use domain info already fetched during status check for efficiency
            domain_info = domain_status.get('raw_info')
            if not domain_info:
                logger.error(f"❌ No domain info found for {domain_name}")
                return None
            numerical_id = domain_info.get('id')
            if not numerical_id:
                logger.error(f"❌ No domain ID found for {domain_name}")
                return None
            
            # Parse domain for the request body
            domain_parts = domain_name.split('.')
            name = '.'.join(domain_parts[:-1])
            extension = domain_parts[-1]
            
            # Build nameserver payload with glue record support (IP resolution)
            nameserver_payload, resolution_errors = await self._build_nameserver_payload(nameservers, domain_name)
            
            # If glue record IP resolution failed, return error to user
            if resolution_errors:
                error_detail = "; ".join(resolution_errors)
                logger.error(f"❌ Glue record IP resolution failed for {domain_name}: {error_detail}")
                
                # Send admin alert about glue record resolution failure
                await send_warning_alert(
                    "Glue Record IP Resolution Failed",
                    f"Failed to resolve IP addresses for glue records: {domain_name}",
                    "external_api",
                    {
                        "domain": domain_name,
                        "nameservers": nameservers,
                        "errors": resolution_errors
                    }
                )
                
                return {
                    'success': False,
                    'error': 'GLUE_RECORD_RESOLUTION_FAILED',
                    'message': f"Cannot update nameservers for {domain_name} because the custom nameservers could not be resolved.",
                    'user_action': f"Your nameservers ({', '.join([ns for ns in nameservers if self._is_glue_record(ns, domain_name)])}) are under your domain name and require IP addresses. Please ensure these nameservers have valid DNS records before updating.",
                    'details': error_detail,
                    'retry_suggested': True
                }
            
            # Prepare complete domain update data according to OpenProvider API docs
            update_data = {
                'domain': {
                    'name': name,
                    'extension': extension
                },
                'name_servers': nameserver_payload,
                # Include existing contact handles from domain info
                'owner_handle': domain_info.get('owner_handle'),
                'admin_handle': domain_info.get('admin_handle'),
                'tech_handle': domain_info.get('tech_handle'),
                'billing_handle': domain_info.get('billing_handle')
            }
            
            logger.info(f"📤 Sending nameserver update request for {domain_name}")
            logger.info(f"   Domain ID: {numerical_id}")
            logger.info(f"   Nameservers: {nameservers}")
            
            # Use PUT request with correct OpenProvider URL format: /v1beta/domains/{id}
            api_url = f"{self.base_url}/v1beta/domains/{numerical_id}"
            logger.info(f"   API URL: {api_url}")
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client for nameserver update")
                return {
                    'success': False,
                    'error': 'HTTP client initialization failed',
                    'message': f"Failed to initialize client for nameserver update on {domain_name}"
                }
            
            # Execute nameserver update with enhanced error handling
            response = await self._make_nameserver_update_request(
                api_url, update_data, domain_name, nameservers
            )
            
            # Handle response with comprehensive error analysis
            return await self._handle_nameserver_update_response(
                response, domain_name, nameservers, api_url, update_data
            )
                
        except Exception as e:
            logger.error(f"❌ Error during nameserver update for {domain_name}: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            
            # Send admin alert for unexpected exceptions
            await send_error_alert(
                "OpenProvider Nameserver Update",
                f"Unexpected exception during nameserver update: {domain_name}",
                "external_api",
                {
                    "domain": domain_name,
                    "nameservers": nameservers,
                    "exception": str(e),
                    "traceback": traceback.format_exc()
                }
            )
            
            return {
                'success': False,
                'error': 'NAMESERVER_UPDATE_EXCEPTION',
                'message': f"An unexpected error occurred while updating nameservers for {domain_name}. Our team has been notified.",
                'user_action': "Please try again in a few minutes. If the problem persists, contact support."
            }
    
    async def _make_nameserver_update_request(self, api_url: str, update_data: Dict, domain_name: str, nameservers: List[str]) -> httpx.Response:
        """Make nameserver update request with retry logic for transient failures"""
        max_retries = 3
        base_delay = 2.0
        
        for attempt in range(max_retries):
            try:
                logger.info(f"🔄 Nameserver update attempt {attempt + 1}/{max_retries} for {domain_name}")
                
                client = await self._ensure_client()
                response = await client.put(
                    api_url,
                    headers=self.headers,
                    json=update_data,
                    timeout=httpx.Timeout(30.0)  # 30 second timeout for nameserver updates
                )
                
                # Return response immediately for status code analysis
                return response
                
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout) as e:
                attempt_num = attempt + 1
                if attempt_num >= max_retries:
                    logger.error(f"❌ Nameserver update request timeout after {max_retries} attempts: {domain_name}")
                    raise
                
                delay = base_delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"⏳ Request timeout (attempt {attempt_num}/{max_retries}), retrying in {delay}s...")
                await asyncio.sleep(delay)
                
            except Exception as e:
                logger.error(f"❌ Nameserver update request failed: {str(e)}")
                raise
        
        # Should never reach here due to raises above
        raise Exception("Request failed after all retries")
    
    async def _handle_nameserver_update_response(self, response: httpx.Response, domain_name: str, nameservers: List[str], api_url: str, update_data: Dict) -> Dict:
        """Handle nameserver update response with specific error code 366, 399, and 245 handling"""
        try:
            # OpenProvider sometimes returns HTTP 500 with error details in JSON body
            # Always try to parse JSON first to extract error codes
            data = None
            api_code = None
            
            try:
                data = response.json()
                api_code = data.get('code', 0)
            except:
                # If JSON parsing fails, handle as HTTP error below
                data = None
                api_code = None
            
            # Handle successful HTTP 200 with code 0
            if response.status_code == 200 and api_code == 0:
                logger.info(f"✅ Nameservers updated successfully for {domain_name}")
                
                # AUTO-CLEAR RESTRICTION: If update succeeds, domain is no longer restricted
                try:
                    from database import clear_domain_restriction
                    await clear_domain_restriction(domain_name)
                    logger.info(f"🔓 Cleared any previous restriction for {domain_name} (update succeeded)")
                except Exception as clear_err:
                    logger.debug(f"Could not clear restriction for {domain_name}: {clear_err}")
                
                return {
                    'success': True,
                    'domain_name': domain_name,
                    'nameservers': nameservers,
                    'message': f"Nameservers updated successfully for {domain_name}!",
                    'user_action': "Your domain nameservers have been updated. DNS changes may take up to 24 hours to fully propagate."
                }
            
            # Check if we have API error codes (can be in HTTP 200 or HTTP 500 responses)
            if data and api_code:
                # CRITICAL FIX: Handle OpenProvider error code 366 and similar prohibited status errors
                if api_code == 366:
                    error_desc = data.get('desc', 'This action is prohibited for current domain status')
                    logger.error(f"❌ OpenProvider Error 366 - Domain status prohibited: {domain_name} - {error_desc}")
                    
                    # AUTO-DETECT RESTRICTION: Save to database for ALL TLDs
                    try:
                        from database import set_domain_restriction
                        await set_domain_restriction(
                            domain_name, 
                            'prohibited_status',
                            f"OpenProvider Error 366: {error_desc}"
                        )
                        logger.info(f"🔒 Auto-saved restriction for {domain_name} (Error 366)")
                    except Exception as restrict_err:
                        logger.warning(f"⚠️ Could not save restriction for {domain_name}: {restrict_err}")
                    
                    # Send admin alert for error 366 - critical domain status issue
                    await send_critical_alert(
                        "OpenProvider Error 366",
                        f"Domain nameserver update blocked by prohibited status: {domain_name}",
                        "external_api",
                        {
                            "domain": domain_name,
                            "error_code": 366,
                            "error_description": error_desc,
                            "attempted_nameservers": nameservers,
                            "api_url": api_url,
                            "requires_manual_intervention": True
                        }
                    )
                    
                    return {
                        'success': False,
                        'error': 'DOMAIN_STATUS_PROHIBITED_366',
                        'error_code': 366,
                        'message': f"Cannot update nameservers for {domain_name} due to domain status restrictions.",
                        'user_action': f"Your domain is in a restricted state that prevents nameserver changes. Please contact support for assistance. (Error: {error_desc})",
                        'technical_details': error_desc,
                        'requires_support': True,
                        'retry_suggested': False
                    }
                
                # Handle other prohibited status error codes
                elif api_code in [365, 367, 368, 1000, 1001]:  # Common prohibited status codes
                    error_desc = data.get('desc', f'Domain operation prohibited (code {api_code})')
                    logger.error(f"❌ OpenProvider prohibited status error {api_code}: {domain_name} - {error_desc}")
                    
                    # AUTO-DETECT RESTRICTION: Save permanent restrictions to database for ALL TLDs
                    # (368, 1000, 1001 are permanent; 365, 367 are often temporary)
                    if api_code in [368, 1000, 1001]:
                        try:
                            from database import set_domain_restriction
                            await set_domain_restriction(
                                domain_name, 
                                'prohibited_operation',
                                f"OpenProvider Error {api_code}: {error_desc}"
                            )
                            logger.info(f"🔒 Auto-saved restriction for {domain_name} (Error {api_code})")
                        except Exception as restrict_err:
                            logger.warning(f"⚠️ Could not save restriction for {domain_name}: {restrict_err}")
                    
                    # Send admin alert for prohibited status errors
                    await send_warning_alert(
                        "OpenProvider Prohibited Status",
                        f"Domain operation prohibited (code {api_code}): {domain_name}",
                        "external_api",
                        {
                            "domain": domain_name,
                            "error_code": api_code,
                            "error_description": error_desc,
                            "attempted_nameservers": nameservers
                        }
                    )
                    
                    return {
                        'success': False,
                        'error': f'DOMAIN_OPERATION_PROHIBITED_{api_code}',
                        'error_code': api_code,
                        'message': f"Cannot update nameservers for {domain_name} due to current domain restrictions.",
                        'user_action': f"Your domain has restrictions that prevent this operation. Please wait or contact support. (Error code: {api_code})",
                        'technical_details': error_desc,
                        'retry_suggested': api_code in [365, 367],  # Some codes may be temporary
                        'retry_delay_seconds': 1800 if api_code in [365, 367] else None  # 30 minutes for retryable errors
                    }
                
                # Handle transient errors that should be retried
                elif api_code in [503, 504, 429, 500]:  # Server errors and rate limits
                    error_desc = data.get('desc', f'Temporary server error (code {api_code})')
                    logger.warning(f"⚠️ OpenProvider temporary error {api_code}: {domain_name} - {error_desc}")
                    
                    return {
                        'success': False,
                        'error': f'TEMPORARY_ERROR_{api_code}',
                        'error_code': api_code,
                        'message': f"Temporary issue updating nameservers for {domain_name}. Please try again in a few minutes.",
                        'user_action': "There was a temporary server issue. Please wait a few minutes and try again.",
                        'technical_details': error_desc,
                        'retry_suggested': True,
                        'retry_delay_seconds': 300  # 5 minutes
                    }
                
                # Handle error 524: Domain update failed (DENIC NS consistency errors for .de domains)
                elif api_code == 524:
                    error_desc = data.get('desc', 'Domain update failed')
                    error_data = data.get('data', '')
                    
                    # Check if this is a DENIC NS consistency error for German .de domains
                    is_de_domain = domain_name.endswith('.de')
                    is_ns_consistency_error = 'Inconsistent set of NS RRs' in error_data or 'Nameserver error: ERROR: 118' in error_data
                    
                    if is_de_domain and is_ns_consistency_error:
                        logger.error(f"❌ German .de domain NS consistency error for {domain_name}")
                        logger.error(f"   DENIC Error 118: {error_data}")
                        
                        # Parse DENIC error to extract the CORRECT nameservers from the error message
                        # Format: "(ns.cloudflare.com, IP, ['correct_ns1.ns.cloudflare.com', 'correct_ns2.ns.cloudflare.com'])"
                        correct_nameservers = None
                        user_action_msg = ""
                        
                        import re
                        ns_match = re.search(r"\['([^']+)',\s*'([^']+)'\]", error_data)
                        if ns_match:
                            correct_nameservers = [ns_match.group(1), ns_match.group(2)]
                            logger.info(f"📋 DENIC reports correct nameservers: {correct_nameservers}")
                            user_action_msg = (
                                f"The nameservers you entered don't match your Cloudflare zone. "
                                f"Your Cloudflare zone uses: {correct_nameservers[0]} and {correct_nameservers[1]}. "
                                f"Please use these nameservers instead, or check your Cloudflare account to find the correct nameservers for your domain."
                            )
                        else:
                            user_action_msg = (
                                f"For .de domains, the nameservers must exactly match your Cloudflare zone. "
                                f"Please log into your Cloudflare account, find this domain, and use the nameservers shown there. "
                                f"Each Cloudflare zone has a unique pair of nameservers."
                            )
                        
                        # Send admin alert with correct nameservers if found
                        alert_data = {
                            "domain": domain_name,
                            "error_code": 524,
                            "denic_error": "ERROR 118 - Inconsistent NS RRs",
                            "error_description": error_desc,
                            "error_details": error_data,
                            "attempted_nameservers": nameservers,
                            "issue": "User provided wrong Cloudflare nameservers for their zone",
                            "diagnosis": "Each Cloudflare zone has unique NS pair - user used wrong pair"
                        }
                        if correct_nameservers:
                            alert_data["correct_nameservers_from_denic"] = correct_nameservers
                            alert_data["solution"] = f"User should use {correct_nameservers[0]} and {correct_nameservers[1]}"
                        
                        await send_error_alert(
                            "DENIC NS Consistency Error",
                            f"German .de domain nameserver update failed - wrong NS pair: {domain_name}",
                            "external_api",
                            alert_data
                        )
                        
                        result = {
                            'success': False,
                            'error': 'DENIC_NS_CONSISTENCY_ERROR',
                            'error_code': 524,
                            'denic_error': 'ERROR 118',
                            'message': f"German .de domain nameserver update failed - wrong nameservers provided.",
                            'user_action': user_action_msg,
                            'technical_details': error_data,
                            'retry_suggested': True,
                            'retry_delay_seconds': 60,  # Just 1 minute - user needs to fix input, not wait
                            'requires_correct_nameservers': True
                        }
                        if correct_nameservers:
                            result['correct_nameservers'] = correct_nameservers
                        
                        return result
                    else:
                        # Generic 524 error (not DENIC-specific)
                        logger.error(f"❌ OpenProvider error 524 for {domain_name}: {error_desc}")
                        
                        await send_error_alert(
                            "OpenProvider Error 524",
                            f"Domain update failed: {domain_name}",
                            "external_api",
                            {
                                "domain": domain_name,
                                "error_code": 524,
                                "error_description": error_desc,
                                "error_details": error_data,
                                "attempted_nameservers": nameservers
                            }
                        )
                        
                        return {
                            'success': False,
                            'error': 'DOMAIN_UPDATE_FAILED_524',
                            'error_code': 524,
                            'message': f"Domain update failed for {domain_name}.",
                            'user_action': f"The registrar rejected the nameserver update. Please contact support for assistance. (Error: {error_desc})",
                            'technical_details': error_data,
                            'retry_suggested': False
                        }
                
                # Handle error 399: Nameserver authorization error (glue record issues)
                elif api_code == 399:
                    error_desc = data.get('desc', 'Nameserver authorization error')
                    error_data = data.get('data', '')
                    
                    logger.error(f"❌ OpenProvider error 399 - Nameserver authorization error: {domain_name}")
                    logger.error(f"   Error details: {error_data}")
                    
                    # Check if this is a glue record authorization issue
                    is_glue_auth_error = 'Registrar does not own the parent domain' in error_data or 'Authorization error' in error_data
                    
                    if is_glue_auth_error:
                        await send_warning_alert(
                            "Nameserver Authorization Error",
                            f"Cannot create glue records for nameservers: {domain_name}",
                            "external_api",
                            {
                                "domain": domain_name,
                                "error_code": 399,
                                "error_description": error_desc,
                                "error_details": error_data,
                                "attempted_nameservers": nameservers,
                                "issue": "Nameservers are under a parent domain not owned by this registrar"
                            }
                        )
                        
                        return {
                            'success': False,
                            'error': 'NAMESERVER_AUTHORIZATION_ERROR',
                            'error_code': 399,
                            'message': f"Cannot use these nameservers for {domain_name} - authorization error.",
                            'user_action': f"The nameservers you're trying to use ({', '.join(nameservers)}) are under a parent domain that this registrar doesn't control. You can only use these nameservers if: 1) You own the parent domain through this registrar, OR 2) You use nameservers from a different domain/provider (like ns1.hostingprovider.com).",
                            'technical_details': error_data,
                            'retry_suggested': False,
                            'requires_different_nameservers': True
                        }
                    else:
                        # Generic 399 error
                        await send_error_alert(
                            "OpenProvider Error 399",
                            f"Nameserver update authorization error: {domain_name}",
                            "external_api",
                            {
                                "domain": domain_name,
                                "error_code": 399,
                                "error_description": error_desc,
                                "error_details": error_data,
                                "attempted_nameservers": nameservers
                            }
                        )
                        
                        return {
                            'success': False,
                            'error': f'API_ERROR_399',
                            'error_code': 399,
                            'message': f"Authorization error updating nameservers for {domain_name}.",
                            'user_action': f"There was an authorization issue with the nameserver update. Please try different nameservers or contact support. (Error: {error_desc})",
                            'technical_details': error_data,
                            'retry_suggested': False
                        }
                
                # Handle error 245: Invalid nameserver format/values
                elif api_code == 245:
                    error_desc = data.get('desc', 'Nameserver-update failed')
                    error_data = data.get('data', '')
                    
                    logger.error(f"❌ OpenProvider error 245 - Invalid nameserver values: {domain_name}")
                    logger.error(f"   Attempted nameservers: {nameservers}")
                    
                    return {
                        'success': False,
                        'error': 'INVALID_NAMESERVER_VALUES',
                        'error_code': 245,
                        'message': f"Invalid nameserver values for {domain_name}. Nameservers must be valid hostnames.",
                        'user_action': f"The nameserver values you provided are not valid. Please provide fully qualified domain names (e.g., ns1.example.com, ns2.example.com). Do not use placeholder values like 'string'.",
                        'technical_details': f"Attempted nameservers: {', '.join(nameservers)}",
                        'retry_suggested': False
                        }
                
                # Handle other API errors
                else:
                    error_desc = data.get('desc', f'Unknown API error (code {api_code})')
                    logger.error(f"❌ OpenProvider API error {api_code}: {domain_name} - {error_desc}")
                    
                    # Send admin alert for unknown API errors
                    await send_error_alert(
                        "OpenProvider API Error",
                        f"Unknown API error during nameserver update: {domain_name}",
                        "external_api",
                        {
                            "domain": domain_name,
                            "error_code": api_code,
                            "error_description": error_desc,
                            "attempted_nameservers": nameservers,
                            "response_data": data
                        }
                    )
                    
                    return {
                        'success': False,
                        'error': f'API_ERROR_{api_code}',
                        'error_code': api_code,
                        'message': f"Failed to update nameservers for {domain_name}. Our team has been notified.",
                        'user_action': f"There was an issue with the nameserver update. Please try again later or contact support. (Error: {error_desc})",
                        'technical_details': error_desc,
                        'retry_suggested': True,
                        'retry_delay_seconds': 600  # 10 minutes
                    }
            
            # Handle HTTP-level errors
            else:
                error_text = response.text
                logger.error(f"❌ Nameserver update HTTP error: {response.status_code} - {error_text}")
                logger.error(f"   Request URL: {api_url}")
                logger.error(f"   Request Body: {update_data}")
                
                # Send admin alert for HTTP errors
                await send_error_alert(
                    "OpenProvider HTTP Error",
                    f"HTTP error during nameserver update: {domain_name}",
                    "external_api",
                    {
                        "domain": domain_name,
                        "http_status": response.status_code,
                        "response_body": error_text,
                        "request_url": api_url,
                        "request_data": update_data
                    }
                )
                
                return {
                    'success': False,
                    'error': f'HTTP_ERROR_{response.status_code}',
                    'message': f"Server error occurred while updating nameservers for {domain_name}.",
                    'user_action': "There was a server communication issue. Please try again in a few minutes.",
                    'retry_suggested': response.status_code in [502, 503, 504],
                    'retry_delay_seconds': 300 if response.status_code in [502, 503, 504] else None
                }
                
        except Exception as e:
            logger.error(f"❌ Error parsing nameserver update response: {e}")
            return {
                'success': False,
                'error': 'RESPONSE_PARSING_ERROR',
                'message': f"Error processing server response for {domain_name}.",
                'user_action': "There was an issue processing the server response. Please try again."
            }

    async def check_and_recover_domain_status(self, domain_name: str) -> Dict:
        """Check domain status and attempt recovery for stuck domains"""
        try:
            logger.info(f"🔍 Checking domain status for recovery: {domain_name}")
            
            status_info = await self.get_domain_status(domain_name)
            if not status_info:
                return {
                    'recoverable': False,
                    'error': 'STATUS_CHECK_FAILED',
                    'message': 'Could not check domain status'
                }
            
            current_status = status_info['status']
            
            # Check if domain is stuck in transitional state for too long
            if status_info['is_transitional']:
                # In a real implementation, you would check how long the domain has been in this state
                logger.warning(f"⚠️ Domain {domain_name} stuck in transitional state: {current_status}")
                
                # Send alert for stuck domain
                await send_warning_alert(
                    "Domain Status Monitoring",
                    f"Domain stuck in transitional state: {domain_name}",
                    "domain_registration",
                    {
                        "domain": domain_name,
                        "current_status": current_status,
                        "requires_monitoring": True
                    }
                )
                
                return {
                    'recoverable': True,
                    'status': current_status,
                    'message': f'Domain is in transitional state: {current_status}',
                    'recommended_action': 'wait_and_retry',
                    'retry_delay_seconds': 900  # 15 minutes
                }
            
            # Check if domain is prohibited
            elif status_info['is_prohibited']:
                logger.error(f"❌ Domain {domain_name} is in prohibited state: {current_status}")
                
                # Send alert for prohibited domain
                await send_critical_alert(
                    "Domain Status Critical",
                    f"Domain in prohibited state requiring intervention: {domain_name}",
                    "domain_registration",
                    {
                        "domain": domain_name,
                        "current_status": current_status,
                        "requires_manual_intervention": True
                    }
                )
                
                return {
                    'recoverable': False,
                    'status': current_status,
                    'message': f'Domain is in prohibited state: {current_status}',
                    'recommended_action': 'contact_support',
                    'requires_manual_intervention': True
                }
            
            # Domain status is OK
            else:
                logger.info(f"✅ Domain {domain_name} status is healthy: {current_status}")
                return {
                    'recoverable': True,
                    'status': current_status,
                    'message': f'Domain status is healthy: {current_status}',
                    'recommended_action': 'proceed'
                }
                
        except Exception as e:
            logger.error(f"❌ Error during domain status recovery check: {e}")
            return {
                'recoverable': False,
                'error': 'RECOVERY_CHECK_FAILED',
                'message': f'Failed to check domain recovery status: {str(e)}'
            }
    
    async def update_nameservers_with_retry(self, domain_name: str, nameservers: List[str], domain_id: Optional[str] = None) -> Optional[Dict]:
        """Update nameservers with intelligent retry logic for transitional states"""
        global _retry_manager
        
        logger.info(f"🔄 Starting nameserver update with retry logic for {domain_name}")
        last_result = None
        
        for attempt in range(_retry_manager.max_retries):
            try:
                logger.info(f"🔄 Nameserver update attempt {attempt + 1}/{_retry_manager.max_retries} for {domain_name}")
                
                # Attempt the nameserver update
                result = await self.update_nameservers(domain_name, nameservers, domain_id)
                
                # If successful, return immediately
                if result and result.get('success'):
                    logger.info(f"✅ Nameserver update successful on attempt {attempt + 1} for {domain_name}")
                    return result
                
                # Analyze failure and determine retry strategy
                if not result:
                    logger.error(f"❌ Nameserver update returned None on attempt {attempt + 1}")
                    break
                
                last_result = result
                error_code = result.get('error_code')
                error_type = self._classify_error_type(result.get('error', ''), error_code)
                
                # Check if we should retry
                should_retry = _retry_manager.should_retry(error_code, error_type, attempt)
                if not should_retry:
                    logger.info(f"🚫 No retry recommended for error type '{error_type}' (code: {error_code})")
                    break
                
                # Calculate retry delay
                retry_delay = _retry_manager.calculate_retry_delay(attempt, error_type)
                logger.info(f"⏳ Retrying nameserver update in {retry_delay} seconds (attempt {attempt + 1}/{_retry_manager.max_retries})")
                
                # Send admin alert for retry attempts after first failure
                if attempt == 1:  # Send alert on second attempt
                    await send_warning_alert(
                        "Nameserver Update Retry",
                        f"Nameserver update retrying after failure: {domain_name}",
                        "external_api",
                        {
                            "domain": domain_name,
                            "error_type": error_type,
                            "error_code": error_code,
                            "attempt_number": attempt + 1,
                            "retry_delay_seconds": retry_delay,
                            "nameservers": nameservers
                        }
                    )
                
                # Wait before retry
                await asyncio.sleep(retry_delay)
                
            except Exception as e:
                logger.error(f"❌ Exception during nameserver update retry attempt {attempt + 1}: {e}")
                if attempt == _retry_manager.max_retries - 1:  # Last attempt
                    await send_critical_alert(
                        "Nameserver Update Retry Failed",
                        f"All nameserver update retries exhausted: {domain_name}",
                        "external_api",
                        {
                            "domain": domain_name,
                            "total_attempts": _retry_manager.max_retries,
                            "final_exception": str(e),
                            "nameservers": nameservers
                        }
                    )
                    break
        
        # All retries exhausted - return last result with retry information
        if last_result:
            last_result['retry_attempts'] = _retry_manager.max_retries
            last_result['retry_exhausted'] = True
            if not last_result.get('user_action'):
                last_result['user_action'] = f"Multiple attempts to update nameservers failed. Please contact support for assistance with {domain_name}."
        else:
            last_result = {
                'success': False,
                'error': 'RETRY_EXHAUSTED',
                'message': f"All attempts to update nameservers for {domain_name} have failed.",
                'user_action': "Please contact support for assistance with this domain.",
                'retry_attempts': _retry_manager.max_retries,
                'retry_exhausted': True
            }
        
        logger.error(f"❌ All nameserver update retries exhausted for {domain_name}")
        return last_result
    
    def _classify_error_type(self, error_message: str, error_code: Optional[int]) -> str:
        """Classify error type for retry strategy"""
        if error_code == 366:
            return 'prohibited'
        elif error_code in [365, 367, 368]:
            return 'transitional'
        elif error_code in [429]:
            return 'rate_limit'
        elif error_code in [500, 502, 503, 504]:
            return 'server_error'
        elif 'TRANSITIONAL' in error_message:
            return 'transitional'
        elif 'PROHIBITED' in error_message:
            return 'prohibited'
        elif 'TIMEOUT' in error_message:
            return 'timeout'
        else:
            return 'general'
    
    async def create_contact_handle(self, contact_info: Dict) -> Optional[str]:
        """Create a contact handle for domain registration"""
        try:
            if not self.username or not self.password:
                return None
            
            # Authenticate first to get bearer token
            if not self.bearer_token:
                auth_success = await self.authenticate()
                if not auth_success:
                    return None
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client for contact creation")
                return None

            # Format phone number and log for debugging
            phone_formatted = self._format_phone_for_openprovider(contact_info.get('phone', '+15551234567'))
            logger.info(f"📞 DEBUG: Phone input: {contact_info.get('phone')}")
            logger.info(f"📞 DEBUG: Phone formatted: {phone_formatted}")

            # Build request payload
            request_payload = {
                'name': {
                    'first_name': contact_info.get('first_name', ''),
                    'last_name': contact_info.get('last_name', '')
                },
                'address': {
                    'street': contact_info.get('address', ''),
                    'city': contact_info.get('city', ''),
                    'state': contact_info.get('state', ''),
                    'zipcode': contact_info.get('postal_code', ''),
                    'country': contact_info.get('country', 'US')
                },
                'phone': phone_formatted,
                'email': contact_info.get('email', ''),
                'company_name': contact_info.get('organization', '')
            }
            
            # Add VAT number for companies if provided
            if contact_info.get('vat'):
                request_payload['vat'] = contact_info.get('vat')
                logger.info(f"🏢 DEBUG: Added VAT number to contact: {contact_info.get('vat')}")
            
            # Add social security number for Italian domains if provided
            if contact_info.get('social_security_number'):
                request_payload['additional_data'] = {
                    'social_security_number': contact_info.get('social_security_number')
                }
                logger.info(f"🇮🇹 DEBUG: Added fiscal code to contact: {contact_info.get('social_security_number')}")

            logger.info(f"📦 DEBUG: Full request payload: {request_payload}")

            response = await self._client.post(
                f"{self.base_url}/v1beta/customers",
                headers=self.headers,
                json=request_payload
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    handle = data.get('data', {}).get('handle')
                    logger.info(f"✅ Contact handle created: {handle}")
                    return handle
                else:
                    error_msg = data.get('desc', 'Unknown contact creation error')
                    logger.error(f"❌ Contact creation failed: {error_msg}")
                    # Send admin alert for contact handle creation failure
                    await send_error_alert(
                        "OpenProvider",
                        f"Contact handle creation failed: {error_msg}",
                        "domain_registration",
                        {
                            "contact_info": contact_info,
                            "api_response": data,
                            "error_code": data.get('code')
                        }
                    )
            else:
                # Handle non-200 HTTP status codes
                error_text = response.text
                logger.error(f"❌ Contact creation HTTP error: status_code={response.status_code}")
                logger.error(f"   Raw response body: {error_text}")
                
                # Try to parse JSON error response for detailed error information
                error_details = {}
                try:
                    error_json = response.json()
                    error_details = error_json
                    error_code = error_json.get('code', 'N/A')
                    error_desc = error_json.get('desc', 'No description')
                    logger.error(f"   Error code: {error_code}")
                    logger.error(f"   Error description: {error_desc}")
                except Exception as parse_error:
                    logger.error(f"   Failed to parse JSON error response: {parse_error}")
                
                # Send admin alert for HTTP-level failures
                await send_error_alert(
                    "OpenProvider",
                    f"Contact creation HTTP {response.status_code} error",
                    "external_api",
                    {
                        "contact_info": contact_info,
                        "http_status": response.status_code,
                        "raw_response": error_text,
                        "error_details": error_details
                    }
                )
                    
        except Exception as e:
            logger.error(f"❌ Error creating contact handle: {e}")
            # Send admin alert for contact handle creation exception
            await send_critical_alert(
                "OpenProvider",
                f"Contact handle creation exception: {str(e)}",
                "domain_registration",
                {
                    "contact_info": contact_info,
                    "exception": str(e)
                }
            )
        
        return None
    
    async def get_contact_handles(self) -> List[str]:
        """Get list of existing contact handles from OpenProvider"""
        try:
            if not self.username or not self.password:
                return []
            
            # Authenticate first to get bearer token
            if not self.bearer_token:
                auth_success = await self.authenticate()
                if not auth_success:
                    return []
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client for contact list")
                return []

            response = await self._client.get(
                f"{self.base_url}/v1beta/customers",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    customers = data.get('data', {}).get('results', [])
                    handles = [customer.get('handle') for customer in customers if customer.get('handle')]
                    logger.info(f"✅ Found {len(handles)} contact handles: {handles}")
                    return handles
                else:
                    logger.error(f"❌ Failed to get contact handles: {data}")
            else:
                logger.error(f"❌ OpenProvider contact API failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ Error getting contact handles: {e}")
        
        return []
    
    async def get_or_create_singapore_contact_handle(self) -> Optional[str]:
        """
        Get or create a contact handle specifically for Singapore .com.sg domain registration.
        Uses Singapore company credentials from environment variables.
        """
        try:
            singapore_uen = os.getenv('SINGAPORE_COMPANY_UEN')
            singapore_company_name = os.getenv('SINGAPORE_COMPANY_NAME')
            singapore_admin_email = os.getenv('SINGAPORE_ADMIN_EMAIL')
            singapore_address = os.getenv('SINGAPORE_COMPANY_ADDRESS')
            singapore_postal_code = os.getenv('SINGAPORE_COMPANY_POSTAL_CODE')
            singapore_singpass_id = os.getenv('SINGAPORE_ADMIN_SINGPASS_ID')
            
            missing_creds = []
            if not singapore_uen:
                missing_creds.append('SINGAPORE_COMPANY_UEN')
            if not singapore_company_name:
                missing_creds.append('SINGAPORE_COMPANY_NAME')
            if not singapore_admin_email:
                missing_creds.append('SINGAPORE_ADMIN_EMAIL')
            if not singapore_address:
                missing_creds.append('SINGAPORE_COMPANY_ADDRESS')
            if not singapore_postal_code:
                missing_creds.append('SINGAPORE_COMPANY_POSTAL_CODE')
            if not singapore_singpass_id:
                missing_creds.append('SINGAPORE_ADMIN_SINGPASS_ID')
            
            if missing_creds:
                error_msg = f"Missing Singapore credentials: {', '.join(missing_creds)}"
                logger.error(f"❌ {error_msg}")
                return None
            
            logger.info(f"🇸🇬 Creating Singapore contact handle for .com.sg domain registration")
            logger.info(f"   Company: {singapore_company_name}")
            logger.info(f"   UEN: {singapore_uen}")
            
            last_name_value = singapore_company_name[:30] if singapore_company_name and len(singapore_company_name) > 30 else singapore_company_name or 'Company'
            
            singapore_contact = {
                'first_name': 'Admin',
                'last_name': last_name_value,
                'email': singapore_admin_email,
                'address': singapore_address,
                'city': 'Singapore',
                'state': 'SG',
                'postal_code': singapore_postal_code,
                'country': 'SG',
                'phone': '+6512345678',
                'organization': singapore_company_name
            }
            
            handle = await self.create_contact_handle(singapore_contact)
            if handle:
                logger.info(f"✅ Created Singapore contact handle: {handle}")
                return handle
            else:
                logger.error("❌ Failed to create Singapore contact handle")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error creating Singapore contact handle: {e}")
            return None
    
    async def _build_singapore_additional_data(self, domain_name: str) -> Optional[Dict]:
        """
        Build additional data required for .com.sg domain registration and availability checks.
        Uses Singapore company credentials from environment variables.
        """
        try:
            singapore_uen = os.getenv('SINGAPORE_COMPANY_UEN')
            singapore_singpass_id = os.getenv('SINGAPORE_ADMIN_SINGPASS_ID')
            singapore_company_name = os.getenv('SINGAPORE_COMPANY_NAME')
            
            if not singapore_uen or not singapore_singpass_id or not singapore_company_name:
                logger.error("❌ Missing Singapore credentials for .com.sg (need UEN, SingPass ID, Company Name)")
                return None
            
            logger.info(f"🇸🇬 Building Singapore additional data for {domain_name}")
            
            additional_data = {
                'registrant_type': 'organization',
                'company_registration_number': singapore_uen,
                'organization_name': singapore_company_name,
                'admin_singpass_id': singapore_singpass_id
            }
            
            logger.info(f"✅ Built Singapore additional data with {len(additional_data)} fields")
            return additional_data
                
        except Exception as e:
            logger.error(f"❌ Error building Singapore additional data: {e}")
            import traceback
            logger.error(f"   Traceback: {traceback.format_exc()}")
            return None
    
    async def get_or_create_canada_contact_handle(self, cached_handles: Optional[List[str]] = None) -> Optional[str]:
        """
        Get or create a contact handle specifically for Canadian .ca domain registration.
        Prefers existing Canadian contact handles over creating new ones.
        
        Args:
            cached_handles: Optional pre-fetched list of contact handles to avoid duplicate API calls
        """
        try:
            logger.info(f"🇨🇦 Getting Canadian contact handle for .ca domain registration")
            
            # Use cached handles if provided, otherwise fetch
            if cached_handles is not None:
                handles = cached_handles
                logger.info(f"♻️ Using cached contact handles list ({len(handles)} handles)")
            else:
                handles = await self.get_contact_handles()
            
            if handles:
                # Look for existing Canadian contact handles (suffix -CA)
                canadian_handles = [h for h in handles if h.endswith('-CA')]
                if canadian_handles:
                    handle = canadian_handles[0]
                    logger.info(f"✅ Using existing Canadian contact handle: {handle}")
                    return handle
            
            # If no Canadian contact exists, use the default US contact handle
            # (OpenProvider allows using US contacts for .ca domains)
            logger.info(f"📝 No Canadian contact found, using default US contact for .ca domain")
            return await self.get_or_create_contact_handle()
                
        except Exception as e:
            logger.error(f"❌ Error getting Canadian contact handle: {e}")
            # Fallback to default contact
            return await self.get_or_create_contact_handle()
    
    async def get_or_create_italy_contact_handle(self, cached_handles: Optional[List[str]] = None) -> Optional[str]:
        """
        Get or create a contact handle for .it domain registration with Italian company credentials.
        
        Uses Vetrerie Riunite S.p.A. company details:
        - Company Name: Vetrerie Riunite S.p.A.
        - VAT Number: IT04126990961
        - Fiscal Code: IT04126990961 (FULL VAT with IT prefix - required for companies)
        - Address: Via Calcinese 60, 37030 Colognola ai Colli (VR), Italy
        
        CRITICAL: For .it domains, the fiscal code MUST be in the contact handle's 
        social_security_number field, NOT in domain registration additional_data.
        For companies, the fiscal code MUST include the IT prefix (IT04126990961).
        
        Args:
            cached_handles: Optional pre-fetched list of contact handles to avoid duplicate API calls
        """
        try:
            logger.info(f"🇮🇹 Getting contact handle for .it domain registration")
            
            # Use cached handles if provided, otherwise fetch
            if cached_handles is not None:
                handles = cached_handles
                logger.info(f"♻️ Using cached contact handles list ({len(handles)} handles)")
            else:
                handles = await self.get_contact_handles()
            
            if handles:
                # Look for existing Italian contact handles (suffix -IT)
                italian_handles = [h for h in handles if h.endswith('-IT')]
                if italian_handles:
                    handle = italian_handles[0]
                    logger.info(f"✅ Using existing Italian contact handle: {handle}")
                    return handle
            
            # Create new contact with real Italian company credentials
            # OpenProvider requires fiscal code at contact level, not registration level
            logger.info(f"📝 Creating Italian company contact handle (Vetrerie Riunite S.p.A.)")
            from utils.email_config import get_service_email
            
            # Italian company contact with real credentials
            # CRITICAL: For companies, social_security_number must be the FULL VAT (with IT prefix)
            italian_company_contact = {
                'first_name': 'Vetrerie Riunite',
                'last_name': 'S.p.A.',
                'email': get_service_email(),
                'address': 'Via Calcinese 60',
                'city': 'Colognola ai Colli',
                'state': 'VR',  # Province code for Verona
                'postal_code': '37030',
                'country': 'IT',  # Italy
                'phone': '+390456137111',  # Italian phone number (Verona area code 045)
                'organization': 'Vetrerie Riunite S.p.A.',
                'social_security_number': 'IT04126990961',  # Fiscal code (FULL VAT with IT prefix for companies)
                'vat': 'IT04126990961'  # Full VAT number with IT prefix
            }
            
            handle = await self.create_contact_handle(italian_company_contact)
            if handle:
                logger.info(f"✅ Created Italian company contact handle: {handle}")
                logger.info(f"🏢 Company: Vetrerie Riunite S.p.A. (Fiscal Code: IT04126990961)")
                return handle
            else:
                logger.error(f"❌ Failed to create Italian company contact handle")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error getting Italian contact handle: {e}")
            return None
    
    async def get_or_create_contact_handle(self) -> Optional[str]:
        """Get an existing contact handle or create a default one with proper phone formatting"""
        try:
            # CRITICAL FIX: Skip problematic contact handles with invalid phone formats
            # Contact handle RA1083275-US has invalid phone (+86 China code with US address)
            # that causes OpenProvider to reject domain registrations
            
            handles = await self.get_contact_handles()
            problematic_handles = ['RA1083275-US']  # Known bad contact handles
            
            if handles:
                # Filter out known problematic contact handles
                valid_handles = [h for h in handles if h not in problematic_handles]
                
                if valid_handles:
                    handle = valid_handles[0]
                    logger.info(f"✅ Using existing valid contact handle: {handle}")
                    return handle
                else:
                    logger.warning(f"⚠️ All existing contact handles are problematic: {handles}")
                    logger.info("📝 Creating new contact handle with proper phone formatting")
            else:
                logger.info("📝 No existing contact handles found, creating default contact")
            
            # Create a new contact handle with PROPER phone formatting
            from utils.email_config import get_service_email
            logger.info("🔧 PHONE FIX: Creating contact with properly formatted US phone number")
            default_contact = {
                'first_name': 'Hostbay',
                'last_name': 'Support',
                'email': get_service_email(),
                'address': '123 Business Ave',
                'city': 'New York',
                'state': 'NY',
                'postal_code': '10001',
                'country': 'US',
                'phone': '+15551234567',  # PROPER US format: +1 + 10 digits
                'organization': 'Hostbay Domain Services'
            }
            
            handle = await self.create_contact_handle(default_contact)
            if handle:
                logger.info(f"✅ Created new contact handle with proper phone format: {handle}")
                return handle
            else:
                logger.error("❌ Failed to create contact handle with proper phone format")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error getting or creating contact handle: {e}")
            return None
    
    async def get_domain_price(self, domain_name: str, period: int = 1, is_api_purchase: bool = False) -> Optional[Dict]:
        """Get domain pricing (same as get_domain_pricing but with period support)
        
        Args:
            domain_name: Domain name to get pricing for
            period: Registration period in years (currently ignored as markup is applied per year)
            is_api_purchase: If True, apply 10% API discount
        """
        return await self.get_domain_pricing(domain_name, is_api_purchase=is_api_purchase)
    
    async def get_domain_info(self, domain_id: str) -> Optional[Dict]:
        """Get domain information by OpenProvider domain ID"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                logger.error("❌ Failed to authenticate with OpenProvider")
                return None
            
            client = await self._ensure_client()
            
            response = await client.get(
                f"{self.base_url}/v1beta/domains/{domain_id}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    domain_data = data.get('data', {})
                    logger.info(f"✅ Retrieved domain info for ID: {domain_id}")
                    
                    # Extract nameservers from OpenProvider format: [{'name': 'ns1.example.com', 'seq_nr': 1}, ...]
                    raw_nameservers = domain_data.get('name_servers', [])
                    nameservers = [ns.get('name') for ns in raw_nameservers if isinstance(ns, dict) and ns.get('name')]
                    
                    return {
                        'success': True,
                        'domain_data': domain_data,
                        'nameservers': nameservers,
                        'expires_at': domain_data.get('renewal_date'),
                        'status': domain_data.get('status'),
                        'is_locked': domain_data.get('is_locked', False),
                        'privacy_protected': domain_data.get('is_private_whois_enabled', False)
                    }
            
            logger.error(f"❌ Failed to get domain info: HTTP {response.status_code}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting domain info: {e}")
            return None
    
    async def renew_domain(self, domain_id: str, period: int = 1) -> Optional[Dict]:
        """Renew a domain for specified period"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                logger.error("❌ Failed to authenticate with OpenProvider")
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            response = await client.post(
                f"{self.base_url}/v1beta/domains/{domain_id}/renew",
                headers=self.headers,
                json={'period': period}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Domain renewed successfully: {domain_id} for {period} year(s)")
                    return {
                        'success': True,
                        'domain_id': domain_id,
                        'period': period,
                        'new_expires_at': data.get('data', {}).get('renewal_date')
                    }
                else:
                    error_msg = data.get('desc', 'Unknown error')
                    logger.error(f"❌ Domain renewal failed: {error_msg}")
                    return {'success': False, 'error': error_msg}
            
            logger.error(f"❌ Domain renewal request failed: HTTP {response.status_code}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error renewing domain: {e}")
            return {'success': False, 'error': str(e)}
    
    async def transfer_domain(self, domain_name: str, auth_code: str, period: int = 1) -> Optional[Dict]:
        """Transfer a domain from another registrar"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                logger.error("❌ Failed to authenticate with OpenProvider")
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            transfer_data = {
                'domain': {'name': domain_name},
                'auth_code': auth_code,
                'period': period
            }
            
            response = await client.post(
                f"{self.base_url}/v1beta/domains/transfer",
                headers=self.headers,
                json=transfer_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Domain transfer initiated: {domain_name}")
                    return {
                        'success': True,
                        'domain_name': domain_name,
                        'status': 'transfer_pending',
                        'domain_id': data.get('data', {}).get('id')
                    }
                else:
                    error_msg = data.get('desc', 'Unknown error')
                    logger.error(f"❌ Domain transfer failed: {error_msg}")
                    return {'success': False, 'error': error_msg}
            
            logger.error(f"❌ Domain transfer request failed: HTTP {response.status_code}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error transferring domain: {e}")
            return {'success': False, 'error': str(e)}
    
    async def lock_domain(self, domain_id: str) -> Optional[Dict]:
        """Lock domain to prevent transfers"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            response = await client.put(
                f"{self.base_url}/v1beta/domains/{domain_id}",
                headers=self.headers,
                json={'is_locked': True}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Domain locked: {domain_id}")
                    return {'success': True, 'locked': True}
                else:
                    return {'success': False, 'error': data.get('desc', 'Unknown error')}
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error locking domain: {e}")
            return {'success': False, 'error': str(e)}
    
    async def unlock_domain(self, domain_id: str) -> Optional[Dict]:
        """Unlock domain to allow transfers"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            response = await client.put(
                f"{self.base_url}/v1beta/domains/{domain_id}",
                headers=self.headers,
                json={'is_locked': False}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Domain unlocked: {domain_id}")
                    return {'success': True, 'locked': False}
                else:
                    return {'success': False, 'error': data.get('desc', 'Unknown error')}
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error unlocking domain: {e}")
            return {'success': False, 'error': str(e)}
    
    async def enable_whois_privacy(self, domain_id: str) -> Optional[Dict]:
        """Enable WHOIS privacy protection"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            response = await client.put(
                f"{self.base_url}/v1beta/domains/{domain_id}",
                headers=self.headers,
                json={'is_private_whois_enabled': True}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ WHOIS privacy enabled: {domain_id}")
                    return {'success': True, 'privacy_enabled': True}
                else:
                    return {'success': False, 'error': data.get('desc', 'Unknown error')}
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error enabling WHOIS privacy: {e}")
            return {'success': False, 'error': str(e)}
    
    async def disable_whois_privacy(self, domain_id: str) -> Optional[Dict]:
        """Disable WHOIS privacy protection"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            response = await client.put(
                f"{self.base_url}/v1beta/domains/{domain_id}",
                headers=self.headers,
                json={'is_private_whois_enabled': False}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ WHOIS privacy disabled: {domain_id}")
                    return {'success': True, 'privacy_enabled': False}
                else:
                    return {'success': False, 'error': data.get('desc', 'Unknown error')}
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error disabling WHOIS privacy: {e}")
            return {'success': False, 'error': str(e)}
    
    async def get_whois_info(self, domain_name: str) -> Optional[Dict]:
        """Get WHOIS information for a domain"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return None
            
            client = await self._ensure_client()
            
            response = await client.get(
                f"{self.base_url}/v1beta/domains/whois",
                headers=self.headers,
                params={'domain_name': domain_name}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    whois_data = data.get('data', {})
                    logger.info(f"✅ Retrieved WHOIS info for: {domain_name}")
                    return {
                        'success': True,
                        'domain': domain_name,
                        'whois_data': whois_data
                    }
            
            logger.error(f"❌ Failed to get WHOIS info: HTTP {response.status_code}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting WHOIS info: {e}")
            return None
    
    async def get_auth_code(self, domain_id: str) -> Optional[Dict]:
        """Get EPP/Auth code for domain transfer"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return None
            
            client = await self._ensure_client()
            
            response = await client.get(
                f"{self.base_url}/v1beta/domains/{domain_id}/authcode",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    auth_code = data.get('data', {}).get('auth_code')
                    logger.info(f"✅ Retrieved auth code for domain ID: {domain_id}")
                    return {
                        'success': True,
                        'auth_code': auth_code
                    }
            
            logger.error(f"❌ Failed to get auth code: HTTP {response.status_code}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting auth code: {e}")
            return None
    
    async def reset_auth_code(self, domain_id: str, auth_code_type: str = 'internal') -> Optional[Dict]:
        """Reset/generate new EPP/Auth code for domain transfer"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            request_data = {
                'auth_code_type': auth_code_type
            }
            
            response = await client.post(
                f"{self.base_url}/v1beta/domains/{domain_id}/authcode/reset",
                headers=self.headers,
                json=request_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    result_data = data.get('data', {})
                    auth_code = result_data.get('auth_code')
                    logger.info(f"✅ Auth code reset for domain ID: {domain_id}")
                    return {
                        'success': True,
                        'auth_code': auth_code,
                        'type': result_data.get('type', auth_code_type)
                    }
                else:
                    error_msg = data.get('desc', 'Unknown error')
                    logger.error(f"❌ Auth code reset failed: {error_msg}")
                    return {'success': False, 'error': error_msg}
            
            logger.error(f"❌ Auth code reset request failed: HTTP {response.status_code}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error resetting auth code: {e}")
            return {'success': False, 'error': str(e)}
    
    async def approve_transfer(self, domain_id: str, domain_name: str, registrar_tag: str = '') -> Optional[Dict]:
        """Approve outgoing domain transfer"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            domain_parts = self._parse_domain(domain_name)
            
            request_data = {
                'approve': 1,
                'domain': domain_parts,
                'auth_code': '',
                'registrar_tag': registrar_tag,
                'id': 0
            }
            
            response = await client.post(
                f"{self.base_url}/v1beta/domains/{domain_id}/transfer/approve",
                headers=self.headers,
                json=request_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Outgoing transfer approved for: {domain_name}")
                    return {'success': True, 'approved': True}
                else:
                    error_msg = data.get('desc', 'Unknown error')
                    logger.error(f"❌ Transfer approval failed: {error_msg}")
                    return {'success': False, 'error': error_msg}
            
            logger.error(f"❌ Transfer approval request failed: HTTP {response.status_code}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error approving transfer: {e}")
            return {'success': False, 'error': str(e)}
    
    async def reject_transfer(self, domain_id: str, domain_name: str) -> Optional[Dict]:
        """Reject outgoing domain transfer"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            domain_parts = self._parse_domain(domain_name)
            
            request_data = {
                'approve': 0,
                'domain': domain_parts,
                'auth_code': '',
                'registrar_tag': '',
                'id': 0
            }
            
            response = await client.post(
                f"{self.base_url}/v1beta/domains/{domain_id}/transfer/approve",
                headers=self.headers,
                json=request_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Outgoing transfer rejected for: {domain_name}")
                    return {'success': True, 'rejected': True}
                else:
                    error_msg = data.get('desc', 'Unknown error')
                    logger.error(f"❌ Transfer rejection failed: {error_msg}")
                    return {'success': False, 'error': error_msg}
            
            logger.error(f"❌ Transfer rejection request failed: HTTP {response.status_code}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error rejecting transfer: {e}")
            return {'success': False, 'error': str(e)}
    
    async def restart_transfer(self, domain_id: str, domain_name: str) -> Optional[Dict]:
        """Restart a failed domain transfer"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            domain_parts = self._parse_domain(domain_name)
            
            request_data = {
                'domain': domain_parts
            }
            
            response = await client.post(
                f"{self.base_url}/v1beta/domains/{domain_id}/last-operation/restart",
                headers=self.headers,
                json=request_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Transfer restarted for: {domain_name}")
                    return {'success': True, 'restarted': True}
                else:
                    error_msg = data.get('desc', 'Unknown error')
                    logger.error(f"❌ Transfer restart failed: {error_msg}")
                    return {'success': False, 'error': error_msg}
            
            logger.error(f"❌ Transfer restart request failed: HTTP {response.status_code}")
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error restarting transfer: {e}")
            return {'success': False, 'error': str(e)}
    
    async def update_domain_contacts(self, domain_id: str, contacts: Dict) -> Optional[Dict]:
        """Update domain contact information"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            response = await client.put(
                f"{self.base_url}/v1beta/domains/{domain_id}",
                headers=self.headers,
                json={'contacts': contacts}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Domain contacts updated: {domain_id}")
                    return {'success': True}
                else:
                    return {'success': False, 'error': data.get('desc', 'Unknown error')}
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error updating domain contacts: {e}")
            return {'success': False, 'error': str(e)}
    
    async def delete_domain(self, domain_id: str) -> Optional[Dict]:
        """Cancel/delete a domain"""
        try:
            auth_success = await self.authenticate()
            if not auth_success:
                return {'success': False, 'error': 'Authentication failed'}
            
            client = await self._ensure_client()
            
            response = await client.delete(
                f"{self.base_url}/v1beta/domains/{domain_id}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    logger.info(f"✅ Domain deleted: {domain_id}")
                    return {'success': True}
                else:
                    return {'success': False, 'error': data.get('desc', 'Unknown error')}
            
            return {'success': False, 'error': f'HTTP {response.status_code}'}
            
        except Exception as e:
            logger.error(f"❌ Error deleting domain: {e}")
            return {'success': False, 'error': str(e)}


# Global optimized service instance
_optimized_service = OptimizedOpenProviderService()

class OpenProviderService(OptimizedOpenProviderService):
    """OpenProvider API service for domain registration - optimized version"""
    
    def __init__(self):
        super().__init__()
        # Ensure all methods are properly inherited and accessible
        logger.debug("🔧 OpenProviderService initialized with full method inheritance")
    
    # All methods are inherited from OptimizedOpenProviderService
    # No need to redefine them here to avoid LSP "obscured" warnings
    pass


    async def check_transfer_eligibility(self, domain_name: str) -> Dict[str, Any]:
        """
        Check if a domain is eligible for transfer to HostBay.
        
        Eligibility requirements:
        1. Domain must be at least 60 days old (ICANN policy)
        2. Domain must not be locked (no clientTransferProhibited status)
        3. Domain must be registered (not available for new registration)
        
        Returns:
            Dict with eligibility status, reasons, and domain info
        """
        try:
            logger.info(f"🔍 TRANSFER ELIGIBILITY: Checking {domain_name}")
            
            auth_success = await self.authenticate()
            if not auth_success:
                return {
                    'eligible': False,
                    'domain_name': domain_name,
                    'reasons': ['Failed to authenticate with registry'],
                    'checks': {}
                }
            
            client = await self._ensure_client()
            
            # Parse domain name
            parts = domain_name.rsplit('.', 1)
            if len(parts) != 2:
                return {
                    'eligible': False,
                    'domain_name': domain_name,
                    'reasons': ['Invalid domain name format'],
                    'checks': {}
                }
            
            name, extension = parts
            
            # Query OpenProvider with WHOIS data
            check_payload = {
                'domains': [{'name': name, 'extension': extension}],
                'with_whois': True,
                'with_price': True
            }
            
            response = await client.post(
                f"{self.base_url}/v1beta/domains/check",
                headers=self.headers,
                json=check_payload
            )
            
            if response.status_code != 200:
                return {
                    'eligible': False,
                    'domain_name': domain_name,
                    'reasons': [f'Registry check failed: HTTP {response.status_code}'],
                    'checks': {}
                }
            
            data = response.json()
            if data.get('code') != 0:
                return {
                    'eligible': False,
                    'domain_name': domain_name,
                    'reasons': [data.get('desc', 'Unknown registry error')],
                    'checks': {}
                }
            
            results = data.get('data', {}).get('results', [])
            if not results:
                return {
                    'eligible': False,
                    'domain_name': domain_name,
                    'reasons': ['No response from registry'],
                    'checks': {}
                }
            
            domain_info = results[0]
            status = domain_info.get('status', '').lower()
            whois_data = domain_info.get('whois', {})
            
            # Initialize checks
            checks = {
                'is_registered': False,
                'is_old_enough': False,
                'is_unlocked': False,
                'domain_age_days': None,
                'creation_date': None,
                'expiration_date': None,
                'domain_status': [],
                'registrar': None
            }
            
            reasons = []
            
            # Check 1: Domain must be registered (not available)
            if status in ['free', 'available']:
                reasons.append('Domain is not registered - cannot transfer an unregistered domain')
                return {
                    'eligible': False,
                    'domain_name': domain_name,
                    'reasons': reasons,
                    'checks': checks
                }
            
            checks['is_registered'] = True
            
            # Extract WHOIS data
            creation_date_str = whois_data.get('creation_date') or whois_data.get('createdDate')
            expiration_date_str = whois_data.get('expiration_date') or whois_data.get('expirationDate')
            domain_statuses = whois_data.get('domain_status', []) or whois_data.get('status', [])
            registrar = whois_data.get('registrar', 'Unknown')
            
            if isinstance(domain_statuses, str):
                domain_statuses = [domain_statuses]
            
            checks['domain_status'] = domain_statuses
            checks['registrar'] = registrar
            checks['creation_date'] = creation_date_str
            checks['expiration_date'] = expiration_date_str
            
            # Check 2: Domain age (must be > 60 days old)
            if creation_date_str:
                try:
                    from datetime import datetime, timedelta
                    
                    # Try multiple date formats
                    creation_date = None
                    for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%d-%m-%Y']:
                        try:
                            creation_date = datetime.strptime(creation_date_str[:10], fmt[:len(creation_date_str[:10])+2])
                            break
                        except ValueError:
                            continue
                    
                    if creation_date:
                        age_days = (datetime.utcnow() - creation_date).days
                        checks['domain_age_days'] = age_days
                        
                        if age_days >= 60:
                            checks['is_old_enough'] = True
                        else:
                            days_remaining = 60 - age_days
                            reasons.append(f'Domain is only {age_days} days old - must be at least 60 days old ({days_remaining} days remaining)')
                    else:
                        reasons.append('Could not parse domain creation date')
                        
                except Exception as e:
                    logger.warning(f"⚠️ Failed to parse creation date {creation_date_str}: {e}")
                    reasons.append('Could not verify domain age')
            else:
                reasons.append('Domain creation date not available from WHOIS')
            
            # Check 3: Lock status (must not have transfer prohibition)
            transfer_prohibited_statuses = [
                'clienttransferprohibited',
                'servertransferprohibited',
                'transferprohibited',
                'pending transfer',
                'pendingtransfer'
            ]
            
            is_locked = False
            for s in domain_statuses:
                if any(prohibited in s.lower() for prohibited in transfer_prohibited_statuses):
                    is_locked = True
                    break
            
            if is_locked:
                reasons.append('Domain is locked - must unlock at current registrar before transfer')
                checks['is_unlocked'] = False
            else:
                checks['is_unlocked'] = True
            
            # Determine overall eligibility
            is_eligible = checks['is_registered'] and checks['is_old_enough'] and checks['is_unlocked']
            
            # Get transfer pricing if eligible
            transfer_price = None
            if is_eligible:
                try:
                    pricing = await self.get_domain_price(domain_name, period=1, is_api_purchase=True)
                    if pricing:
                        transfer_price = pricing.get('transfer_price') or pricing.get('create_price')
                except Exception as e:
                    logger.warning(f"⚠️ Could not get transfer price: {e}")
            
            result = {
                'eligible': is_eligible,
                'domain_name': domain_name,
                'reasons': reasons if not is_eligible else ['Domain is eligible for transfer'],
                'checks': checks,
                'transfer_price_usd': transfer_price
            }
            
            logger.info(f"{'✅' if is_eligible else '❌'} TRANSFER ELIGIBILITY: {domain_name} - Eligible: {is_eligible}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Error checking transfer eligibility for {domain_name}: {e}")
            return {
                'eligible': False,
                'domain_name': domain_name,
                'reasons': [f'Error checking eligibility: {str(e)}'],
                'checks': {}
            }


# Helper function to get the global optimized service instance
def get_openprovider_service():
    """Get the global OpenProvider service instance"""
    return _optimized_service


# Legacy compatibility function (replaced by the above optimized version)
def legacy_openprovider_service():
    """Legacy compatibility function"""
    return OpenProviderService()

# Performance monitoring decorator
def monitor_performance(func):
    """Decorator to monitor API call performance"""
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(f"🚀 {func.__name__} completed in {execution_time:.2f}s")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"❌ {func.__name__} failed after {execution_time:.2f}s: {e}")
            raise
    return wrapper

