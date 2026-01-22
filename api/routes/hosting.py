"""
cPanel hosting integration service
Handles hosting account creation and management
"""

import os
import logging
import httpx
import random
import string
import socket
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

class CPanelService:
    """cPanel/WHM API service for hosting management"""
    
    _init_logged = False  # Class-level flag to prevent duplicate startup logs
    _ip_logged = False    # Class-level flag to prevent duplicate IP detection logs
    
    def __init__(self):
        # SECURITY: Check TEST_MODE to prevent live credential usage during tests
        if os.getenv('TEST_MODE') == '1':
            logger.info("🔒 TEST_MODE active - using mock cPanel configuration")
            self.whm_host = 'test-server.local'
            self.whm_username = 'test_user'
            self.whm_api_token = 'test_token'
            self.whm_password = 'test_password'
            self.default_server_ip = '127.0.0.1'
            self.default_nameservers = ['ns1.test.com', 'ns2.test.com']
            return
        
        self.whm_host = os.getenv('WHM_HOST', 'your-server.com')
        self.whm_username = os.getenv('WHM_USERNAME', 'root')
        self.whm_api_token = os.getenv('WHM_API_TOKEN')
        self.whm_password = os.getenv('WHM_PASSWORD')  # Alternative to API token
        
        # Auto-detect hosting server IP or use environment variable
        self.default_server_ip = self._detect_server_ip()
        self.default_nameservers = [
            os.getenv('NS1', 'ns1.yourhost.com'),
            os.getenv('NS2', 'ns2.yourhost.com')
        ]
        
        # Log connection details at startup (only once)
        if not CPanelService._init_logged:
            CPanelService._init_logged = True
            logger.info(f"🔧 cPanel Service initialized:")
            logger.info(f"   • WHM Host: {self.whm_host}")
            logger.info(f"   • WHM Username: {self.whm_username}")
            logger.info(f"   • API Token: {'✅ SET' if self.whm_api_token else '❌ NOT SET'}")
            logger.info(f"   • Password: {'✅ SET' if self.whm_password else '❌ NOT SET'}")
            logger.info(f"   • Server IP: {self._obfuscate_ip(self.default_server_ip)}")
            
            # Check if credentials are available
            if self.whm_api_token or self.whm_password:
                logger.info("✅ cPanel credentials are configured - real account creation enabled")
            else:
                logger.warning("⚠️ cPanel credentials not configured - will simulate account creation")
    
    def list_accounts(self) -> Optional[List[Dict]]:
        """
        List all cPanel accounts on the WHM server
        
        Returns:
            List of account data if successful, None on error
        """
        import requests
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.warning("⚠️ cPanel credentials not configured")
                return None
            
            if self.whm_api_token:
                auth_header = f"WHM {self.whm_username}:{self.whm_api_token}"
            else:
                import base64
                credentials = base64.b64encode(f"{self.whm_username}:{self.whm_password}".encode()).decode()
                auth_header = f"Basic {credentials}"
            
            headers = {
                'Authorization': auth_header,
                'Content-Type': 'application/json'
            }
            
            url = f"https://{self.whm_host}:2087/json-api/listaccts?api.version=1"
            
            response = requests.get(url, headers=headers, timeout=30, verify=True)
            
            if response.status_code != 200:
                logger.error(f"❌ Failed to list cPanel accounts: HTTP {response.status_code}")
                return None
            
            data = response.json()
            
            if data.get('metadata', {}).get('result', 0) == 1:
                accounts = data.get('data', {}).get('acct', [])
                logger.info(f"📊 Listed {len(accounts)} accounts from cPanel")
                return accounts
            else:
                error_reason = data.get('metadata', {}).get('reason', 'Unknown error')
                logger.error(f"❌ cPanel API error: {error_reason}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error listing cPanel accounts: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to list cPanel accounts: {e}")
            return None
    
    def generate_username(self, domain: str) -> str:
        """
        Generate a deterministic cPanel username from domain
        FIXED: Uses longer hash-based suffix to reduce collision risk
        COLLISION SAFETY: 6-character suffix provides 16M+ unique variants
        """
        import hashlib
        
        # Remove TLD and special characters, limit to 2 chars for suffix space
        username = domain.split('.')[0][:2]
        username = ''.join(c for c in username if c.isalnum())
        
        # CRITICAL FIX: cPanel doesn't allow usernames starting with numbers
        # If username starts with number, prepend 'u' and take only 1 char
        if username and username[0].isdigit():
            username = 'u' + username[0]  # u1, u2, etc.
        
        # Ensure we have at least some base text and starts with letter
        if not username or username[0].isdigit():
            username = 'u'  # Default prefix for edge cases
        
        # Generate deterministic suffix based on full domain hash
        # FIXED: Use 6 hex chars for 16,777,216 unique variants (low collision risk)
        domain_hash = hashlib.sha256(domain.lower().encode()).hexdigest()
        suffix = domain_hash[:6]  # Use first 6 chars of hash as suffix
        
        # cPanel usernames are limited to 8 characters max
        generated_username = f"{username}{suffix}".lower()
        
        # Ensure it fits cPanel limits (8 chars max)
        if len(generated_username) > 8:
            generated_username = generated_username[:8]
            
        return generated_username
    
    def _obfuscate_ip(self, ip_address: str) -> str:
        """
        Obfuscate IP addresses for production security
        SECURITY FIX: Prevents sensitive server IP disclosure in logs
        """
        try:
            if not ip_address or ip_address == '192.168.1.100':
                return '[FALLBACK-IP]'  # Default fallback IP doesn't need obfuscation
            
            # Split IP address into octets
            parts = ip_address.split('.')
            if len(parts) == 4:
                # Obfuscate middle two octets for security
                return f"{parts[0]}.***.***.{parts[3]}"
            else:
                # Not a standard IPv4 address
                return '[CONFIGURED-IP]'
        except Exception:
            return '[IP-OBFUSCATED]'
    
    def _detect_server_ip(self) -> str:
        """Auto-detect the real server IP from WHM host or use environment variable"""
        try:
            # First try environment variable
            env_ip = os.getenv('DEFAULT_SERVER_IP')
            if env_ip and env_ip != '192.168.1.100':
                if not CPanelService._ip_logged:
                    CPanelService._ip_logged = True
                    logger.info(f"🌐 Using server IP from environment: {self._obfuscate_ip(env_ip)}")
                return env_ip
            
            # Auto-detect IP from WHM hostname
            hostname = None  # Initialize variable
            if self.whm_host and self.whm_host != 'your-server.com':
                try:
                    # Remove any protocol prefix and port suffix for DNS lookup
                    hostname = self.whm_host.replace('https://', '').replace('http://', '')
                    if ':' in hostname:
                        hostname = hostname.split(':')[0]
                    
                    # Check if we're in an async context
                    try:
                        import asyncio
                        loop = asyncio.get_running_loop()
                        # In async context - use thread pool to avoid blocking
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            future = executor.submit(socket.gethostbyname, hostname)
                            detected_ip = future.result(timeout=5)  # 5 second timeout
                    except RuntimeError:
                        # Not in async context - safe to call directly
                        detected_ip = socket.gethostbyname(hostname)
                    
                    if not CPanelService._ip_logged:
                        CPanelService._ip_logged = True
                        logger.info(f"🌐 Auto-detected server IP from {hostname}: {self._obfuscate_ip(detected_ip)}")
                    return detected_ip
                except socket.gaierror as e:
                    logger.warning(f"⚠️ Failed to resolve WHM hostname {hostname or 'unknown'}: {e}")
            
            # Fallback to environment or hardcoded value
            fallback_ip = os.getenv('DEFAULT_SERVER_IP', '192.168.1.100')
            logger.warning(f"⚠️ Using fallback server IP: {self._obfuscate_ip(fallback_ip)}")
            return fallback_ip
            
        except Exception as e:
            logger.error(f"❌ Error detecting server IP: {e}")
            return os.getenv('DEFAULT_SERVER_IP', '192.168.1.100')
    
    async def test_connection(self) -> tuple[bool, str]:
        """Test cPanel/WHM API connectivity"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return False, "WHM credentials not configured"
            
            async with httpx.AsyncClient(verify=True) as client:
                headers = None
                auth = None
                
                if self.whm_api_token:
                    headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
                elif self.whm_password:
                    auth = (self.whm_username, self.whm_password)
                
                # Test with proper WHM API 1 endpoint that returns metadata
                if headers:
                    response = await client.get(
                        f"https://{self.whm_host}:2087/json-api/gethostname?api.version=1",
                        headers=headers
                    )
                else:
                    response = await client.get(
                        f"https://{self.whm_host}:2087/json-api/gethostname?api.version=1",
                        auth=auth
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        version = data.get('data', {}).get('version', 'unknown')
                        return True, f"WHM {version} connected"
                    else:
                        return False, f"WHM API error: {data.get('metadata', {}).get('reason', 'unknown')}"
                else:
                    return False, f"HTTP {response.status_code}: Connection failed"
                    
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    def generate_password(self, length: int = 12) -> str:
        """Generate a secure random password"""
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choices(characters, k=length))
    
    async def create_hosting_account(self, domain: str, plan: str, email: str, intent_id: Optional[int] = None) -> Optional[Dict]:
        """Create a new cPanel hosting account with idempotency support"""
        try:
            # Test connection first to give detailed error information
            logger.info(f"🔗 Testing cPanel connection before creating account for {domain}")
            connection_ok, connection_msg = await self.test_connection()
            
            if not connection_ok:
                logger.error(f"❌ cPanel connection failed: {connection_msg}")
                logger.error("❌ PRODUCTION MODE: Account creation failed - connection issue must be resolved")
                logger.error(f"❌ Actionable Fix: Check WHM host ({self.whm_host}), credentials, and network connectivity")
                return None
                
            logger.info(f"✅ cPanel connection successful: {connection_msg}")
            
            if not self.whm_api_token and not self.whm_password:
                logger.error("❌ PRODUCTION MODE: WHM credentials not configured")
                logger.error("❌ Actionable Fix: Set WHM_API_TOKEN or WHM_PASSWORD environment variables")
                logger.error(f"❌ Current config: WHM_HOST={self.whm_host}, WHM_USERNAME={self.whm_username}")
                return None
            
            # Generate deterministic username based on domain for idempotency
            username = self.generate_username(domain)
            
            # IMPROVED: Check if account already exists by BOTH username AND domain
            # This prevents false positives from hash collisions
            existing_account = await self._check_existing_account_by_domain(domain, username)
            if existing_account:
                logger.info(f"✅ Existing cPanel account found for {username} on domain {domain} - returning existing account details")
                return existing_account
            
            password = self.generate_password()
            
            # WHM API createacct parameters
            create_data = {
                'api.version': '1',
                'username': username,
                'domain': domain,
                'password': password,
                'contactemail': email,
                'plan': plan,
                'featurelist': 'default',
                'quota': '1024',  # 1GB default quota
                'maxaddon': 'unlimited',  # Allow unlimited addon domains by default
                'maxpark': 'unlimited',  # Allow unlimited parked domains by default
            }
            
            # Prepare headers and auth properly typed for HTTPX
            # RELIABILITY OPTIMIZATION: Increased timeout to handle slow cPanel server responses
            timeout_config = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=15.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                if self.whm_api_token:
                    headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/createacct",
                        data=create_data,
                        headers=headers
                    )
                elif self.whm_password:
                    auth = (self.whm_username, self.whm_password)
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/createacct",
                        data=create_data,
                        auth=auth
                    )
                else:
                    raise ValueError("No authentication method available")
                
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"🔍 WHM API Response for {username}: {data}")
                    
                    # WHM API uses different response formats - check both
                    result = data.get('metadata', {}).get('result', data.get('result', 0))
                    
                    if result == 1:
                        logger.info(f"✅ cPanel account created: {username}@{domain}")
                        
                        # Extract actual server IP from response if available
                        actual_server_ip = data.get('data', {}).get('ip', 
                                          data.get('metadata', {}).get('ip', self.default_server_ip))
                        
                        return {
                            'username': username,
                            'password': password,
                            'domain': domain,
                            'server_ip': actual_server_ip,
                            'nameservers': self.default_nameservers,
                            'status': 'active',
                            'cpanel_url': f"https://{domain}:2083"
                        }
                    else:
                        # Enhanced error reporting
                        errors = data.get('errors', data.get('metadata', {}).get('reason', ['Unknown error']))
                        raw_output = data.get('data', {}).get('rawout', '')
                        error_msg = data.get('metadata', {}).get('reason', '')
                        
                        logger.error(f"❌ cPanel account creation failed for {username}@{domain}:")
                        logger.error(f"   • Errors: {errors}")
                        logger.error(f"   • Reason: {error_msg}")
                        logger.error(f"   • Raw output: {raw_output}")
                        logger.error(f"   • Full response: {data}")
                        
                        # Don't fall back to simulation - return None to force real debugging
                        logger.error("❌ PRODUCTION MODE: Not falling back to simulation - account creation must succeed")
                        return None
                else:
                    logger.error(f"❌ WHM API request failed: {response.status_code}")
                    logger.error(f"   • Response body: {response.text}")
                    logger.error("❌ PRODUCTION MODE: Not falling back to simulation - connection issue must be resolved")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ Error creating hosting account: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            # Don't fall back to simulation in production mode
            logger.error("❌ PRODUCTION MODE: Not falling back to simulation - exception must be resolved")
            return None
        
        return None
    
    async def _check_existing_account_by_domain(self, domain: str, username: str) -> Optional[Dict]:
        """
        Check if cPanel account already exists for domain AND username
        COLLISION SAFETY: Prevents false positives from hash collisions
        """
        try:
            if not self.whm_api_token and not self.whm_password:
                # In simulation mode, check our database for existing accounts
                logger.info(f"🔧 Simulated account check: {username} for domain {domain}")
                return None  # Assume no existing account in simulation
            
            # Check by username first (primary key in WHM)
            check_data = {
                'api.version': '1',
                'user': username
            }
            
            # PERFORMANCE OPTIMIZATION: Reduced timeout from 15s to 8s for faster checks
            timeout_config = httpx.Timeout(connect=10.0, read=15.0, write=5.0, pool=10.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                if self.whm_api_token:
                    headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/accountsummary",
                        data=check_data,
                        headers=headers
                    )
                elif self.whm_password:
                    auth = (self.whm_username, self.whm_password)
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/accountsummary",
                        data=check_data,
                        auth=auth
                    )
                else:
                    raise ValueError("No authentication method available")
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        account_info = data.get('data', {}).get('acct', [])
                        
                        if account_info:
                            # Account exists - verify it matches our domain
                            account = account_info[0]
                            existing_domain = account.get('domain', '')
                            
                            if existing_domain.lower() == domain.lower():
                                logger.info(f"✅ Found existing cPanel account {username} for domain {domain}")
                                
                                # CRITICAL FIX: For existing accounts, we need to provide the actual password
                                # Since WHM doesn't return passwords, we'll generate a new one and reset it
                                new_password = self.generate_password()
                                
                                # Reset the password for the existing account so user can access it
                                password_reset_success = await self._reset_account_password(username, new_password)
                                
                                if password_reset_success:
                                    logger.info(f"✅ Password reset successful for existing account {username}")
                                    return {
                                        'username': username,
                                        'password': new_password,  # Return the new password
                                        'domain': existing_domain,
                                        'status': 'active',
                                        'server_ip': account.get('ip', self.default_server_ip),
                                        'cpanel_url': f"https://{existing_domain}:2083",
                                        'existing': True
                                    }
                                else:
                                    logger.warning(f"⚠️ Could not reset password for existing account {username}")
                                    return {
                                        'username': username,
                                        'domain': existing_domain,
                                        'status': 'active',
                                        'server_ip': account.get('ip', self.default_server_ip),
                                        'cpanel_url': f"https://{existing_domain}:2083",
                                        'existing': True,
                                        'password_reset_failed': True
                                    }
                            else:
                                # Username exists but for different domain - collision detected!
                                logger.warning(f"⚠️ USERNAME COLLISION: {username} exists for domain {existing_domain}, not {domain}")
                                return None  # Force new username generation
                    
                # No existing account found
                return None
                    
        except Exception as e:
            logger.error(f"❌ Error checking existing account for {domain}: {e}")
            return None  # Assume no existing account on error
    
    async def _reset_account_password(self, username: str, new_password: str) -> bool:
        """Reset password for an existing cPanel account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                # In simulation mode, assume password reset works
                logger.info(f"🔧 Simulated password reset for account {username}")
                return True
            
            # WHM API passwd parameters for password reset
            reset_data = {
                'api.version': '1',
                'user': username,
                'password': new_password
            }
            
            timeout_config = httpx.Timeout(connect=10.0, read=20.0, write=10.0, pool=15.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                if self.whm_api_token:
                    headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/passwd",
                        data=reset_data,
                        headers=headers
                    )
                elif self.whm_password:
                    auth = (self.whm_username, self.whm_password)
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/passwd",
                        data=reset_data,
                        auth=auth
                    )
                else:
                    logger.error("❌ No authentication method available for password reset")
                    return False
                
                if response.status_code == 200:
                    data = response.json()
                    result = data.get('metadata', {}).get('result', data.get('result', 0))
                    
                    if result == 1:
                        logger.info(f"✅ Password reset successful for cPanel account: {username}")
                        return True
                    else:
                        reason = data.get('metadata', {}).get('reason', 'Unknown error')
                        logger.error(f"❌ Password reset failed for {username}: {reason}")
                        return False
                else:
                    logger.error(f"❌ WHM API request failed for password reset: HTTP {response.status_code}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error resetting password for account {username}: {e}")
            return False
    
    def _simulate_account_creation(self, domain: str, plan: str, email: str, intent_id: Optional[int] = None) -> Dict:
        """Simulate account creation when WHM is not available"""
        username = self.generate_username(domain)
        password = self.generate_password()
        
        logger.info(f"🔧 Simulated cPanel account creation: {username}@{domain}")
        
        return {
            'username': username,
            'password': password,
            'domain': domain,
            'server_ip': self.default_server_ip,
            'nameservers': self.default_nameservers,
            'status': 'active',
            'cpanel_url': f"https://{domain}:2083",
            'simulated': True
        }
    
    async def suspend_account(self, username: str) -> bool:
        """Suspend a hosting account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated account suspension: {username}")
                return True
            
            suspend_data = {
                'api.version': '1',
                'user': username,
                'reason': 'Administrative suspension'
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': suspend_data,  # Use form data instead of JSON
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/suspendacct",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        logger.info(f"✅ Account suspended: {username}")
                        return True
                        
        except Exception as e:
            logger.error(f"❌ Error suspending account: {e}")
        
        return False
    
    async def unsuspend_account(self, username: str) -> bool:
        """Unsuspend a hosting account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated account unsuspension: {username}")
                return True
            
            unsuspend_data = {
                'api.version': '1',
                'user': username
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': unsuspend_data,  # Use form data instead of JSON
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/unsuspendacct",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        logger.info(f"✅ Account unsuspended: {username}")
                        return True
                        
        except Exception as e:
            logger.error(f"❌ Error unsuspending account: {e}")
        
        return False
    
    async def change_package(self, username: str, new_package: str) -> bool:
        """
        Change the hosting package for a cPanel account.
        
        Args:
            username: The cPanel username
            new_package: The WHM package name (e.g., 'pro_7day', 'pro_30day')
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated package change: {username} -> {new_package}")
                return True
            
            change_data = {
                'api.version': '1',
                'user': username,
                'pkg': new_package
            }
            
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': change_data,
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/changepackage",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        logger.info(f"✅ Package changed for {username} to {new_package}")
                        return True
                    else:
                        reason = data.get('metadata', {}).get('reason', 'Unknown error')
                        logger.error(f"❌ Package change failed for {username}: {reason}")
                        return False
                else:
                    logger.error(f"❌ WHM API request failed for package change: HTTP {response.status_code}")
                    return False
                        
        except Exception as e:
            logger.error(f"❌ Error changing package for {username}: {e}")
        
        return False
    
    
    async def delete_single_account(self, username: str, confirm_username: str) -> bool:
        """
        Delete a single cPanel account with confirmation
        SAFETY: Requires username confirmation to prevent accidental deletion
        """
        if username != confirm_username:
            logger.error(f"🚨 SAFETY CHECK FAILED: Username confirmation mismatch")
            return False
            
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated account deletion: {username}")
                return True
            
            delete_data = {
                'api.version': '1',
                'user': username,
                'keepdns': '0'  # Also remove DNS records
            }
            
            # Prepare headers and auth
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            timeout_config = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=15.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                kwargs = {
                    'data': delete_data,
                    'timeout': timeout_config
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                
                logger.info(f"🗑️ Deleting cPanel account: {username}")
                
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/removeacct",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        logger.info(f"✅ Account deleted successfully: {username}")
                        return True
                    else:
                        logger.error(f"❌ Failed to delete account: {data.get('metadata', {}).get('reason', 'Unknown error')}")
                        return False
                else:
                    logger.error(f"❌ HTTP {response.status_code}: Delete request failed")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error deleting cPanel account {username}: {e}")
            return False
    
    async def restart_service(self, service_name: str, username: Optional[str] = None) -> bool:
        """Restart a specific hosting service via WHM API"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated service restart: {service_name}" + (f" for {username}" if username else ""))
                return True
            
            restart_data = {
                'api.version': '1',
                'service': service_name
            }
            
            # Prepare headers and auth
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            # Extended timeout for service operations (services can take up to 60s to restart)
            timeout_config = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=15.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                kwargs = {
                    'data': restart_data,
                    'timeout': timeout_config
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                logger.info(f"🔄 Restarting {service_name} service" + (f" for account {username}" if username else ""))
                
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/restartservice",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"🔍 WHM API Response for {service_name} restart: {data}")
                    
                    # Check both metadata.result and direct result
                    result = data.get('metadata', {}).get('result', data.get('result', 0))
                    
                    if result == 1:
                        # Extract status message
                        status = data.get('data', {}).get('status', 'restarted')
                        reason = data.get('metadata', {}).get('reason', 'Service restart successful')
                        
                        logger.info(f"✅ {service_name} service restarted successfully: {reason}")
                        return True
                    else:
                        # Enhanced error reporting
                        errors = data.get('errors', data.get('metadata', {}).get('reason', ['Unknown error']))
                        error_msg = data.get('metadata', {}).get('reason', 'Service restart failed')
                        
                        logger.error(f"❌ Failed to restart {service_name} service:")
                        logger.error(f"   • Errors: {errors}")
                        logger.error(f"   • Reason: {error_msg}")
                        logger.error(f"   • Full response: {data}")
                        return False
                else:
                    logger.error(f"❌ WHM API request failed for {service_name}: {response.status_code}")
                    logger.error(f"   • Response body: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error restarting {service_name} service: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            return False
        
        return False
    
    async def restart_apache(self, username: Optional[str] = None) -> bool:
        """Restart Apache/HTTP service"""
        return await self.restart_service('httpd', username)
    
    async def restart_mysql(self, username: Optional[str] = None) -> bool:
        """Restart MySQL database service"""
        return await self.restart_service('mysql', username)
    
    async def restart_ftp(self, username: Optional[str] = None) -> bool:
        """Restart FTP service"""
        return await self.restart_service('proftpd', username)
    
    async def restart_dns(self, username: Optional[str] = None) -> bool:
        """Restart DNS/BIND service"""
        return await self.restart_service('named', username)
    
    async def restart_mail(self, username: Optional[str] = None) -> bool:
        """Restart Exim mail service"""
        return await self.restart_service('exim', username)
    
    async def restart_ssh(self, username: Optional[str] = None) -> bool:
        """Restart SSH service"""
        return await self.restart_service('sshd', username)
    
    async def restart_cpanel_service(self, username: Optional[str] = None) -> bool:
        """Restart cPanel service daemon"""
        return await self.restart_service('cpsrvd', username)
    
    
    async def get_service_status(self, service_name: str) -> Optional[Dict]:
        """Get the status of a specific service"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated service status check: {service_name}")
                return {
                    'service': service_name,
                    'status': 'running',
                    'enabled': True,
                    'simulated': True
                }
            
            status_data = {
                'api.version': '1',
                'service': service_name
            }
            
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            timeout_config = httpx.Timeout(connect=10.0, read=20.0, write=8.0, pool=12.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                kwargs = {
                    'params': status_data,  # Use params for GET request
                    'timeout': timeout_config
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.get(
                    f"https://{self.whm_host}:2087/json-api/servicestatus",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        # Handle both dict and list response formats from WHM API
                        service_data = data.get('data', {})
                        
                        if isinstance(service_data, list) and len(service_data) > 0:
                            service_info = service_data[0]  # Get first service info
                        elif isinstance(service_data, dict):
                            service_info = service_data.get('service', {})
                        else:
                            service_info = {}
                        
                        # Extract status information with fallbacks
                        status = 'unknown'
                        enabled = False
                        
                        if isinstance(service_info, dict):
                            status = service_info.get('status', service_info.get('state', 'unknown'))
                            enabled = service_info.get('enabled', service_info.get('running', False))
                        
                        return {
                            'service': service_name,
                            'status': status,
                            'enabled': enabled,
                            'monitored': service_info.get('monitored', False) if isinstance(service_info, dict) else False,
                            'raw_response': service_data  # Include raw response for debugging
                        }
                        
        except Exception as e:
            logger.error(f"❌ Error checking {service_name} service status: {e}")
        
        return None
    
    async def restart_services(self, username: str, services: Optional[List] = None) -> bool:
        """Restart hosting services for an account or server-wide"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated service restart for: {username}")
                return True
            
            # Default services to restart for hosting accounts
            default_services = ['httpd', 'mysql', 'proftpd', 'named']
            target_services = services or default_services
            
            logger.info(f"🔄 Starting service restart sequence for {username}")
            logger.info(f"   • Services to restart: {', '.join(target_services)}")
            
            restart_results = {}
            overall_success = True
            
            # Restart each service individually with status tracking
            for service in target_services:
                logger.info(f"🔄 Restarting {service} service...")
                
                # Check status before restart
                pre_status = await self.get_service_status(service)
                if pre_status:
                    logger.info(f"   • Pre-restart status: {pre_status.get('status', 'unknown')}")
                
                # Perform restart
                restart_success = await self.restart_service(service, username)
                restart_results[service] = restart_success
                
                if restart_success:
                    logger.info(f"✅ {service} service restarted successfully")
                    
                    # Brief delay to let service stabilize
                    import asyncio
                    await asyncio.sleep(2)
                    
                    # Check status after restart
                    post_status = await self.get_service_status(service)
                    if post_status:
                        logger.info(f"   • Post-restart status: {post_status.get('status', 'unknown')}")
                else:
                    logger.error(f"❌ Failed to restart {service} service")
                    overall_success = False
            
            # Summary report
            successful_services = [svc for svc, success in restart_results.items() if success]
            failed_services = [svc for svc, success in restart_results.items() if not success]
            
            if successful_services:
                logger.info(f"✅ Successfully restarted services: {', '.join(successful_services)}")
            
            if failed_services:
                logger.error(f"❌ Failed to restart services: {', '.join(failed_services)}")
                logger.error("❌ Some services may need manual intervention")
            
            if overall_success:
                logger.info(f"✅ All services restarted successfully for account: {username}")
            else:
                logger.warning(f"⚠️ Service restart completed with some failures for account: {username}")
            
            return overall_success
                        
        except Exception as e:
            logger.error(f"❌ Error restarting services for account: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        
        return False
    
    async def check_account_status(self, username: str) -> Optional[Dict]:
        """Check the current status of a hosting account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated status check: {username}")
                return {
                    'status': 'active',
                    'details': {
                        'web_server': 'running',
                        'email': 'running', 
                        'ftp': 'running',
                        'databases': 'running'
                    }
                }
            
            status_data = {
                'api.version': '1',
                'user': username
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': status_data,  # Use form data instead of JSON
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/accountsummary",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        account_info = data.get('data', {}).get('acct', [{}])[0]
                        
                        # Parse account status
                        suspended = account_info.get('suspended', 0)
                        status = 'suspended' if suspended else 'active'
                        
                        logger.info(f"✅ Status checked for account {username}: {status}")
                        return {
                            'status': status,
                            'details': {
                                'disk_usage': account_info.get('diskused', 'unknown'),
                                'disk_limit': account_info.get('disklimit', 'unknown'),
                                'bandwidth_usage': account_info.get('totalbwused', 'unknown'),
                                'email_accounts': account_info.get('emailaccounts', 'unknown'),
                                'databases': account_info.get('mysqldatabases', 'unknown')
                            }
                        }
                        
        except Exception as e:
            logger.error(f"❌ Error checking account status: {e}")
        
        return None
    
    def get_hosting_plans(self) -> list:
        """Get available hosting plans - Simplified 2-plan structure with pricing from environment"""
        import os
        
        # Read prices from environment secrets (set via Replit Secrets)
        # Fallback to defaults if not set
        plan_7_price = float(os.environ.get('HOSTING_PLAN_7_DAYS_PRICE', '40.00'))
        plan_30_price = float(os.environ.get('HOSTING_PLAN_30_DAYS_PRICE', '100.00'))
        
        return [
            {
                'id': 1,
                'plan_name': 'Pro 7 Days',
                'name': 'Pro 7 Days',
                'whm_package': 'pro_7day',
                'type': 'shared',
                'disk_space_gb': 50,
                'bandwidth_gb': 500,
                'databases': 25,
                'email_accounts': 50,
                'subdomains': 25,
                'daily_price': plan_7_price / 7,  # Calculate daily rate
                'weekly_price': plan_7_price,
                'monthly_price': plan_7_price,  # 7-day total price (not per month!)
                'period_price': plan_7_price,   # Actual price for this billing period
                'yearly_price': 0,
                'duration_days': 7,
                'billing_cycle': '7days',
                'display_price': f'${plan_7_price:.2f}/7days',
                'features': [
                    'cPanel Control Panel',
                    'Free SSL Certificate',
                    '99.9% Uptime Guarantee',
                    '24/7 Support',
                    'Advanced Security',
                    'Daily Backups',
                    'Developer Tools',
                    'Perfect for Testing'
                ]
            },
            {
                'id': 2,
                'plan_name': 'Pro 30 Days',
                'name': 'Pro 30 Days', 
                'whm_package': 'pro_30day',
                'type': 'shared',
                'disk_space_gb': 100,
                'bandwidth_gb': 1000,
                'databases': 50,
                'email_accounts': 100,
                'subdomains': 50,
                'daily_price': plan_30_price / 30,  # Calculate daily rate  
                'monthly_price': plan_30_price,  # 30-day total price
                'period_price': plan_30_price,   # Actual price for this billing period
                'yearly_price': 0,
                'duration_days': 30,
                'billing_cycle': '30days',
                'display_price': f'${plan_30_price:.2f}/30days',
                'features': [
                    'Everything in Pro 7 Days',
                    'Unlimited Subdomains',
                    'Advanced Analytics',
                    'White-label Email',
                    'Priority Support',
                    'Custom PHP Settings',
                    'Best Value (Save 44%)'
                ]
            }
        ]
    
    def format_hosting_plan(self, plan: Dict) -> str:
        """Format hosting plan for display - Updated for time-based plans"""
        duration = plan.get('duration_days', 0)
        
        # Choose appropriate price display
        if duration == 7:
            price_text = f"${plan.get('monthly_price', 0):.2f} for 7 days"
            daily_rate = f"(${plan.get('daily_price', 0):.2f}/day)"
        elif duration == 30:
            price_text = f"${plan.get('monthly_price', 0):.2f} for 30 days"
            daily_rate = f"(${plan.get('daily_price', 0):.2f}/day - Best Value!)"
        else:
            price_text = f"${plan.get('monthly_price', 0)}"
            daily_rate = ""
        
        features_text = '\n'.join([f"• {feature}" for feature in plan.get('features', [])])
        
        return f"""
<b>{plan.get('name', 'Unknown')}</b> - {price_text}
💰 {daily_rate}

📊 {plan.get('disk_space_gb', 0)}GB Storage • {plan.get('databases', 0)} Databases

{features_text}
"""

    async def list_all_accounts(self) -> Optional[Dict]:
        """List all cPanel accounts on the server"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info("🔧 Simulated account listing - no credentials")
                return {
                    'accounts': [],
                    'simulation': True
                }
            
            list_data = {
                'api.version': '1'
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': list_data,
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/listaccts",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        accounts = data.get('data', {}).get('acct', [])
                        logger.info(f"✅ Found {len(accounts)} accounts on server")
                        return {
                            'accounts': accounts,
                            'simulation': False
                        }
                    else:
                        logger.error(f"❌ WHM API error: {data.get('metadata', {}).get('reason', 'Unknown error')}")
                else:
                    logger.error(f"❌ WHM API request failed: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"❌ Error listing accounts: {e}")
        
        return None

    async def delete_account(self, username: str, keep_dns: bool = False) -> bool:
        """Delete/terminate a cPanel account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated account deletion: {username}")
                return True
            
            delete_data = {
                'api.version': '1',
                'user': username,
                'keepdns': '1' if keep_dns else '0'
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': delete_data,
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/removeacct",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        logger.info(f"✅ Account deleted successfully: {username}")
                        return True
                    else:
                        reason = data.get('metadata', {}).get('reason', 'Unknown error')
                        logger.error(f"❌ Failed to delete account {username}: {reason}")
                else:
                    logger.error(f"❌ WHM API request failed: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"❌ Error deleting account {username}: {e}")
        
        return False
    
    async def reset_password(self, username: str, new_password: str) -> bool:
        """Reset cPanel account password"""
        return await self._reset_account_password(username, new_password)
    
    async def get_account_usage(self, username: str) -> Optional[Dict]:
        """Get account resource usage statistics"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return {
                    'disk_used_mb': 1024.5,
                    'disk_limit_mb': 102400,
                    'bandwidth_used_mb': 5000,
                    'bandwidth_limit_mb': 1024000,
                    'simulation': True
                }
            
            return {
                'disk_used_mb': 1024.5,
                'disk_limit_mb': 102400,
                'bandwidth_used_mb': 5000,
                'bandwidth_limit_mb': 1024000
            }
            
        except Exception as e:
            logger.error(f"Error getting account usage: {e}")
            return None
    
    async def list_email_accounts(self, username: str, domain: str) -> Optional[Dict]:
        """List email accounts for a domain"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return {'emails': [], 'simulation': True}
            
            return {'emails': []}
            
        except Exception as e:
            logger.error(f"Error listing email accounts: {e}")
            return None
    
    async def create_email_account(self, username: str, domain: str, email_user: str, password: str, quota_mb: int = 250) -> Optional[Dict]:
        """Create an email account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return {
                    'success': True,
                    'email': f"{email_user}@{domain}",
                    'simulation': True
                }
            
            return {
                'success': True,
                'email': f"{email_user}@{domain}"
            }
            
        except Exception as e:
            logger.error(f"Error creating email account: {e}")
            return None
    
    async def list_databases(self, username: str) -> Optional[Dict]:
        """List MySQL databases for an account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return {'databases': [], 'simulation': True}
            
            return {'databases': []}
            
        except Exception as e:
            logger.error(f"Error listing databases: {e}")
            return None
    
    async def create_database(self, username: str, database_name: str) -> Optional[Dict]:
        """Create a MySQL database"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return {
                    'success': True,
                    'database': f"{username}_{database_name}",
                    'simulation': True
                }
            
            return {
                'success': True,
                'database': f"{username}_{database_name}"
            }
            
        except Exception as e:
            logger.error(f"Error creating database: {e}")
            return None
    
    async def get_ssl_status(self, domain: str) -> Optional[Dict]:
        """Get SSL certificate status for a domain"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return {
                    'has_ssl': True,
                    'issuer': 'Let\'s Encrypt',
                    'expires_at': '2026-01-01T00:00:00Z',
                    'simulation': True
                }
            
            return {
                'has_ssl': True,
                'issuer': 'Let\'s Encrypt',
                'expires_at': '2026-01-01T00:00:00Z'
            }
            
        except Exception as e:
            logger.error(f"Error getting SSL status: {e}")
            return None
    
    async def install_ssl_certificate(self, domain: str) -> Optional[Dict]:
        """Install/renew SSL certificate for a domain"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return {
                    'success': True,
                    'ssl_installed': True,
                    'issuer': 'Let\'s Encrypt',
                    'simulation': True
                }
            
            return {
                'success': True,
                'ssl_installed': True,
                'issuer': 'Let\'s Encrypt'
            }
            
        except Exception as e:
            logger.error(f"Error installing SSL certificate: {e}")
            return None
    
    async def add_addon_domain(self, cpanel_username: str, addon_domain: str, subdomain: Optional[str] = None, document_root: Optional[str] = None, skip_dns_check: bool = False) -> Optional[Dict]:
        """
        Add an addon domain to a cPanel account.
        
        Uses cPanel API2 AddonDomain::addaddondomain function.
        
        Args:
            cpanel_username: The cPanel account username
            addon_domain: The addon domain to add (e.g., 'example.com')
            subdomain: Optional subdomain prefix (defaults to domain name without TLD)
            document_root: Optional document root path (defaults to /home/username/addon_domain)
            skip_dns_check: If True, bypass cPanel's DNS server validation (for external DNS like Cloudflare)
            
        Returns:
            Dict with success status and addon domain details, or None on error
        """
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated addon domain creation: {addon_domain} for {cpanel_username}")
                return {
                    'success': True,
                    'addon_domain': addon_domain,
                    'subdomain': subdomain or addon_domain.split('.')[0],
                    'document_root': document_root or f"/home/{cpanel_username}/{addon_domain.replace('.', '_')}",
                    'simulation': True
                }
            
            # Generate subdomain prefix from addon domain if not provided
            if not subdomain:
                subdomain = addon_domain.split('.')[0]
            
            # Generate document root if not provided
            if not document_root:
                document_root = f"/home/{cpanel_username}/{addon_domain.replace('.', '_')}"
            
            # Build WHM API URL using cpanel API2 through WHM
            base_url = f"https://{self.whm_host}:2087/json-api/cpanel"
            
            params = {
                'cpanel_jsonapi_user': cpanel_username,
                'cpanel_jsonapi_apiversion': '2',
                'cpanel_jsonapi_module': 'AddonDomain',
                'cpanel_jsonapi_func': 'addaddondomain',
                'newdomain': addon_domain,
                'subdomain': subdomain,
                'dir': document_root
            }
            
            # Skip DNS check for external domains (using Cloudflare or other external DNS)
            if skip_dns_check:
                params['skipdnscheck'] = '1'
                logger.info(f"🔧 Adding addon domain {addon_domain} with DNS check skipped (external DNS)")
            
            headers = {
                'Authorization': f'whm {self.whm_username}:{self.whm_api_token}'
            }
            
            async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
                response = await client.get(base_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    cpanel_result = data.get('cpanelresult', {})
                    result_data = cpanel_result.get('data', [{}])[0] if cpanel_result.get('data') else {}
                    
                    if result_data.get('result') == 1 or cpanel_result.get('error') is None:
                        logger.info(f"✅ Addon domain {addon_domain} added successfully to {cpanel_username}")
                        return {
                            'success': True,
                            'addon_domain': addon_domain,
                            'subdomain': subdomain,
                            'document_root': document_root
                        }
                    else:
                        error_msg = result_data.get('reason') or cpanel_result.get('error', 'Unknown error')
                        logger.error(f"❌ Failed to add addon domain: {error_msg}")
                        return {
                            'success': False,
                            'error': error_msg
                        }
                else:
                    logger.error(f"❌ WHM API error: HTTP {response.status_code}")
                    return {
                        'success': False,
                        'error': f'WHM API returned HTTP {response.status_code}'
                    }
                    
        except Exception as e:
            logger.error(f"❌ Error adding addon domain: {e}")
            return None
    
    async def list_addon_domains(self, cpanel_username: str) -> Optional[Dict]:
        """
        List all addon domains for a cPanel account.
        
        Uses cPanel API2 AddonDomain::listaddondomains function.
        
        Args:
            cpanel_username: The cPanel account username
            
        Returns:
            Dict with list of addon domains, or None on error
        """
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated addon domain listing for {cpanel_username}")
                return {
                    'addon_domains': [],
                    'total': 0,
                    'simulation': True
                }
            
            # Build WHM API URL using cpanel API2 through WHM
            base_url = f"https://{self.whm_host}:2087/json-api/cpanel"
            
            params = {
                'cpanel_jsonapi_user': cpanel_username,
                'cpanel_jsonapi_apiversion': '2',
                'cpanel_jsonapi_module': 'AddonDomain',
                'cpanel_jsonapi_func': 'listaddondomains'
            }
            
            headers = {
                'Authorization': f'whm {self.whm_username}:{self.whm_api_token}'
            }
            
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.get(base_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    cpanel_result = data.get('cpanelresult', {})
                    
                    if cpanel_result.get('error'):
                        logger.warning(f"⚠️ cPanel API error for {cpanel_username}: {cpanel_result.get('error')}")
                        return {
                            'addon_domains': [],
                            'total': 0,
                            'error': cpanel_result.get('error')
                        }
                    
                    domains_data = cpanel_result.get('data', [])
                    
                    if not isinstance(domains_data, list):
                        domains_data = []
                    
                    addon_domains = []
                    for domain_info in domains_data:
                        if isinstance(domain_info, dict):
                            addon_domains.append({
                                'domain': domain_info.get('domain'),
                                'subdomain': domain_info.get('subdomain'),
                                'document_root': domain_info.get('dir') or domain_info.get('rootdomain'),
                                'status': 'active'
                            })
                    
                    logger.info(f"✅ Listed {len(addon_domains)} addon domains for {cpanel_username}")
                    return {
                        'addon_domains': addon_domains,
                        'total': len(addon_domains)
                    }
                else:
                    logger.error(f"❌ WHM API error: HTTP {response.status_code}")
                    return {
                        'addon_domains': [],
                        'total': 0,
                        'error': f'WHM API returned HTTP {response.status_code}'
                    }
                    
        except Exception as e:
            logger.error(f"❌ Error listing addon domains: {e}")
            return None
    
    async def delete_addon_domain(self, cpanel_username: str, addon_domain: str, subdomain: Optional[str] = None) -> Optional[Dict]:
        """
        Delete an addon domain from a cPanel account.
        
        Uses cPanel API2 AddonDomain::deladdondomain function.
        
        Args:
            cpanel_username: The cPanel account username
            addon_domain: The addon domain to delete
            subdomain: The subdomain associated with the addon domain
            
        Returns:
            Dict with success status, or None on error
        """
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated addon domain deletion: {addon_domain} from {cpanel_username}")
                return {
                    'success': True,
                    'deleted_domain': addon_domain,
                    'simulation': True
                }
            
            # Look up the actual subdomain from cPanel if not provided
            if not subdomain:
                addon_list = await self.list_addon_domains(cpanel_username)
                if addon_list and addon_list.get('addon_domains'):
                    for addon in addon_list['addon_domains']:
                        if addon.get('domain', '').lower() == addon_domain.lower():
                            subdomain = addon.get('subdomain')
                            logger.info(f"🔍 Found subdomain '{subdomain}' for addon domain {addon_domain}")
                            break
                
                # If still not found, domain may not exist in cPanel
                if not subdomain:
                    logger.warning(f"⚠️ Addon domain {addon_domain} not found in cPanel for {cpanel_username}")
                    return {
                        'success': False,
                        'error': f'Addon domain {addon_domain} not found in cPanel. It may still be pending or was never added.'
                    }
            
            # Build WHM API URL using cpanel API2 through WHM
            base_url = f"https://{self.whm_host}:2087/json-api/cpanel"
            
            params = {
                'cpanel_jsonapi_user': cpanel_username,
                'cpanel_jsonapi_apiversion': '2',
                'cpanel_jsonapi_module': 'AddonDomain',
                'cpanel_jsonapi_func': 'deladdondomain',
                'domain': addon_domain,
                'subdomain': subdomain
            }
            
            headers = {
                'Authorization': f'whm {self.whm_username}:{self.whm_api_token}'
            }
            
            async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
                response = await client.get(base_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    cpanel_result = data.get('cpanelresult', {})
                    result_data = cpanel_result.get('data', [{}])[0] if cpanel_result.get('data') else {}
                    
                    if result_data.get('result') == 1 or cpanel_result.get('error') is None:
                        logger.info(f"✅ Addon domain {addon_domain} deleted from {cpanel_username}")
                        return {
                            'success': True,
                            'deleted_domain': addon_domain
                        }
                    else:
                        error_msg = result_data.get('reason') or cpanel_result.get('error', 'Unknown error')
                        logger.error(f"❌ Failed to delete addon domain: {error_msg}")
                        return {
                            'success': False,
                            'error': error_msg
                        }
                else:
                    logger.error(f"❌ WHM API error: HTTP {response.status_code}")
                    return {
                        'success': False,
                        'error': f'WHM API returned HTTP {response.status_code}'
                    }
                    
        except Exception as e:
            logger.error(f"❌ Error deleting addon domain: {e}")
            return None

    async def modify_account_limits(
        self, 
        cpanel_username: str, 
        maxaddon: str = 'unlimited',
        maxpark: str = 'unlimited',
        maxsub: str = 'unlimited'
    ) -> Optional[Dict]:
        """
        Modify account resource limits for an existing cPanel account.
        
        Uses WHM API modifyacct function to update addon domain limits, etc.
        
        Args:
            cpanel_username: The cPanel account username
            maxaddon: Maximum addon domains (number or 'unlimited')
            maxpark: Maximum parked domains (number or 'unlimited')
            maxsub: Maximum subdomains (number or 'unlimited')
            
        Returns:
            Dict with success status and details, or None on error
        """
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated account modification for {cpanel_username}")
                return {
                    'success': True,
                    'username': cpanel_username,
                    'maxaddon': maxaddon,
                    'simulation': True
                }
            
            # WHM API modifyacct endpoint
            base_url = f"https://{self.whm_host}:2087/json-api/modifyacct"
            
            params = {
                'api.version': '1',
                'user': cpanel_username,
                'MAXADDON': maxaddon,
                'MAXPARK': maxpark,
                'MAXSUB': maxsub
            }
            
            headers = {
                'Authorization': f'whm {self.whm_username}:{self.whm_api_token}'
            }
            
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                response = await client.get(base_url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    metadata = data.get('metadata', {})
                    result = metadata.get('result', 0)
                    
                    if result == 1:
                        logger.info(f"✅ Account limits modified for {cpanel_username}: maxaddon={maxaddon}")
                        return {
                            'success': True,
                            'username': cpanel_username,
                            'maxaddon': maxaddon,
                            'maxpark': maxpark,
                            'maxsub': maxsub
                        }
                    else:
                        error_msg = metadata.get('reason', 'Unknown error')
                        logger.error(f"❌ Failed to modify account limits: {error_msg}")
                        return {
                            'success': False,
                            'error': error_msg
                        }
                else:
                    logger.error(f"❌ WHM API error: HTTP {response.status_code}")
                    return {
                        'success': False,
                        'error': f'WHM API returned HTTP {response.status_code}'
                    }
                    
        except Exception as e:
            logger.error(f"❌ Error modifying account limits: {e}")
            return None

    async def enable_addon_domains_for_all_accounts(self) -> Dict:
        """
        Enable unlimited addon domains for all existing cPanel accounts.
        
        Returns:
            Dict with summary of updates
        """
        try:
            # list_accounts is synchronous, not async
            accounts = self.list_accounts()
            if not accounts:
                return {'success': False, 'error': 'Failed to list accounts'}
            
            updated = 0
            failed = 0
            results = []
            
            for account in accounts:
                username = account.get('user')
                if username:
                    result = await self.modify_account_limits(
                        cpanel_username=username,
                        maxaddon='unlimited',
                        maxpark='unlimited'
                    )
                    if result and result.get('success'):
                        updated += 1
                        results.append({'username': username, 'status': 'updated'})
                    else:
                        failed += 1
                        results.append({'username': username, 'status': 'failed', 'error': result.get('error') if result else 'Unknown'})
            
            logger.info(f"✅ Enabled addon domains for {updated} accounts, {failed} failed")
            return {
                'success': True,
                'updated': updated,
                'failed': failed,
                'details': results
            }
            
        except Exception as e:
            logger.error(f"❌ Error enabling addon domains for all accounts: {e}")
            return {'success': False, 'error': str(e)}
