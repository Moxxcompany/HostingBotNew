"""
Vultr API Service
Handles Windows RDP server provisioning and management via Vultr API
"""

import os
import requests
import logging
from typing import Dict, List, Optional, Any
from decimal import Decimal
import asyncio
from cryptography.fernet import Fernet
import base64
import hashlib

logger = logging.getLogger(__name__)

class VultrService:
    """Vultr API wrapper for RDP server management"""
    
    def __init__(self):
        self.api_key = os.environ.get('VULTR_API_KEY')
        if not self.api_key:
            logger.warning("VULTR_API_KEY environment variable not set - Vultr features disabled")
        
        self.base_url = 'https://api.vultr.com/v2'
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        # Initialize encryption for password storage
        self._init_encryption()
    
    def _init_encryption(self):
        """Initialize Fernet encryption for password storage"""
        # Use a key derived from a secret (in production, use proper key management)
        secret = os.environ.get('DATABASE_ENCRYPTION_KEY', 'default-key-change-in-production')
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
        self.cipher = Fernet(key)
    
    def encrypt_password(self, password: str) -> str:
        """Encrypt password for storage"""
        return self.cipher.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted: str) -> str:
        """Decrypt password from storage"""
        return self.cipher.decrypt(encrypted.encode()).decode()
    
    # === API Methods ===
    
    def get_regions(self) -> List[Dict[str, Any]]:
        """Get all available Vultr regions"""
        try:
            response = requests.get(
                f'{self.base_url}/regions',
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            return response.json().get('regions', [])
        except Exception as e:
            logger.error(f"Failed to fetch Vultr regions: {e}")
            return []
    
    def get_plans(self) -> List[Dict[str, Any]]:
        """Get all available Vultr plans"""
        try:
            response = requests.get(
                f'{self.base_url}/plans',
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            plans = response.json().get('plans', [])
            
            # Filter for Cloud Compute (vc2) plans
            return [p for p in plans if p.get('type') == 'vc2']
        except Exception as e:
            logger.error(f"Failed to fetch Vultr plans: {e}")
            return []
    
    def get_os_list(self) -> List[Dict[str, Any]]:
        """Get all available operating systems"""
        try:
            response = requests.get(
                f'{self.base_url}/os',
                headers=self.headers,
                timeout=15
            )
            response.raise_for_status()
            return response.json().get('os', [])
        except Exception as e:
            logger.error(f"Failed to fetch Vultr OS list: {e}")
            return []
    
    def create_instance(
        self,
        region: str,
        plan: str,
        os_id: int,
        label: str,
        hostname: str
    ) -> Optional[Dict[str, Any]]:
        """
        Create a new Vultr instance
        
        Args:
            region: Region ID (e.g., 'ewr')
            plan: Plan ID (e.g., 'vc2-1c-2gb')
            os_id: Operating system ID
            label: Server label
            hostname: Server hostname
        
        Returns:
            Instance data if successful, None otherwise
        """
        try:
            data = {
                "region": region,
                "plan": plan,
                "os_id": os_id,
                "label": label,
                "hostname": hostname
            }
            
            response = requests.post(
                f'{self.base_url}/instances',
                headers=self.headers,
                json=data,
                timeout=30
            )
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Created Vultr instance: {result.get('instance', {}).get('id')}")
            return result.get('instance')
        
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error creating Vultr instance: {e}")
            logger.error(f"Response: {e.response.text if e.response else 'No response'}")
            return None
        except Exception as e:
            logger.error(f"Failed to create Vultr instance: {e}")
            return None
    
    def list_instances(self) -> Optional[List[Dict[str, Any]]]:
        """
        List all instances in the Vultr account
        
        Returns:
            List of instance data if successful, None on error
        """
        try:
            all_instances = []
            cursor = ""
            
            while True:
                params = {"per_page": 100}
                if cursor:
                    params["cursor"] = cursor
                
                response = requests.get(
                    f'{self.base_url}/instances',
                    headers=self.headers,
                    params=params,
                    timeout=15
                )
                response.raise_for_status()
                
                data = response.json()
                instances = data.get('instances', [])
                all_instances.extend(instances)
                
                meta = data.get('meta', {})
                links = meta.get('links', {})
                next_cursor = links.get('next', '')
                
                if not next_cursor or next_cursor == cursor:
                    break
                cursor = next_cursor
            
            logger.info(f"📊 Listed {len(all_instances)} instances from Vultr")
            return all_instances
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error listing Vultr instances: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to list Vultr instances: {e}")
            return None
    
    def get_instance(self, instance_id: str) -> tuple[Optional[Dict[str, Any]], Optional[int]]:
        """
        Get instance details
        
        Returns:
            Tuple of (instance_data, http_status_code)
            - (instance_dict, 200) on success
            - (None, 404) if instance not found
            - (None, None) on other errors (network, timeout, 500, etc.)
        """
        try:
            response = requests.get(
                f'{self.base_url}/instances/{instance_id}',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return (response.json().get('instance'), 200)
            elif response.status_code == 404:
                logger.info(f"Vultr instance {instance_id} not found (404)")
                return (None, 404)
            else:
                logger.warning(f"Unexpected status {response.status_code} getting instance {instance_id}")
                return (None, response.status_code)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error getting Vultr instance {instance_id}: {e}")
            return (None, None)
        except Exception as e:
            logger.error(f"Failed to get Vultr instance {instance_id}: {e}")
            return (None, None)
    
    def delete_instance(self, instance_id: str) -> bool:
        """
        Delete an instance
        
        Returns:
            True if instance was deleted or already doesn't exist (404)
            False if deletion failed
        """
        try:
            response = requests.delete(
                f'{self.base_url}/instances/{instance_id}',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 204:
                logger.info(f"✅ Deleted Vultr instance: {instance_id}")
                return True
            elif response.status_code == 404:
                logger.info(f"✅ Vultr instance {instance_id} already deleted (404) - treating as success")
                return True
            else:
                logger.warning(f"⚠️ Unexpected response deleting instance {instance_id}: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"❌ Failed to delete Vultr instance {instance_id}: {e}")
            return False
    
    def start_instance(self, instance_id: str) -> bool:
        """Start a stopped instance"""
        try:
            response = requests.post(
                f'{self.base_url}/instances/{instance_id}/start',
                headers=self.headers,
                timeout=30
            )
            if response.status_code == 204:
                logger.info(f"✅ Successfully started instance {instance_id}")
                return True
            else:
                logger.error(f"❌ Failed to start instance {instance_id}: HTTP {response.status_code}, Response: {response.text}")
                return False
        except Exception as e:
            logger.error(f"❌ Exception starting instance {instance_id}: {e}")
            return False
    
    def stop_instance(self, instance_id: str) -> bool:
        """Stop a running instance"""
        try:
            response = requests.post(
                f'{self.base_url}/instances/{instance_id}/halt',
                headers=self.headers,
                timeout=30
            )
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Failed to stop instance {instance_id}: {e}")
            return False
    
    def reboot_instance(self, instance_id: str) -> bool:
        """Reboot an instance"""
        try:
            response = requests.post(
                f'{self.base_url}/instances/{instance_id}/reboot',
                headers=self.headers,
                timeout=30
            )
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Failed to reboot instance {instance_id}: {e}")
            return False
    
    def reinstall_instance(self, instance_id: str) -> bool:
        """Reinstall OS (resets password)"""
        try:
            response = requests.post(
                f'{self.base_url}/instances/{instance_id}/reinstall',
                headers=self.headers,
                timeout=30
            )
            return response.status_code == 202
        except Exception as e:
            logger.error(f"Failed to reinstall instance {instance_id}: {e}")
            return False
    
    async def wait_for_instance_ready(
        self,
        instance_id: str,
        timeout: int = 300,
        poll_interval: int = 10
    ) -> Optional[Dict[str, Any]]:
        """
        Wait for instance to be ready with IP address
        
        Args:
            instance_id: Vultr instance ID
            timeout: Maximum wait time in seconds
            poll_interval: Time between status checks
        
        Returns:
            Instance data when ready, None if timeout
        """
        import time
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            instance, http_status = self.get_instance(instance_id)
            
            if not instance:
                await asyncio.sleep(poll_interval)
                continue
            
            status = instance.get('status')
            main_ip = instance.get('main_ip')
            
            # Ready when status is 'active' and has valid IP
            if status == 'active' and main_ip and main_ip != '0.0.0.0':
                logger.info(f"Instance {instance_id} is ready: {main_ip}")
                return instance
            
            await asyncio.sleep(poll_interval)
        
        logger.warning(f"Timeout waiting for instance {instance_id}")
        return None


# Global instance (lazy - doesn't crash if VULTR_API_KEY is missing)
try:
    vultr_service = VultrService()
except Exception as e:
    logger.warning(f"Vultr service not initialized: {e}")
    vultr_service = None
