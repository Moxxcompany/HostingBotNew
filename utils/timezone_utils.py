"""
Comprehensive Timezone Consistency Utilities
Ensures all datetime operations use UTC and provides safe conversion utilities
"""

import os
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, Any, Dict
import pytz

logger = logging.getLogger(__name__)

# Set system timezone to UTC
os.environ['TZ'] = 'UTC'
time.tzset()

class TimezoneManager:
    """Centralized timezone management for production consistency"""
    
    def __init__(self):
        self.utc = timezone.utc
        self.system_timezone = self._detect_system_timezone()
        self._log_timezone_status()
    
    def _detect_system_timezone(self) -> timezone:
        """Detect and validate system timezone"""
        try:
            # Force UTC for consistency
            return timezone.utc
        except Exception as e:
            logger.warning(f"⚠️ Timezone detection error: {e}, using UTC")
            return timezone.utc
    
    def _log_timezone_status(self):
        """Log current timezone configuration"""
        current_time = self.now()
        logger.info(f"🌍 Timezone Manager Initialized:")
        logger.info(f"   • System Timezone: {self.system_timezone}")
        logger.info(f"   • Current UTC Time: {current_time.isoformat()}")
        logger.info(f"   • Environment TZ: {os.environ.get('TZ', 'not set')}")
    
    def now(self) -> datetime:
        """Get current time in UTC"""
        return datetime.now(self.utc)
    
    def utc_timestamp(self) -> float:
        """Get current UTC timestamp"""
        return time.time()
    
    def to_utc(self, dt: Union[datetime, str, float, int]) -> datetime:
        """Convert various datetime formats to UTC datetime"""
        if dt is None:
            return self.now()
        
        if isinstance(dt, (int, float)):
            # Unix timestamp
            return datetime.fromtimestamp(dt, self.utc)
        
        if isinstance(dt, str):
            # ISO string or other string formats
            return self._parse_datetime_string(dt)
        
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                # Naive datetime - assume UTC
                logger.debug(f"⚠️ Converting naive datetime to UTC: {dt}")
                return dt.replace(tzinfo=self.utc)
            else:
                # Timezone-aware datetime - convert to UTC
                return dt.astimezone(self.utc)
        
        raise ValueError(f"Cannot convert {type(dt)} to UTC datetime: {dt}")
    
    def _parse_datetime_string(self, dt_str: str) -> datetime:
        """Parse datetime string to UTC datetime"""
        if not dt_str:
            return self.now()
        
        # Try ISO format first
        try:
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            return self.to_utc(dt)
        except ValueError:
            pass
        
        # Try common formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%d',
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(dt_str, fmt)
                return dt.replace(tzinfo=self.utc)
            except ValueError:
                continue
        
        logger.warning(f"⚠️ Could not parse datetime string: {dt_str}, using current time")
        return self.now()
    
    def format_utc(self, dt: Optional[datetime] = None, format_type: str = 'iso') -> str:
        """Format UTC datetime in various formats"""
        if dt is None:
            dt = self.now()
        
        # Ensure it's UTC
        dt = self.to_utc(dt)
        
        if format_type == 'iso':
            return dt.isoformat()
        elif format_type == 'timestamp':
            return str(int(dt.timestamp()))
        elif format_type == 'human':
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        elif format_type == 'filename':
            return dt.strftime('%Y%m%d_%H%M%S')
        else:
            return dt.isoformat()
    
    def add_seconds(self, dt: datetime, seconds: Union[int, float]) -> datetime:
        """Add seconds to datetime maintaining UTC"""
        dt = self.to_utc(dt)
        return dt + timedelta(seconds=seconds)
    
    def add_days(self, dt: datetime, days: int) -> datetime:
        """Add days to datetime maintaining UTC"""
        dt = self.to_utc(dt)
        return dt + timedelta(days=days)
    
    def time_diff_seconds(self, dt1: datetime, dt2: datetime) -> float:
        """Calculate difference between two datetimes in seconds"""
        dt1 = self.to_utc(dt1)
        dt2 = self.to_utc(dt2)
        return (dt1 - dt2).total_seconds()
    
    def is_expired(self, dt: datetime, ttl_seconds: Union[int, float]) -> bool:
        """Check if datetime is expired based on TTL"""
        dt = self.to_utc(dt)
        now = self.now()
        return (now - dt).total_seconds() > ttl_seconds
    
    def validate_timezone_consistency(self) -> Dict[str, Any]:
        """Validate system timezone consistency"""
        checks = {
            'system_tz_utc': os.environ.get('TZ') == 'UTC',
            'datetime_now_utc': datetime.now().tzinfo is None,  # Should be naive in UTC system
            'time_module_utc': time.tzname[0] == 'UTC',
            'current_utc_time': self.now().isoformat(),
            'warnings': []
        }
        
        if not checks['system_tz_utc']:
            checks['warnings'].append('System TZ environment variable not set to UTC')
        
        if not checks['time_module_utc']:
            checks['warnings'].append('Time module not using UTC timezone')
        
        # Log validation results
        if checks['warnings']:
            logger.warning(f"⚠️ Timezone consistency issues: {checks['warnings']}")
        else:
            logger.info("✅ Timezone consistency validated - all systems using UTC")
        
        return checks

# Global timezone manager
_timezone_manager: Optional[TimezoneManager] = None

def get_timezone_manager() -> TimezoneManager:
    """Get global timezone manager instance"""
    global _timezone_manager
    if _timezone_manager is None:
        _timezone_manager = TimezoneManager()
    return _timezone_manager

# Convenience functions for common operations
def utc_now() -> datetime:
    """Get current UTC time"""
    return get_timezone_manager().now()

def to_utc(dt: Union[datetime, str, float, int]) -> datetime:
    """Convert any datetime format to UTC"""
    return get_timezone_manager().to_utc(dt)

def utc_timestamp() -> float:
    """Get current UTC timestamp"""
    return get_timezone_manager().utc_timestamp()

def format_utc(dt: Optional[datetime] = None, format_type: str = 'iso') -> str:
    """Format UTC datetime"""
    return get_timezone_manager().format_utc(dt, format_type)

def is_expired(dt: datetime, ttl_seconds: Union[int, float]) -> bool:
    """Check if datetime is expired"""
    return get_timezone_manager().is_expired(dt, ttl_seconds)

def validate_timezone_consistency() -> Dict[str, Any]:
    """Validate system timezone consistency"""
    return get_timezone_manager().validate_timezone_consistency()

# Database integration helpers
def get_utc_for_db() -> str:
    """Get UTC timestamp string for database insertion"""
    return utc_now().isoformat()

def parse_db_timestamp(timestamp_str: str) -> datetime:
    """Parse database timestamp to UTC datetime"""
    return to_utc(timestamp_str)

# Decorator for ensuring functions use UTC
def ensure_utc(func):
    """Decorator to ensure function operates in UTC context"""
    def wrapper(*args, **kwargs):
        # Validate timezone before function execution
        tz_status = validate_timezone_consistency()
        if tz_status['warnings']:
            logger.warning(f"⚠️ Timezone issues detected before {func.__name__}: {tz_status['warnings']}")
        
        result = func(*args, **kwargs)
        return result
    
    return wrapper

# Context manager for timezone operations
class UTCContext:
    """Context manager for ensuring UTC operations"""
    
    def __enter__(self):
        self.tz_manager = get_timezone_manager()
        self.start_time = self.tz_manager.now()
        return self.tz_manager
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = self.tz_manager.now()
        duration = self.tz_manager.time_diff_seconds(end_time, self.start_time)
        
        if duration > 1.0:  # Log slow operations
            logger.debug(f"🕐 UTC operation completed in {duration:.3f}s")
        
        if exc_type:
            logger.error(f"❌ UTC operation failed: {exc_val}")

# Telegram language_code -> approximate UTC offset mapping
# Based on most common timezone for each language's primary country
LANGUAGE_CODE_TO_TIMEZONE = {
    # Western Europe (UTC+1)
    'fr': 1, 'de': 1, 'it': 1, 'es': 1, 'nl': 1, 'da': 1, 'nb': 1, 'sv': 1, 'pl': 1,
    'cs': 1, 'sk': 1, 'hu': 1, 'hr': 1, 'sl': 1, 'bs': 1, 'sr': 1, 'mk': 1, 'sq': 1,
    'mt': 1, 'lb': 1,
    # Eastern Europe (UTC+2)
    'el': 2, 'bg': 2, 'ro': 2, 'uk': 2, 'fi': 2, 'et': 2, 'lv': 2, 'lt': 2,
    # Russia / Moscow (UTC+3)
    'ru': 3,
    # Turkey (UTC+3)
    'tr': 3,
    # Arabic - broad spread, default to Gulf (UTC+3)
    'ar': 3,
    # Iran (UTC+3:30 -> round to 4)
    'fa': 4,
    # India (UTC+5:30 -> round to 5)
    'hi': 5, 'bn': 5, 'ta': 5, 'te': 5, 'mr': 5, 'gu': 5, 'kn': 5, 'ml': 5, 'pa': 5,
    'ur': 5, 'ne': 5, 'si': 5,
    # Central Asia (UTC+6)
    'kk': 6, 'uz': 5,
    # Southeast Asia (UTC+7)
    'th': 7, 'vi': 7, 'id': 7, 'ms': 8,
    # East Asia (UTC+8)
    'zh': 8, 'zh-hans': 8, 'zh-hant': 8,
    # Japan / Korea (UTC+9)
    'ja': 9, 'ko': 9,
    # Australia (UTC+10)
    'en-au': 10,
    # New Zealand (UTC+12)
    'en-nz': 12,
    # Americas
    'pt': -3, 'pt-br': -3,  # Brazil
    # English defaults to UTC (0) since it's too broad
    'en': 0,
    # North America - too broad for 'en', but specific codes:
    'en-us': -5, 'en-ca': -5, 'en-gb': 0,
}


def detect_timezone_from_language_code(language_code: str) -> int:
    """
    Detect approximate timezone UTC offset from Telegram language_code.
    Returns the offset in hours, or 0 (UTC) if unknown.
    """
    if not language_code:
        return 0
    
    lc = language_code.lower().strip()
    
    # Try exact match first (e.g., 'pt-br', 'zh-hans')
    if lc in LANGUAGE_CODE_TO_TIMEZONE:
        return LANGUAGE_CODE_TO_TIMEZONE[lc]
    
    # Try base language (e.g., 'pt' from 'pt-br')
    base = lc.split('-')[0]
    if base in LANGUAGE_CODE_TO_TIMEZONE:
        return LANGUAGE_CODE_TO_TIMEZONE[base]
    
    return 0


# Initialize timezone consistency on module import
try:
    tz_manager = get_timezone_manager()
    consistency_check = validate_timezone_consistency()
    if consistency_check['warnings']:
        logger.warning(f"⚠️ Timezone initialization warnings: {consistency_check['warnings']}")
    else:
        logger.info("✅ Timezone utilities initialized successfully")
except Exception as e:
    logger.error(f"❌ Timezone initialization error: {e}")