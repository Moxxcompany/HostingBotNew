"""
FastForex Exchange Rate Service
Provides real-time cryptocurrency and fiat exchange rates with non-blocking cache
"""

import os
import httpx
import asyncio
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)

# Supported cryptocurrencies
SUPPORTED_CRYPTOS = ['BTC', 'ETH', 'LTC', 'DOGE', 'USDT-ERC20', 'USDT-TRC20']

class FastForexService:
    """
    FastForex API service for real-time exchange rates with non-blocking cache.
    
    Key Features:
    - Non-blocking fetch_cached_rate() that never waits for API calls
    - Background pre-warming via prewarm_rates() 
    - Circuit breaker to detect API failures
    - 3-second timeout to prevent webhook delays
    - 10-minute cache duration with stale-while-revalidate pattern
    """
    
    def __init__(self):
        self.api_key = os.getenv('FASTFOREX_API_KEY')
        self.base_url = "https://api.fastforex.io"
        self.cache = {}
        self.cache_duration = timedelta(minutes=10)  # Extended to 10 minutes per architect
        self.cache_lock = asyncio.Lock()  # Thread-safe cache updates
        
        # Circuit breaker state
        self.consecutive_failures = 0
        self.max_failures = 5  # Alert after 5 consecutive failures
        self.last_alert_time = None
        self.circuit_open_until = None  # Timestamp when circuit will close again
        self.circuit_backoff_seconds = 60  # Skip API calls for 60s after repeated failures
        
        if self.api_key:
            logger.info("📈 FastForex service initialized with API key (cache: 10min, timeout: 3s)")
        else:
            logger.warning("⚠️ FastForex API key not found - will use fallback rates")
    
    def is_available(self) -> bool:
        """Check if FastForex service is properly configured"""
        return bool(self.api_key)
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid"""
        if cache_key not in self.cache:
            return False
        
        cached_data = self.cache[cache_key]
        if 'timestamp' not in cached_data:
            return False
        
        cache_time = cached_data['timestamp']
        return datetime.now() - cache_time < self.cache_duration
    
    async def get_crypto_rate(self, crypto_symbol: str, base_currency: str = "USD") -> Optional[float]:
        """
        Get current exchange rate for a cryptocurrency
        
        Args:
            crypto_symbol: Cryptocurrency symbol (e.g., 'BTC', 'ETH', 'LTC', 'USDT-ERC20')
            base_currency: Base currency (default: 'USD')
            
        Returns:
            Exchange rate as float, or None if not available
        """
        if not self.is_available():
            logger.warning(f"⚠️ FastForex not available, using fallback for {crypto_symbol}")
            return self._get_fallback_rate(crypto_symbol)
        
        cache_key = f"{crypto_symbol}-{base_currency}"
        
        # Check cache first
        if self._is_cache_valid(cache_key):
            logger.debug(f"📊 Using cached rate for {crypto_symbol}: {self.cache[cache_key]['rate']}")
            return self.cache[cache_key]['rate']
        
        # Check if circuit breaker is open (too many recent failures)
        if self.circuit_open_until and datetime.now() < self.circuit_open_until:
            remaining = (self.circuit_open_until - datetime.now()).seconds
            logger.warning(f"⚡ Circuit breaker OPEN for {crypto_symbol} - skipping API call ({remaining}s remaining)")
            return self._get_fallback_rate(crypto_symbol)
        
        # Normalize stablecoin variants - FastForex doesn't support USDT-ERC20/USDT-TRC20
        # These should be normalized to USDT for API calls (all map to ~1.0 USD)
        api_symbol = crypto_symbol
        if crypto_symbol.startswith('USDT-'):
            # For USDT variants (USDT-ERC20, USDT-TRC20), use fallback directly
            # as FastForex doesn't support these specific variants
            logger.info(f"📊 Using fallback rate for {crypto_symbol}: 1 USD = 1.0 {crypto_symbol}")
            # Cache it so we don't try again
            async with self.cache_lock:
                self.cache[cache_key] = {
                    'rate': 1.0,
                    'timestamp': datetime.now()
                }
            return 1.0
        
        try:
            # Fetch from FastForex API
            async with httpx.AsyncClient() as client:
                # FastForex uses different endpoint for crypto vs fiat
                url = f"{self.base_url}/fetch-one"
                params = {
                    'api_key': self.api_key,
                    'from': base_currency,
                    'to': api_symbol
                }
                
                # Reduced timeout from 10s to 3s to prevent webhook delays
                timeout_config = httpx.Timeout(3.0, connect=1.5)
                response = await client.get(url, params=params, timeout=timeout_config)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # FastForex returns rate in 'result' field
                    # Use uppercase for API lookup (FastForex returns uppercase keys like 'BTC')
                    api_key = api_symbol.upper()
                    if 'result' in data and api_key in data['result']:
                        rate = float(data['result'][api_key])
                        
                        # Cache the result with thread-safe locking
                        async with self.cache_lock:
                            self.cache[cache_key] = {
                                'rate': rate,
                                'timestamp': datetime.now()
                            }
                        
                        # Reset circuit breaker on success
                        self.consecutive_failures = 0
                        self.circuit_open_until = None
                        
                        logger.info(f"📈 FastForex rate for {crypto_symbol}: 1 {base_currency} = {rate} {crypto_symbol}")
                        return rate
                    else:
                        logger.error(f"❌ FastForex API missing rate data for {crypto_symbol}: {data}")
                        self._record_failure()
                        return self._get_fallback_rate(crypto_symbol)
                else:
                    logger.error(f"❌ FastForex API error: {response.status_code} - {response.text}")
                    self._record_failure()
                    return self._get_fallback_rate(crypto_symbol)
                    
        except Exception as e:
            logger.error(f"❌ FastForex API request failed for {crypto_symbol}: {str(e)}")
            self._record_failure()
            return self._get_fallback_rate(crypto_symbol)
    
    def _get_fallback_rate(self, crypto_symbol: str) -> float:
        """
        Fallback exchange rates when FastForex is unavailable
        These are approximate rates updated as of December 2025
        """
        fallback_rates = {
            'BTC': 0.00001,    # 1 USD = ~0.00001 BTC (≈$100,000 per BTC)
            'ETH': 0.00033,    # 1 USD = ~0.00033 ETH (≈$3,000 per ETH)  
            'LTC': 0.012,      # 1 USD = ~0.012 LTC (≈$83 per LTC)
            'DOGE': 7.0,       # 1 USD = ~7 DOGE (≈$0.14 per DOGE)
            'USDT': 1.0,       # 1 USD = ~1.0 USDT (≈$1 per USDT)
            'USDT-ERC20': 1.0, # 1 USD = ~1.0 USDT (≈$1 per USDT)
            'USDT-TRC20': 1.0  # 1 USD = ~1.0 USDT (≈$1 per USDT)
        }
        
        rate = fallback_rates.get(crypto_symbol.upper(), 1.0)
        logger.info(f"📊 Using fallback rate for {crypto_symbol}: 1 USD = {rate} {crypto_symbol}")
        return rate
    
    async def get_usd_to_crypto_amount(self, usd_amount: float, crypto_symbol: str) -> tuple[float, str]:
        """
        Convert USD amount to crypto amount with formatted display
        
        Args:
            usd_amount: Amount in USD
            crypto_symbol: Target cryptocurrency symbol
            
        Returns:
            Tuple of (crypto_amount, formatted_display_string)
        """
        rate = await self.get_crypto_rate(crypto_symbol, "USD")
        if not rate:
            return 0.0, "TBD"
        
        crypto_amount = usd_amount * rate
        
        # Format crypto amount for display (strip trailing zeros)
        from pricing_utils import format_crypto_amount
        formatted = format_crypto_amount(crypto_amount, crypto_symbol)
        
        logger.debug(f"💱 Converted ${usd_amount} USD → {formatted}")
        return crypto_amount, formatted
    
    def clear_cache(self):
        """Clear the exchange rate cache"""
        self.cache.clear()
        logger.info("🗑️ FastForex cache cleared")
    
    def _record_failure(self):
        """Record API failure for circuit breaker"""
        self.consecutive_failures += 1
        
        # Open circuit breaker after max failures (stop making API calls temporarily)
        if self.consecutive_failures >= self.max_failures:
            now = datetime.now()
            self.circuit_open_until = now + timedelta(seconds=self.circuit_backoff_seconds)
            
            # Only alert once per hour
            if not self.last_alert_time or (now - self.last_alert_time) > timedelta(hours=1):
                logger.error(
                    f"🚨 ALERT: FastForex API has failed {self.consecutive_failures} consecutive times! "
                    f"Circuit breaker OPEN for {self.circuit_backoff_seconds}s. Using fallback rates."
                )
                self.last_alert_time = now
    
    async def fetch_cached_rate(self, crypto_symbol: str, base_currency: str = "USD") -> Tuple[float, str]:
        """
        Non-blocking fetch of exchange rate - NEVER waits for API calls.
        
        Returns cached rate if available, or fallback rate immediately.
        If cache is stale, schedules async refresh in background.
        
        Args:
            crypto_symbol: Cryptocurrency symbol (e.g., 'BTC', 'ETH', 'LTC')
            base_currency: Base currency (default: 'USD')
            
        Returns:
            Tuple of (rate, source) where source is 'cache', 'api', or 'fallback'
        """
        cache_key = f"{crypto_symbol}-{base_currency}"
        
        # Check if we have cached data
        if cache_key in self.cache:
            cached_data = self.cache[cache_key]
            cache_age = datetime.now() - cached_data['timestamp']
            rate = cached_data['rate']
            
            # Return cached rate immediately
            if cache_age < self.cache_duration:
                logger.debug(f"📊 Cache HIT for {crypto_symbol}: {rate} (age: {cache_age.seconds}s)")
                return rate, 'cache'
            else:
                # Cache is stale - return it anyway and refresh in background
                logger.info(f"⏰ Cache STALE for {crypto_symbol}: {rate} (age: {cache_age.seconds}s) - refreshing in background")
                
                # Fire-and-forget background refresh
                asyncio.create_task(self._refresh_rate_async(crypto_symbol, base_currency))
                
                return rate, 'cache_stale'
        
        # No cache - use fallback and trigger background fetch
        fallback_rate = self._get_fallback_rate(crypto_symbol)
        logger.warning(f"⚠️ Cache MISS for {crypto_symbol}: using fallback {fallback_rate} - fetching in background")
        
        # Fire-and-forget background fetch
        asyncio.create_task(self._refresh_rate_async(crypto_symbol, base_currency))
        
        return fallback_rate, 'fallback'
    
    async def _refresh_rate_async(self, crypto_symbol: str, base_currency: str = "USD"):
        """
        Background task to refresh a single exchange rate.
        Updates cache but doesn't return value (fire-and-forget).
        """
        try:
            # Use existing get_crypto_rate which handles caching
            await self.get_crypto_rate(crypto_symbol, base_currency)
            logger.debug(f"✅ Background refresh completed for {crypto_symbol}")
        except Exception as e:
            logger.error(f"❌ Background refresh failed for {crypto_symbol}: {e}")
    
    async def prewarm_rates(self):
        """
        Pre-warm cache for all supported cryptocurrencies using a single batch API call.
        Called by APScheduler background job every 3 minutes.
        """
        if not self.api_key:
            return 0, len(SUPPORTED_CRYPTOS)

        logger.info(f"🔄 Batch pre-warming exchange rates for {len(SUPPORTED_CRYPTOS)} currencies...")
        start_time = datetime.now()
        
        try:
            # Use fetch-all to get all rates for USD in one call
            async with httpx.AsyncClient() as client:
                url = f"{self.base_url}/fetch-all"
                params = {
                    'api_key': self.api_key,
                    'from': 'USD'
                }
                
                timeout_config = httpx.Timeout(5.0, connect=2.0)
                response = await client.get(url, params=params, timeout=timeout_config)
                
                if response.status_code == 200:
                    data = response.json()
                    results = data.get('results', {})
                    
                    success_count = 0
                    async with self.cache_lock:
                        for crypto in SUPPORTED_CRYPTOS:
                            # Normalize for API check (some might be lowercase in results)
                            rate = results.get(crypto.upper()) or results.get(crypto.lower())
                            
                            if rate is not None:
                                cache_key = f"{crypto}-USD"
                                self.cache[cache_key] = {
                                    'rate': float(rate),
                                    'timestamp': datetime.now()
                                }
                                success_count += 1
                    
                    duration = (datetime.now() - start_time).total_seconds()
                    logger.info(f"✅ Batch pre-warm SUCCESS: {success_count}/{len(SUPPORTED_CRYPTOS)} rates updated in {duration:.2f}s")
                    
                    # Reset circuit breaker
                    self.consecutive_failures = 0
                    self.circuit_open_until = None
                    
                    return success_count, len(SUPPORTED_CRYPTOS) - success_count
                else:
                    logger.error(f"❌ FastForex batch API error: {response.status_code}")
                    self._record_failure()
                    return 0, len(SUPPORTED_CRYPTOS)
                    
        except Exception as e:
            logger.error(f"❌ Batch pre-warm FAILED: {e}")
            self._record_failure()
            return 0, len(SUPPORTED_CRYPTOS)
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics for monitoring"""
        now = datetime.now()
        stats = {
            'total_cached': len(self.cache),
            'fresh_count': 0,
            'stale_count': 0,
            'consecutive_failures': self.consecutive_failures,
            'rates': {}
        }
        
        for cache_key, data in self.cache.items():
            age_seconds = (now - data['timestamp']).total_seconds()
            is_fresh = age_seconds < self.cache_duration.total_seconds()
            
            if is_fresh:
                stats['fresh_count'] += 1
            else:
                stats['stale_count'] += 1
            
            stats['rates'][cache_key] = {
                'rate': data['rate'],
                'age_seconds': int(age_seconds),
                'is_fresh': is_fresh
            }
        
        return stats

# Global service instance
fastforex_service = FastForexService()
