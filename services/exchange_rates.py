"""
Dynamic Exchange Rate Service for HostBay
Replaces hardcoded EUR_TO_USD with real-time API rates
Uses ExchangeRate-API with performance caching for reliability
"""

import os
import logging
import httpx
import time
from typing import Dict, Optional, Any
from decimal import Decimal, ROUND_HALF_UP
from performance_cache import cache_get, cache_set, cache_invalidate_category
from performance_monitor import monitor_performance, OperationTimer
from financial_precision import (
    to_decimal, to_currency_decimal, decimal_multiply, decimal_divide,
    ZERO, ONE
)

logger = logging.getLogger(__name__)

class ExchangeRateService:
    """
    High-performance exchange rate service with caching and fallback
    Optimized for 20+ ops/sec throughput target
    """
    
    def __init__(self):
        # FastForex API (restore working service from yesterday)
        self.fastforex_api_key = os.getenv('FASTFOREX_API_KEY')
        self.fastforex_api_url = "https://api.fastforex.io"
        
        # Primary API: ExchangeRate-API (1,500 requests/month free)
        self.primary_api_url = "https://v6.exchangerate-api.com/v6"
        self.api_key = os.getenv('EXCHANGE_RATE_API_KEY', '')  # Optional for free tier
        
        # Fallback API: Fawazahmed0 (unlimited, no key required)
        self.fallback_api_url = "https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies"
        
        # Crypto currencies that need special handling
        self.crypto_currencies = {'BTC', 'ETH', 'LTC', 'DOGE', 'USDT', 'USDC', 'DAI'}
        
        # Cache configuration
        self.cache_ttl = 3600  # 1 hour cache for exchange rates
        self.cache_category = 'exchange_rates'
        
        # Fallback rates in case all APIs fail (using Decimal for precision)
        self.fallback_rates = {
            'EUR_TO_USD': Decimal('1.10'),
            'USD_TO_EUR': Decimal('0.91'),
            'GBP_TO_USD': Decimal('1.27'),
            'USD_TO_GBP': Decimal('0.79')
        }
        
        # Rate bounds validation (prevent extreme rates) using Decimal
        self.rate_bounds = {
            'EUR_TO_USD': {'min': Decimal('0.80'), 'max': Decimal('1.50')},
            'USD_TO_EUR': {'min': Decimal('0.60'), 'max': Decimal('1.25')},
            'GBP_TO_USD': {'min': Decimal('1.00'), 'max': Decimal('1.60')},
            'USD_TO_GBP': {'min': Decimal('0.60'), 'max': Decimal('1.00')}
        }
        
        # Performance tracking
        self._api_success_count = 0
        self._api_failure_count = 0
        self._cache_hit_count = 0
        self._fallback_usage_count = 0
        
        logger.info("✅ Exchange rate service initialized with caching and fallback support")
    
    async def get_exchange_rate(self, from_currency: str, to_currency: str) -> Decimal:
        """
        Get exchange rate with caching, fallback, and validation
        
        Args:
            from_currency: Source currency (e.g., 'EUR')
            to_currency: Target currency (e.g., 'USD')
            
        Returns:
            Exchange rate as Decimal for financial precision
        """
        async with OperationTimer(f"exchange_rate_{from_currency}_{to_currency}"):
            return await self._get_rate_with_cache(from_currency.upper(), to_currency.upper())
    
    async def _get_rate_with_cache(self, from_currency: str, to_currency: str) -> Decimal:
        """Get exchange rate with performance cache"""
        cache_key = f"{from_currency}_{to_currency}"
        
        # Try cache first
        cached_rate = cache_get(self.cache_category, cache_key)
        if cached_rate is not None:
            self._cache_hit_count += 1
            cached_decimal = to_decimal(cached_rate, "cached_rate")
            logger.debug(f"💾 Cache HIT: {from_currency}/{to_currency} = {cached_decimal:.6f}")
            return cached_decimal
        
        # Cache miss - fetch from API
        logger.debug(f"🌐 Cache MISS: fetching {from_currency}/{to_currency} from API")
        rate = await self._fetch_rate_from_apis(from_currency, to_currency)
        
        # Cache the result (store as string to preserve Decimal precision)
        cache_set(self.cache_category, cache_key, str(rate))
        
        return rate
    
    async def _fetch_rate_from_apis(self, from_currency: str, to_currency: str) -> Decimal:
        """Fetch exchange rate from APIs with prioritized routing"""
        
        # Route crypto conversions to specialized handler
        if from_currency in self.crypto_currencies and to_currency == 'USD':
            rate = await self._fetch_crypto_to_usd_rate(from_currency)
            if rate:
                self._api_success_count += 1
                return rate
        
        # For fiat pairs, try FastForex first (restore working service)
        if (from_currency not in self.crypto_currencies and 
            to_currency not in self.crypto_currencies and 
            self.fastforex_api_key):
            rate = await self._fetch_from_fastforex_api(from_currency, to_currency)
            if rate:
                self._api_success_count += 1
                return rate
        
        # Try primary API 
        rate = await self._fetch_from_primary_api(from_currency, to_currency)
        if rate:
            self._api_success_count += 1
            return rate
        
        # Try fallback API
        rate = await self._fetch_from_fallback_api(from_currency, to_currency)
        if rate:
            self._api_success_count += 1
            logger.warning(f"⚠️ Primary API failed, using fallback for {from_currency}/{to_currency}")
            return rate
        
        # All APIs failed - use hardcoded fallback (safe pairs only)
        self._api_failure_count += 1
        self._fallback_usage_count += 1
        try:
            fallback_rate = self._get_fallback_rate(from_currency, to_currency)
            logger.error(f"❌ All exchange rate APIs failed, using hardcoded fallback: {from_currency}/{to_currency} = {fallback_rate:.6f}")
            return fallback_rate
        except ValueError as e:
            # Re-raise - no safe fallback available
            logger.error(f"❌ CRITICAL: No safe fallback rate available for {from_currency}/{to_currency}")
            raise e
    
    async def _fetch_from_primary_api(self, from_currency: str, to_currency: str) -> Optional[Decimal]:
        """Fetch rate from ExchangeRate-API (primary) with optimized timeout"""
        try:
            # PERFORMANCE FIX: Reduce timeout from 10s to 3s for webhook processing
            timeout = httpx.Timeout(3.0, connect=1.5)
            
            if self.api_key:
                url = f"{self.primary_api_url}/{self.api_key}/latest/{from_currency}"
            else:
                # Use free tier without API key (limited to 1000/month)
                url = f"https://api.exchangerate-api.com/v4/latest/{from_currency}"
            
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                data = response.json()
                
                # Handle different API response formats
                rates = data.get('rates', {})
                if not rates:
                    # Try conversion_rates format
                    rates = data.get('conversion_rates', {})
                
                if to_currency not in rates:
                    logger.warning(f"⚠️ Currency {to_currency} not found in primary API response")
                    return None
                
                rate = to_decimal(rates[to_currency], "exchange_rate")
                
                # Validate rate bounds
                if not self._validate_rate_bounds(from_currency, to_currency, rate):
                    logger.warning(f"⚠️ Rate {rate:.6f} for {from_currency}/{to_currency} outside expected bounds")
                    return None
                
                logger.info(f"✅ Primary API: {from_currency}/{to_currency} = {rate:.6f}")
                return rate
                
        except Exception as e:
            logger.warning(f"⚠️ Primary exchange rate API failed: {e}")
            return None
    
    async def _fetch_from_fallback_api(self, from_currency: str, to_currency: str) -> Optional[Decimal]:
        """Fetch rate from Fawazahmed0 API (fallback) with optimized timeout"""
        try:
            # PERFORMANCE FIX: Reduce timeout from 10s to 3s for webhook processing
            timeout = httpx.Timeout(3.0, connect=1.5)
            url = f"{self.fallback_api_url}/{from_currency.lower()}.json"
            
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                data = response.json()
                rates = data.get(from_currency.lower(), {})
                
                target_key = to_currency.lower()
                if target_key not in rates:
                    logger.warning(f"⚠️ Currency {to_currency} not found in fallback API response")
                    return None
                
                rate = to_decimal(rates[target_key], "exchange_rate")
                
                # Validate rate bounds
                if not self._validate_rate_bounds(from_currency, to_currency, rate):
                    logger.warning(f"⚠️ Fallback rate {rate:.6f} for {from_currency}/{to_currency} outside expected bounds")
                    return None
                
                logger.info(f"✅ Fallback API: {from_currency}/{to_currency} = {rate:.6f}")
                return rate
                
        except Exception as e:
            logger.warning(f"⚠️ Fallback exchange rate API failed: {e}")
            return None
    
    async def _fetch_from_fastforex_api(self, from_currency: str, to_currency: str) -> Optional[Decimal]:
        """Fetch rate from FastForex API with optimized timeout and internal caching"""
        if not self.fastforex_api_key:
            return None
            
        # Optimization: Use the dedicated FastForexService which has its own batch caching
        from services.fastforex import fastforex_service
        
        try:
            # Try to get from FastForexService cache first (non-blocking)
            rate_val, source = await fastforex_service.fetch_cached_rate(to_currency, from_currency)
            if rate_val:
                return to_decimal(rate_val, "fastforex_rate")
                
            # If not in cache, fallback to individual fetch (already has 3s timeout)
            # This handles cases where a specific pair isn't in the pre-warmed list
            timeout = httpx.Timeout(3.0, connect=1.5)
            url = f"{self.fastforex_api_url}/fetch-one?from={from_currency}&to={to_currency}&api_key={self.fastforex_api_key}"
            
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                
                if 'result' in data and to_currency in data['result']:
                    rate = to_decimal(data['result'][to_currency], "exchange_rate")
                    if self._validate_rate_bounds(from_currency, to_currency, rate):
                        return rate
            return None
        except Exception as e:
            logger.warning(f"⚠️ FastForex API optimization failed: {e}")
            return None
    
    async def _fetch_crypto_to_usd_rate(self, crypto_currency: str) -> Optional[Decimal]:
        """Fetch crypto to USD rate from CoinGecko API with optimized timeout"""
        try:
            # Map crypto symbols to CoinGecko IDs
            crypto_ids = {
                'BTC': 'bitcoin',
                'ETH': 'ethereum', 
                'LTC': 'litecoin',
                'DOGE': 'dogecoin',
                'USDT': 'tether',
                'USDC': 'usd-coin',
                'DAI': 'dai'
            }
            
            crypto_id = crypto_ids.get(crypto_currency)
            if not crypto_id:
                logger.warning(f"⚠️ Unsupported crypto currency: {crypto_currency}")
                return None
            
            # For stablecoins, return 1.0 directly (PERFORMANCE OPTIMIZATION)
            if crypto_currency in ['USDT', 'USDC', 'DAI']:
                logger.debug(f"💰 Stablecoin {crypto_currency}: 1.0 USD (instant)")
                return ONE
            
            # CoinGecko simple price API with REDUCED timeout for webhook processing
            # PERFORMANCE FIX: Reduce from 10s to 3s to prevent webhook timeout
            timeout = httpx.Timeout(3.0, connect=1.5)
            url = f"https://api.coingecko.com/api/v3/simple/price?ids={crypto_id}&vs_currencies=usd"
            
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url)
                response.raise_for_status()
                
                data = response.json()
                
                if crypto_id not in data or 'usd' not in data[crypto_id]:
                    logger.warning(f"⚠️ CoinGecko: No USD price for {crypto_currency}")
                    return None
                
                rate = to_decimal(data[crypto_id]['usd'], "crypto_rate")
                
                # Validate crypto rate is reasonable (> $1 for major cryptos)
                if crypto_currency in ['BTC', 'ETH'] and rate < ONE:
                    logger.error(f"❌ Suspicious crypto rate: {crypto_currency} = ${rate:.6f}")
                    return None
                
                logger.info(f"✅ CoinGecko: {crypto_currency}/USD = {rate:.2f}")
                return rate
                
        except Exception as e:
            logger.warning(f"⚠️ CoinGecko crypto API failed: {e}")
            return None
    
    def _validate_rate_bounds(self, from_currency: str, to_currency: str, rate: Decimal) -> bool:
        """Validate exchange rate is within reasonable bounds"""
        rate_key = f"{from_currency}_TO_{to_currency}"
        bounds = self.rate_bounds.get(rate_key)
        
        if not bounds:
            # No specific bounds configured - allow any positive rate
            return rate > ZERO
        
        return bounds['min'] <= rate <= bounds['max']
    
    def _get_fallback_rate(self, from_currency: str, to_currency: str) -> Decimal:
        """Get hardcoded fallback rate when all APIs fail"""
        rate_key = f"{from_currency}_TO_{to_currency}"
        
        # Try direct lookup
        if rate_key in self.fallback_rates:
            return self.fallback_rates[rate_key]
        
        # Try reverse calculation
        reverse_key = f"{to_currency}_TO_{from_currency}"
        if reverse_key in self.fallback_rates:
            return ONE / self.fallback_rates[reverse_key]
        
        # SAFETY: Never return 1.0 for unknown pairs - raise exception instead
        logger.error(f"❌ No fallback rate configured for {from_currency}/{to_currency}")
        raise ValueError(f"No exchange rate available for {from_currency}/{to_currency} - all APIs failed")
    
    def invalidate_cache(self) -> None:
        """Invalidate all cached exchange rates"""
        count = cache_invalidate_category(self.cache_category)
        logger.info(f"🗑️ Exchange rate cache invalidated: {count} entries removed")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get exchange rate service statistics"""
        total_api_calls = self._api_success_count + self._api_failure_count
        success_rate = (self._api_success_count / total_api_calls * 100) if total_api_calls > 0 else 0
        
        return {
            'api_success_count': self._api_success_count,
            'api_failure_count': self._api_failure_count,
            'api_success_rate_percent': success_rate,
            'cache_hit_count': self._cache_hit_count,
            'fallback_usage_count': self._fallback_usage_count,
            'cache_ttl_seconds': self.cache_ttl,
            'supported_currencies': list(self.fallback_rates.keys())
        }

# Global exchange rate service instance
_exchange_service = ExchangeRateService()

# Convenience functions for external use
async def get_eur_to_usd_rate() -> Decimal:
    """Get current EUR to USD exchange rate"""
    return await _exchange_service.get_exchange_rate('EUR', 'USD')

async def get_usd_to_eur_rate() -> Decimal:
    """Get current USD to EUR exchange rate"""
    return await _exchange_service.get_exchange_rate('USD', 'EUR')

async def get_exchange_rate(from_currency: str, to_currency: str) -> Decimal:
    """Get exchange rate between any supported currencies"""
    return await _exchange_service.get_exchange_rate(from_currency, to_currency)

def invalidate_exchange_rate_cache() -> None:
    """Invalidate all cached exchange rates"""
    _exchange_service.invalidate_cache()

def get_exchange_rate_stats() -> Dict[str, Any]:
    """Get exchange rate service performance statistics"""
    return _exchange_service.get_stats()

# Enhanced currency conversion with precision
async def convert_currency(amount: Decimal, from_currency: str, to_currency: str) -> Decimal:
    """
    Convert amount from one currency to another with high precision
    
    Args:
        amount: Amount to convert (Decimal for precision)
        from_currency: Source currency
        to_currency: Target currency
        
    Returns:
        Converted amount with proper rounding (Decimal)
    """
    if from_currency.upper() == to_currency.upper():
        return to_currency_decimal(amount, "amount")
    
    rate = await get_exchange_rate(from_currency, to_currency)
    
    # Use Decimal for precise calculation
    decimal_amount = to_currency_decimal(amount, "amount")
    converted = decimal_multiply(decimal_amount, rate)
    
    # Round to 2 decimal places and return as Decimal
    return to_currency_decimal(converted, "converted_amount")

logger.info("✅ Dynamic exchange rate service loaded - ready for real-time currency conversions")
