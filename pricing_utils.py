"""
Pricing utility functions for HostBay domain registration
Handles profit markup and minimum price enforcement
"""

import os
import logging
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional, Dict, Any
from financial_precision import (
    to_decimal, to_currency_decimal, decimal_multiply, decimal_divide,
    add_percentage, format_currency, ZERO, ONE, CENT
)

logger = logging.getLogger(__name__)

# Dynamic exchange rates now handled by services/exchange_rates.py
# Fallback rate used only if exchange rate service fails completely
FALLBACK_EUR_TO_USD = Decimal('1.10')

class PricingConfig:
    """Configuration class for pricing settings"""
    
    def __init__(self):
        # Hardcoded pricing config - set directly in code for deployment stability
        # 230% markup = 3.3 multiplier
        self.markup_multiplier = Decimal('3.3')
        self.minimum_price = Decimal('30.00')
        self.markup_enabled = True
        
    def get_config_info(self) -> Dict[str, Any]:
        """Get current pricing configuration for logging/debugging"""
        markup_percentage = (self.markup_multiplier - ONE) * Decimal('100') if self.markup_multiplier >= ONE else ZERO
        
        # Get current exchange rate (fallback to static if service fails)
        try:
            current_eur_to_usd = _get_exchange_rate_sync('EUR', 'USD')
        except Exception as e:
            logger.warning(f"⚠️ Could not fetch current EUR/USD rate for config: {e}")
            current_eur_to_usd = FALLBACK_EUR_TO_USD
        
        return {
            'markup_multiplier': float(self.markup_multiplier),  # Convert to float for JSON serialization
            'markup_percentage': float(markup_percentage),
            'minimum_price': float(self.minimum_price),
            'markup_enabled': self.markup_enabled,
            'eur_to_usd_rate': float(current_eur_to_usd),
            'dynamic_rates_enabled': True
        }

def _get_exchange_rate_sync(from_currency: str, to_currency: str) -> Decimal:
    """Get exchange rate synchronously - handles both running and new event loops"""
    import asyncio
    import threading
    try:
        # Import here to avoid circular dependencies
        from services.exchange_rates import get_exchange_rate
        
        # Check if we're already in an async context
        try:
            loop = asyncio.get_running_loop()
            # We're in a running event loop - use run_coroutine_threadsafe
            
            def run_async_in_thread():
                # Create new event loop in thread
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    return new_loop.run_until_complete(get_exchange_rate(from_currency, to_currency))
                finally:
                    new_loop.close()
            
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_async_in_thread)
                return future.result(timeout=10)  # 10 second timeout
        except RuntimeError:
            # No running event loop - safe to use asyncio.run
            return asyncio.run(get_exchange_rate(from_currency, to_currency))
            
    except Exception as e:
        logger.warning(f"⚠️ Failed to get {from_currency}/{to_currency} rate: {e}")
        # Return fallback based on currency pair
        if from_currency.upper() == 'EUR' and to_currency.upper() == 'USD':
            return FALLBACK_EUR_TO_USD
        elif from_currency.upper() == 'USD' and to_currency.upper() == 'EUR':
            return ONE / FALLBACK_EUR_TO_USD
        else:
            return ONE  # Default fallback for unknown pairs

def convert_eur_to_usd(eur_amount: Decimal) -> Decimal:
    """Convert EUR to USD using dynamic exchange rate with fallback"""
    eur_decimal = to_currency_decimal(eur_amount, "eur_amount")
    
    try:
        # Get current exchange rate dynamically
        exchange_rate = _get_exchange_rate_sync('EUR', 'USD')
        
        converted_amount = decimal_multiply(eur_decimal, exchange_rate)
        logger.debug(f"💱 Dynamic EUR/USD rate: {exchange_rate:.6f} (amount: €{eur_decimal:.2f} → ${converted_amount:.2f})")
        
    except Exception as e:
        # Fallback to static rate if service fails
        exchange_rate = FALLBACK_EUR_TO_USD
        converted_amount = decimal_multiply(eur_decimal, exchange_rate)
        logger.warning(f"⚠️ Dynamic exchange rate failed, using fallback {exchange_rate:.2f}: {e}")
    
    return to_currency_decimal(converted_amount, "converted_amount")

def calculate_marked_up_price(base_price: Decimal, currency: str = 'EUR', tld: Optional[str] = None, is_api_purchase: bool = False) -> Dict[str, Any]:
    """
    Calculate marked-up price with minimum price enforcement and TLD-specific surcharges
    
    Args:
        base_price: Base price from OpenProvider
        currency: Currency of base price (typically EUR)
        tld: Optional TLD (e.g., 'ca', 'com') for TLD-specific pricing
        is_api_purchase: If True, apply 10% discount for API purchases
        
    Returns:
        Dict containing marked-up pricing information
    """
    config = PricingConfig()
    base_price_decimal = to_currency_decimal(base_price, "base_price")
    
    # Convert to USD if needed
    if currency.upper() == 'EUR':
        base_price_usd = convert_eur_to_usd(base_price_decimal)
    else:
        base_price_usd = base_price_decimal
    
    # Apply percentage markup if enabled (using pure Decimal arithmetic)
    if config.markup_enabled:
        marked_up_price = decimal_multiply(base_price_usd, config.markup_multiplier)
    else:
        marked_up_price = base_price_usd
    
    # Enforce minimum price FIRST (before surcharges)
    price_after_minimum = max(marked_up_price, config.minimum_price)
    
    # Apply TLD-specific surcharges AFTER minimum price enforcement
    # This ensures surcharges are always added on top of the base price floor
    tld_surcharge = ZERO
    if tld:
        tld_normalized = tld.lower().lstrip('.')
        if tld_normalized == 'ca':
            tld_surcharge = Decimal('10.00')
            logger.info(f"🇨🇦 Applied .ca surcharge: +${tld_surcharge:.2f} USD")
        elif tld_normalized == 'it':
            tld_surcharge = Decimal('10.00')
            logger.info(f"🇮🇹 Applied .it surcharge: +${tld_surcharge:.2f} USD")
    
    # Final price = minimum-enforced price + surcharges
    price_before_api_discount = price_after_minimum + tld_surcharge
    
    # Apply 10% API discount if requested
    api_discount = ZERO
    if is_api_purchase:
        api_discount = decimal_multiply(price_before_api_discount, Decimal('0.10'))
        final_price = price_before_api_discount - api_discount
        logger.info(f"🎯 Applied API discount: -${api_discount:.2f} (10%) → final ${final_price:.2f}")
    else:
        final_price = price_before_api_discount
    
    # Calculate actual markup applied (may be less if minimum price kicked in)
    actual_markup = final_price - base_price_usd
    
    # Calculate effective multiplier for transparency
    effective_multiplier = decimal_divide(final_price, base_price_usd) if base_price_usd > ZERO else ZERO
    
    pricing_info = {
        'base_price_eur': float(base_price_decimal) if currency.upper() == 'EUR' else 0,
        'base_price_usd': float(base_price_usd),
        'markup_multiplier': float(config.markup_multiplier) if config.markup_enabled else 1.0,
        'markup_percentage': float((config.markup_multiplier - ONE) * Decimal('100')) if config.markup_enabled and config.markup_multiplier >= ONE else 0,
        'marked_up_price': float(marked_up_price),
        'minimum_price': float(config.minimum_price),
        'final_price': float(final_price),
        'actual_markup': float(actual_markup),
        'effective_multiplier': float(effective_multiplier),
        'currency': 'USD',
        'markup_applied': config.markup_enabled,
        'minimum_enforced': final_price == config.minimum_price,
        'tld_surcharge': float(tld_surcharge),
        'tld': tld.lower().lstrip('.') if tld else None,
        'api_discount': float(api_discount),
        'api_purchase': is_api_purchase,
        'price_before_discount': float(price_before_api_discount) if is_api_purchase else float(final_price)
    }
    
    markup_percentage = (config.markup_multiplier - ONE) * Decimal('100') if config.markup_enabled and config.markup_multiplier >= ONE else ZERO
    
    if is_api_purchase:
        logger.info(f"💰 API Price: base ${base_price_usd:.2f} × {config.markup_multiplier:.1f} ({markup_percentage:.0f}%) = ${price_before_api_discount:.2f} - 10% API discount (${api_discount:.2f}) → final ${final_price:.2f}")
    else:
        logger.info(f"💰 Bot Price: base ${base_price_usd:.2f} × {config.markup_multiplier:.1f} ({markup_percentage:.0f}%) → final ${final_price:.2f} (markup: ${actual_markup:.2f})")
    
    return pricing_info

def get_currency_symbol(currency_code: str) -> str:
    """Get currency symbol for a given currency code"""
    currency_symbols = {
        'USD': '$',
        'EUR': '€',
        'GBP': '£',
        'JPY': '¥',
        'CHF': 'CHF',
        'CAD': 'C$',
        'AUD': 'A$',
        'SEK': 'kr',
        'NOK': 'kr',
        'DKK': 'kr',
        'PLN': 'zł',
        'CZK': 'Kč',
        'HUF': 'Ft',
        'RON': 'lei',
        'BGN': 'лв',
        'HRK': 'kn',
        'RSD': 'din',
        'TRY': '₺',
        'RUB': '₽',
        'CNY': '¥',
        'KRW': '₩',
        'INR': '₹',
        'SGD': 'S$',
        'HKD': 'HK$',
        'NZD': 'NZ$',
        'MXN': 'MX$',
        'BRL': 'R$',
        'ARS': 'AR$',
        'CLP': 'CL$',
        'COP': 'CO$',
        'PEN': 'S/',
        'UYU': 'UY$',
        'ZAR': 'R',
        'EGP': 'ج.م',
        'MAD': 'د.م.',
        'TND': 'د.ت',
        'ILS': '₪',
        'AED': 'د.إ',
        'SAR': 'ر.س',
        'QAR': 'ر.ق',
        'KWD': 'د.ك',
        'BHD': 'د.ب',
        'OMR': 'ر.ع.',
        'JOD': 'د.أ',
        'LBP': 'ل.ل',
        'THB': '฿',
        'MYR': 'RM',
        'IDR': 'Rp',
        'PHP': '₱',
        'VND': '₫'
    }
    return currency_symbols.get(currency_code.upper(), currency_code.upper())

def format_money(amount: Decimal, currency: str = "USD", include_currency: bool = True) -> str:
    """
    Enhanced money formatting utility with proper currency symbol mapping
    
    Args:
        amount: The monetary amount to format (Decimal for precision)
        currency: Currency code (default: USD)
        include_currency: Whether to include currency code in output
        
    Returns:
        Clean formatted money string (e.g., "$31.99 USD" or "€29.99 EUR")
    """
    # Ensure proper Decimal precision for currency
    decimal_amount = to_currency_decimal(amount, "amount")
    
    # Get proper currency symbol
    currency_symbol = get_currency_symbol(currency)
    
    # Format with currency symbol
    formatted_amount = f"{currency_symbol}{decimal_amount:.2f}"
    
    # Add currency code if requested (for clarity, especially in international contexts)
    if include_currency and currency:
        formatted_amount += f" {currency.upper()}"
    
    return formatted_amount

def format_crypto_amount(amount, currency_symbol: str) -> str:
    """
    Format crypto amount for display, stripping unnecessary trailing zeros.
    Keeps at least 2 decimal places for readability.
    
    Examples:
        10.0100 USDT-TRC20 → 10.01 USDT-TRC20
        0.00012300 BTC     → 0.000123 BTC
        0.003330 ETH       → 0.00333 ETH
        5.0000 LTC         → 5.00 LTC
    """
    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return f"{amount} {currency_symbol}"
    
    # Choose initial precision based on magnitude
    if amount >= 1:
        formatted = f"{amount:.4f}"
    elif amount >= 0.001:
        formatted = f"{amount:.6f}"
    else:
        formatted = f"{amount:.8f}"
    
    # Strip trailing zeros but keep at least 2 decimal places
    if '.' in formatted:
        integer_part, decimal_part = formatted.split('.')
        decimal_part = decimal_part.rstrip('0')
        if len(decimal_part) < 2:
            decimal_part = decimal_part.ljust(2, '0')
        formatted = f"{integer_part}.{decimal_part}"
    
    return f"{formatted} {currency_symbol}"


def format_price_display(pricing_info: Dict[str, Any], domain_name: str = "") -> str:
    """
    Format pricing information for user display
    
    Args:
        pricing_info: Result from calculate_marked_up_price()
        domain_name: Optional domain name for context
        
    Returns:
        Formatted price string for display
    """
    final_price = pricing_info['final_price']
    currency = pricing_info['currency']
    
    # Use robust money formatting to prevent precision errors
    display = format_money(final_price, currency, include_currency=True)
    
    # Add context if minimum price was enforced
    if pricing_info.get('minimum_enforced', False):
        display += " (minimum price)"
    
    return display

def get_pricing_breakdown(pricing_info: Dict[str, Any]) -> str:
    """
    Get detailed pricing breakdown for admin/debug purposes
    
    Args:
        pricing_info: Result from calculate_marked_up_price()
        
    Returns:
        Detailed breakdown string
    """
    config = PricingConfig()
    
    breakdown = f"""
📊 <b>Pricing Breakdown</b>
• Base Price: ${pricing_info['base_price_usd']:.2f} USD
• Markup: {pricing_info.get('markup_percentage', 0):.0f}% (×{pricing_info.get('markup_multiplier', 1.0):.1f})
• Marked-up Price: ${pricing_info['marked_up_price']:.2f} USD
• Minimum Price: ${pricing_info['minimum_price']:.2f} USD
• <b>Final Price: ${pricing_info['final_price']:.2f} USD</b>
• Effective Multiplier: ×{pricing_info.get('effective_multiplier', 1.0):.2f}

🔧 <b>Configuration</b>
• Markup Enabled: {config.markup_enabled}
• Markup Percentage: {(config.markup_multiplier - 1) * 100:.0f}%
• Markup Multiplier: ×{config.markup_multiplier:.1f}
• Minimum Price: ${config.minimum_price:.2f}
• Minimum Enforced: {pricing_info.get('minimum_enforced', False)}
"""
    
    return breakdown.strip()

def validate_pricing_config() -> bool:
    """
    Validate that pricing configuration is reasonable
    
    Returns:
        True if configuration is valid, False otherwise
    """
    config = PricingConfig()
    
    # Validate markup multiplier
    if config.markup_multiplier < ZERO:
        logger.error("❌ Invalid pricing config: markup multiplier cannot be negative")
        return False
        
    if config.markup_multiplier < ONE:
        logger.warning(f"⚠️ Markup multiplier less than 1.0 detected: {config.markup_multiplier:.2f} (this means discount pricing)")
        
    if config.markup_multiplier > Decimal('10.0'):
        markup_percentage = (config.markup_multiplier - ONE) * Decimal('100')
        logger.warning(f"⚠️ Very high markup multiplier detected: {config.markup_multiplier:.2f} ({markup_percentage:.0f}% markup)")
    
    # Validate minimum price
    if config.minimum_price < ZERO:
        logger.error("❌ Invalid pricing config: minimum price cannot be negative")
        return False
        
    if config.minimum_price > Decimal('1000'):
        logger.warning("⚠️ Very high minimum price detected: ${:.2f}".format(config.minimum_price))
    
    # Log configuration for transparency
    markup_percentage = (config.markup_multiplier - ONE) * Decimal('100') if config.markup_multiplier >= ONE else ZERO
    logger.info(f"✅ Pricing configuration validated: markup={markup_percentage:.0f}% (×{config.markup_multiplier:.1f}), minimum=${config.minimum_price:.2f}, enabled={config.markup_enabled}")
    
    return True

# Initialize and validate configuration on module import
if not validate_pricing_config():
    logger.error("❌ Pricing configuration validation failed - check environment variables")