#!/usr/bin/env python3
"""
Debug script to check environment variable loading and pricing logic
"""

import sys
import os
sys.path.insert(0, '/app')

# Load environment first
from dotenv import load_dotenv
load_dotenv('/app/.env', override=True)

print("🔍 Environment Variables Check:")
print(f"DOMAIN_PRICE_MARKUP_MULTIPLIER = {os.getenv('DOMAIN_PRICE_MARKUP_MULTIPLIER')}")
print(f"DOMAIN_MINIMUM_PRICE = {os.getenv('DOMAIN_MINIMUM_PRICE')}")
print(f"ENABLE_DOMAIN_MARKUP = {os.getenv('ENABLE_DOMAIN_MARKUP')}")
print()

# Import after environment is loaded
from pricing_utils import PricingConfig, USER_PRICING_OVERRIDES
from decimal import Decimal

print("🔍 USER_PRICING_OVERRIDES content:")
print(USER_PRICING_OVERRIDES)
print()

print("🔍 Testing PricingConfig with different scenarios:")

# Test 1: No username (should use env vars)
print("\n1. PricingConfig() - No username:")
config1 = PricingConfig()
print(f"   markup_multiplier: {config1.markup_multiplier}")
print(f"   minimum_price: {config1.minimum_price}")
print(f"   markup_enabled: {config1.markup_enabled}")

# Test 2: With pacelolx username
print("\n2. PricingConfig(telegram_username='pacelolx'):")
config2 = PricingConfig(telegram_username='pacelolx')
print(f"   markup_multiplier: {config2.markup_multiplier}")
print(f"   minimum_price: {config2.minimum_price}")
print(f"   markup_enabled: {config2.markup_enabled}")

# Test 3: With random username
print("\n3. PricingConfig(telegram_username='randomuser'):")
config3 = PricingConfig(telegram_username='randomuser')
print(f"   markup_multiplier: {config3.markup_multiplier}")
print(f"   minimum_price: {config3.minimum_price}")
print(f"   markup_enabled: {config3.markup_enabled}")

print()
print("🔍 Debug: Checking default values in PricingConfig.__init__:")
print("Looking at the constructor defaults...")