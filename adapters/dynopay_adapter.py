#!/usr/bin/env python3
"""
DynoPay Webhook Adapter
Converts DynoPay webhook data to standardized DTOs using type-safe converters
Handles all DynoPay-specific field patterns and data structures
"""

import logging
from typing import Dict, Any, Optional, List
from decimal import Decimal
from datetime import datetime

from schemas.webhook_schemas import DynoPayWebhookSchema, validate_webhook_data
from models.payment_models import (
    PaymentIntentDTO, WalletCreditDTO, PaymentStatus, PaymentProvider, PaymentMethod,
    create_payment_intent_from_webhook, create_wallet_credit_from_payment
)
from utils.type_converters import safe_decimal, safe_string, safe_int, safe_uuid
from services.exchange_rates import ExchangeRateService

logger = logging.getLogger(__name__)

class DynoPayAdapter:
    """
    Adapter for converting DynoPay webhook data to standardized DTOs
    Handles DynoPay-specific quirks and data formats
    """
    
    def __init__(self):
        self.exchange_service = ExchangeRateService()
        self.provider = PaymentProvider.DYNOPAY
        
        # DynoPay status mapping
        self.status_mapping = {
            'pending': PaymentStatus.PENDING,
            'processing': PaymentStatus.PROCESSING,
            'successful': PaymentStatus.SUCCESSFUL,
            'confirmed': PaymentStatus.CONFIRMED,
            'completed': PaymentStatus.COMPLETED,
            'failed': PaymentStatus.FAILED,
            'cancelled': PaymentStatus.CANCELLED,
            'expired': PaymentStatus.EXPIRED,
            'refunded': PaymentStatus.REFUNDED
        }
        
        # DynoPay field priority for amount extraction
        self.usd_amount_fields = [
            'base_amount', 'amount_usd', 'final_amount_usd', 
            'confirmed_amount_usd', 'total_usd', 'value_usd'
        ]
        
        self.crypto_amount_fields = [
            'crypto_amount', 'coin_amount', 'paid_amount', 
            'received_amount', 'confirmed_amount', 'final_amount', 'amount'
        ]
        
        # Common cryptocurrency mappings
        self.stablecoin_currencies = {'USDT', 'USDC', 'DAI', 'BUSD'}
        
    async def convert_webhook_to_payment_intent(
        self, 
        webhook_data: Dict[str, Any],
        validate_schema: bool = True
    ) -> PaymentIntentDTO:
        """
        Convert DynoPay webhook data to PaymentIntentDTO
        
        Args:
            webhook_data: Raw webhook data from DynoPay
            validate_schema: Whether to validate with Pydantic schema first
            
        Returns:
            Validated PaymentIntentDTO
            
        Raises:
            ValueError: If conversion fails or data is invalid
        """
        try:
            logger.info(f"🔄 DYNOPAY ADAPTER: Converting webhook data to PaymentIntentDTO")
            
            # Step 1: Validate with Pydantic schema if requested
            validated_webhook = None
            if validate_schema:
                try:
                    validated_webhook = validate_webhook_data(webhook_data, "dynopay")
                    logger.debug("✅ DynoPay webhook schema validation passed")
                except Exception as e:
                    logger.warning(f"⚠️ DynoPay schema validation failed, proceeding with raw data: {e}")
            
            # Step 2: Extract core fields with safe conversion
            order_id = self._extract_order_id(webhook_data)
            if not order_id:
                raise ValueError("No valid order_id found in DynoPay webhook")
            
            status = self._extract_status(webhook_data)
            user_id = self._extract_user_id(webhook_data)
            
            # Step 3: Extract amount with comprehensive logic
            amount_data = await self._extract_amount_data(webhook_data)
            
            # Step 4: Extract transaction and payment details
            transaction_details = self._extract_transaction_details(webhook_data)
            
            # Step 5: Create PaymentIntentDTO with all extracted data
            payment_intent = PaymentIntentDTO(
                order_id=order_id,
                user_id=user_id,
                amount_usd=amount_data['amount_usd'],
                status=status,
                provider=self.provider,
                provider_payment_id=transaction_details.get('provider_payment_id'),
                transaction_id=transaction_details.get('transaction_id'),
                original_amount=amount_data.get('original_amount'),
                original_currency=amount_data.get('original_currency', 'USD'),
                exchange_rate=amount_data.get('exchange_rate'),
                payment_method=self._determine_payment_method(webhook_data),
                cryptocurrency=amount_data.get('cryptocurrency'),
                wallet_address=safe_string(webhook_data.get('wallet_address')),
                description=safe_string(webhook_data.get('description')),
                customer_email=self._extract_customer_email(webhook_data),
                callback_url=safe_string(webhook_data.get('callback_url')),
                external_reference=safe_string(webhook_data.get('external_id')),
                confirmations=safe_int(webhook_data.get('confirmations'), default=0) or 0,
                required_confirmations=safe_int(webhook_data.get('required_confirmations'), default=1) or 1,
                network_fee=safe_decimal(webhook_data.get('fee'), field_name="network_fee"),
                metadata=self._extract_metadata(webhook_data)
            )
            
            logger.info(f"✅ DYNOPAY ADAPTER: Successfully converted webhook to PaymentIntentDTO")
            logger.info(f"   Order: {payment_intent.order_id}, Amount: {payment_intent.get_display_amount()}, Status: {payment_intent.status.value}")
            
            return payment_intent
            
        except Exception as e:
            logger.error(f"❌ DYNOPAY ADAPTER: Failed to convert webhook data: {e}")
            logger.error(f"   Webhook data keys: {list(webhook_data.keys())}")
            raise ValueError(f"DynoPay webhook conversion failed: {e}")
    
    def _extract_order_id(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract order_id from DynoPay webhook data"""
        # Try top-level first
        order_id = safe_string(data.get('order_id'))
        if order_id:
            return order_id
        
        # NEW API: payment_id and link_id fields
        order_id = safe_string(data.get('payment_id')) or safe_string(data.get('link_id'))
        if order_id:
            logger.debug(f"🔍 DYNOPAY: Extracted order_id from payment_id/link_id: {order_id}")
            return order_id
        
        # Check meta_data (DynoPay often puts order_id here)
        meta_data = data.get('meta_data', {})
        if isinstance(meta_data, dict):
            order_id = safe_string(meta_data.get('order_id')) or safe_string(meta_data.get('refId'))
            if order_id:
                logger.debug(f"🔍 DYNOPAY: Extracted order_id from meta_data: {order_id}")
                return order_id
        
        # Try other common fields
        for field in ['reference_id', 'external_id', 'ref_id']:
            if field in data:
                order_id = safe_string(data[field])
                if order_id:
                    logger.debug(f"🔍 DYNOPAY: Using {field} as order_id: {order_id}")
                    return order_id
        
        return None
    
    def _extract_status(self, data: Dict[str, Any]) -> PaymentStatus:
        """Extract and normalize payment status"""
        raw_status = safe_string(data.get('status', 'pending'))
        if raw_status:
            normalized_status = raw_status.lower()
            return self.status_mapping.get(normalized_status, PaymentStatus.PENDING)
        return PaymentStatus.PENDING
    
    def _extract_user_id(self, data: Dict[str, Any]) -> Optional[int]:
        """Extract user_id from various locations in webhook data"""
        # Try direct field
        user_id = safe_int(data.get('user_id'), field_name="user_id")
        if user_id:
            return user_id
        
        # Try meta_data
        meta_data = data.get('meta_data', {})
        if isinstance(meta_data, dict):
            user_id = safe_int(meta_data.get('user_id'), field_name="meta_data.user_id")
            if user_id:
                return user_id
        
        # Try callback_url parameter extraction
        callback_url = safe_string(data.get('callback_url'))
        if callback_url:
            import re
            match = re.search(r'user_id[=:](\d+)', callback_url)
            if match:
                user_id = safe_int(match.group(1), field_name="callback_url_user_id")
                if user_id:
                    logger.debug(f"🔍 DYNOPAY: Extracted user_id from callback_url: {user_id}")
                    return user_id
        
        return None
    
    async def _extract_amount_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract amount data with currency conversion if needed
        Returns dict with amount_usd, original_amount, original_currency, exchange_rate, cryptocurrency
        """
        result = {
            'amount_usd': Decimal('0.00'),
            'original_amount': None,
            'original_currency': 'USD',
            'exchange_rate': None,
            'cryptocurrency': None
        }
        
        # Step 1: Try USD amount fields first (no conversion needed)
        usd_amount = self._extract_usd_amount(data)
        if usd_amount and usd_amount > 0:
            result['amount_usd'] = usd_amount
            logger.debug(f"💰 DYNOPAY: Using USD amount: {usd_amount}")
            return result
        
        # Step 2: Try cryptocurrency amounts with conversion
        crypto_data = await self._extract_crypto_amount(data)
        if crypto_data['amount'] and crypto_data['amount'] > 0:
            result['amount_usd'] = crypto_data['amount_usd']
            result['original_amount'] = crypto_data['amount']
            result['original_currency'] = crypto_data['currency']
            result['exchange_rate'] = crypto_data['exchange_rate']
            result['cryptocurrency'] = crypto_data['currency']
            
            logger.debug(f"💰 DYNOPAY: Converted {crypto_data['amount']} {crypto_data['currency']} to ${crypto_data['amount_usd']}")
            return result
        
        logger.warning("⚠️ DYNOPAY: No valid amount found in webhook data")
        return result
    
    def _extract_usd_amount(self, data: Dict[str, Any]) -> Optional[Decimal]:
        """Extract USD amount from direct USD fields"""
        # Check direct fields
        for field in self.usd_amount_fields:
            if field in data:
                amount = safe_decimal(data[field], field_name=f"dynopay.{field}")
                if amount is not None and amount > 0:
                    return amount
        
        # Check nested structures
        nested_fields = ['meta_data', 'payment_data', 'transaction_data']
        for nested_field in nested_fields:
            nested_data = data.get(nested_field, {})
            if isinstance(nested_data, dict):
                for field in self.usd_amount_fields:
                    if field in nested_data:
                        amount = safe_decimal(nested_data[field], field_name=f"dynopay.{nested_field}.{field}")
                        if amount is not None and amount > 0:
                            return amount
        
        return None
    
    async def _extract_crypto_amount(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract cryptocurrency amount and convert to USD"""
        result = {
            'amount': None,
            'currency': None,
            'amount_usd': Decimal('0.00'),
            'exchange_rate': None
        }
        
        # Extract currency first
        currency = safe_string(data.get('currency')) or safe_string(data.get('coin'))
        if not currency:
            return result
        
        currency = currency.upper()
        result['currency'] = currency
        
        # Extract crypto amount
        crypto_amount = None
        for field in self.crypto_amount_fields:
            if field in data:
                crypto_amount = safe_decimal(data[field], field_name=f"dynopay.crypto.{field}")
                if crypto_amount is not None and crypto_amount > 0:
                    result['amount'] = crypto_amount
                    break
        
        if not crypto_amount:
            return result
        
        # Convert to USD
        try:
            if currency in self.stablecoin_currencies:
                # Stablecoins are 1:1 with USD
                result['amount_usd'] = crypto_amount
                result['exchange_rate'] = Decimal('1.00')
            else:
                # Get exchange rate and convert
                exchange_rate = await self.exchange_service.get_exchange_rate(currency, 'USD')
                result['exchange_rate'] = Decimal(str(exchange_rate))
                result['amount_usd'] = crypto_amount * result['exchange_rate']
                result['amount_usd'] = result['amount_usd'].quantize(Decimal('0.01'))
        except Exception as e:
            logger.error(f"❌ DYNOPAY: Currency conversion failed for {crypto_amount} {currency}: {e}")
            
        return result
    
    def _extract_transaction_details(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract transaction-related details"""
        return {
            'provider_payment_id': safe_string(data.get('payment_id')) or safe_string(data.get('id')),
            'transaction_id': (
                safe_string(data.get('txid')) or 
                safe_string(data.get('transaction_id')) or 
                safe_string(data.get('hash'))
            )
        }
    
    def _determine_payment_method(self, data: Dict[str, Any]) -> Optional[PaymentMethod]:
        """Determine payment method from webhook data"""
        # Check for explicit payment method field
        payment_method = safe_string(data.get('payment_method'))
        if payment_method:
            payment_method_lower = payment_method.lower()
            if 'crypto' in payment_method_lower:
                return PaymentMethod.CRYPTOCURRENCY
            elif 'card' in payment_method_lower:
                return PaymentMethod.CREDIT_CARD
            elif 'bank' in payment_method_lower:
                return PaymentMethod.BANK_TRANSFER
        
        # Infer from currency/coin
        currency = safe_string(data.get('currency')) or safe_string(data.get('coin'))
        if currency:
            currency_upper = currency.upper()
            if currency_upper in self.stablecoin_currencies:
                return PaymentMethod.STABLECOIN
            elif currency_upper in {'BTC', 'ETH', 'LTC', 'DOGE', 'BCH', 'XRP'}:
                return PaymentMethod.CRYPTOCURRENCY
        
        return None
    
    def _extract_customer_email(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract customer email from various locations"""
        # Check direct field
        email = safe_string(data.get('customer_email'))
        if email:
            return email
        
        # Check meta_data
        meta_data = data.get('meta_data', {})
        if isinstance(meta_data, dict):
            email = safe_string(meta_data.get('customer_email')) or safe_string(meta_data.get('email'))
            if email:
                return email
        
        return None
    
    def _extract_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and preserve metadata"""
        metadata = {}
        
        # Preserve original meta_data
        if 'meta_data' in data:
            metadata['dynopay_meta_data'] = data['meta_data']
        
        # Add useful debugging information
        metadata['dynopay_original_fields'] = list(data.keys())
        metadata['adapter_version'] = "1.0"
        metadata['provider'] = "dynopay"
        
        # Preserve any additional useful fields
        for field in ['network', 'confirmations_required', 'fee_currency']:
            if field in data:
                metadata[f'dynopay_{field}'] = data[field]
        
        return metadata
    
    async def create_wallet_credit_from_webhook(
        self, 
        webhook_data: Dict[str, Any]
    ) -> Optional[WalletCreditDTO]:
        """
        Create WalletCreditDTO from DynoPay webhook for wallet funding
        
        Args:
            webhook_data: Raw DynoPay webhook data
            
        Returns:
            WalletCreditDTO if this is a confirmed wallet funding, None otherwise
        """
        try:
            # Convert to payment intent first
            payment_intent = await self.convert_webhook_to_payment_intent(webhook_data)
            
            # Check if this is confirmed wallet funding
            if (not payment_intent.is_confirmed() or 
                not payment_intent.order_id.startswith('wallet_fund_') or
                not payment_intent.user_id):
                return None
            
            # Create wallet credit DTO
            wallet_credit = create_wallet_credit_from_payment(
                payment_intent=payment_intent,
                transaction_id=payment_intent.transaction_id
            )
            
            logger.info(f"✅ DYNOPAY: Created wallet credit for user {wallet_credit.user_id}: {wallet_credit.get_display_amount()}")
            return wallet_credit
            
        except Exception as e:
            logger.error(f"❌ DYNOPAY: Failed to create wallet credit from webhook: {e}")
            return None

# Convenience function for external use
async def convert_dynopay_webhook(webhook_data: Dict[str, Any]) -> PaymentIntentDTO:
    """
    Convenience function to convert DynoPay webhook data to PaymentIntentDTO
    
    Args:
        webhook_data: Raw DynoPay webhook data
        
    Returns:
        Validated PaymentIntentDTO
    """
    adapter = DynoPayAdapter()
    return await adapter.convert_webhook_to_payment_intent(webhook_data)

if __name__ == "__main__":
    # Test the adapter with sample data
    import asyncio
    
    async def test_adapter():
        logging.basicConfig(level=logging.INFO)
        
        # Test data that should work
        test_data = {
            "order_id": "wallet_fund_12345",
            "status": "successful", 
            "base_amount": "10.50",
            "currency": "USD",
            "txid": "abc123def456",
            "meta_data": {
                "user_id": 123,
                "callback_url": "https://example.com/webhook"
            }
        }
        
        try:
            payment = await convert_dynopay_webhook(test_data)
            logger.info(f"✅ Test passed: {payment.order_id}, amount: {payment.get_display_amount()}")
        except Exception as e:
            logger.error(f"❌ Test failed: {e}")
    
    asyncio.run(test_adapter())