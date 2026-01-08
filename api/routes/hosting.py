"""
Hosting Management Routes
"""
from decimal import Decimal
from fastapi import APIRouter, Depends, Query
from api.middleware.authentication import get_api_key_from_header, check_permission
from api.schemas.hosting import (
    UnifiedOrderHostingRequest,
    OrderHostingRequest,
    OrderHostingExistingRequest,
    OrderHostingExternalRequest,
    RenewHostingRequest,
    ResetPasswordRequest,
    ServerInfoResponse,
    ServerLocation,
    ServerSpecifications,
    ServerNameservers
)
from api.utils.responses import success_response
from api.utils.errors import ResourceNotFoundError, InternalServerError, BadRequestError
from services.cpanel import CPanelService
from services.hosting_orchestrator import HostingBundleOrchestrator
from database import (
    execute_query, 
    execute_update,
    reserve_wallet_balance,
    get_user_wallet_balance_by_id,
    finalize_wallet_reservation,
    save_dns_records_to_db
)
from admin_alerts import send_info_alert
from webhook_handler import queue_user_message
from localization import t_for_user
import secrets
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
cpanel = CPanelService()
hosting_orchestrator = HostingBundleOrchestrator()

import os

# Hosting pricing from environment secrets
def get_hosting_prices():
    """Get hosting prices from environment variables"""
    plan_7_price = Decimal(os.environ.get('HOSTING_PLAN_7_DAYS_PRICE', '40.00'))
    plan_30_price = Decimal(os.environ.get('HOSTING_PLAN_30_DAYS_PRICE', '80.00'))
    return {
        "pro_7day": plan_7_price,
        "pro_30day": plan_30_price,
        "Pro 7 Days": plan_7_price,
        "Pro 30 Days": plan_30_price
    }

HOSTING_PRICES = get_hosting_prices()


@router.get("/hosting/plans", response_model=dict)
async def get_hosting_plans(
    key_data: dict = Depends(get_api_key_from_header)
):
    """Get available hosting plans"""
    check_permission(key_data, "hosting", "read")
    
    plans = cpanel.get_hosting_plans()
    return success_response({"plans": plans})


@router.get("/hosting/server-info", response_model=dict)
async def get_server_info(
    domain_name: str = Query(None, description="Optional: Domain name to get personalized DNS linking instructions"),
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Get hosting server information with optional domain-specific DNS instructions.
    
    **Use this endpoint for:**
    - Getting server IP for A record DNS configuration
    - Getting HostBay nameservers for domain linking
    - Understanding server location for latency optimization
    - Displaying server information to end users
    - **NEW**: Getting personalized DNS instructions for a specific domain (pass domain_name query param)
    
    **Response Structure:**
    - hostname: Server hostname
    - ip_address: Server IP for A record configuration
    - location: Physical server location (region, datacenter, country, timezone)
    - specifications: Server specs (control panel, storage, features)
    - nameservers: Primary and secondary NS records
    - dns_nameservers: HostBay NS for external domain linking
    - dns_instructions: (Optional) Domain-specific DNS instructions if domain_name provided
    """
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    import os
    from services.cloudflare import CloudflareService
    from services.domain_analysis_service import DomainAnalysisService
    
    # Get server configuration from environment
    whm_host = os.getenv('WHM_HOST', 'N/A')
    server_ip = cpanel.default_server_ip
    
    # Dynamically fetch Cloudflare nameservers from the API
    cloudflare_service = CloudflareService()
    cloudflare_ns_list = await cloudflare_service.get_account_nameservers()
    
    # Primary and secondary nameservers from dynamic Cloudflare fetch
    ns1 = cloudflare_ns_list[0] if len(cloudflare_ns_list) > 0 else 'N/A'
    ns2 = cloudflare_ns_list[1] if len(cloudflare_ns_list) > 1 else 'N/A'
    
    # Server location info - configurable via environment variables
    server_location = {
        "region": os.getenv('SERVER_REGION', 'Russia'),
        "datacenter": os.getenv('SERVER_DATACENTER', 'Moscow'),
        "country": os.getenv('SERVER_COUNTRY', 'Russian Federation'),
        "timezone": os.getenv('SERVER_TIMEZONE', 'Europe/Moscow'),
        "latency_info": os.getenv('SERVER_LATENCY_INFO', 'Optimal for Eastern Europe, Russia, and Western Asia. Good connectivity to Europe and Asia.')
    }
    
    # Server specifications
    server_specs = {
        "control_panel": "HostBay Panel",
        "storage_type": "NVMe SSD",
        "network_speed": "1 Gbps",
        "uptime_guarantee": "99.9%",
        "features": [
            "Unlimited bandwidth",
            "NVMe SSD storage",
            "Free SSL certificates",
            "Unlimited email accounts",
            "Unlimited MySQL databases",
            "FTP/SFTP access",
            "File manager",
            "Daily backups",
            "One-click installer",
            "PHP version selector",
            "Node.js support"
        ]
    }
    
    # Base response
    response_data = {
        "hostname": whm_host,
        "ip_address": server_ip,
        "location": server_location,
        "specifications": server_specs,
        "nameservers": {
            "primary": ns1,
            "secondary": ns2
        },
        # New generic field name
        "dns_nameservers": cloudflare_ns_list,
        # Legacy field name (backward compatibility)
        "cloudflare_nameservers": cloudflare_ns_list
    }
    
    # If domain_name provided, add personalized DNS instructions
    if domain_name:
        domain_analysis_service = DomainAnalysisService()
        
        # Try to get zone-specific nameservers for this domain
        zone_info = await cloudflare_service.get_zone_by_name(domain_name)
        zone_specific_ns = None
        if zone_info:
            zone_specific_ns = zone_info.get('name_servers', [])
            logger.info(f"📋 Found zone-specific nameservers for {domain_name}: {zone_specific_ns}")
        
        # Use zone-specific nameservers if available, otherwise use account-level
        effective_ns = zone_specific_ns if zone_specific_ns else cloudflare_ns_list
        ns1_effective = effective_ns[0] if len(effective_ns) > 0 else ns1
        ns2_effective = effective_ns[1] if len(effective_ns) > 1 else ns2
        
        # Update response with zone-specific nameservers if available
        if zone_specific_ns:
            response_data["dns_nameservers"] = effective_ns
            response_data["cloudflare_nameservers"] = effective_ns
            response_data["nameservers"] = {
                "primary": ns1_effective,
                "secondary": ns2_effective
            }
        
        # Check if domain was purchased on HostBay platform (internal domain)
        internal_domain_check = await execute_query("""
            SELECT id, domain_name FROM domains 
            WHERE domain_name = %s AND user_id = %s AND deleted_at IS NULL
            LIMIT 1
        """, (domain_name.lower(), user_id))
        
        is_internal = len(internal_domain_check) > 0 if internal_domain_check else False
        
        # Analyze current domain DNS configuration
        analysis_result = await domain_analysis_service.analyze_domain(domain_name)
        dns_info = analysis_result.get('dns_info', {})
        current_nameservers = dns_info.get('nameservers', [])
        
        # Check if already using Cloudflare nameservers
        cloudflare_ns_patterns = ['cloudflare.com', 'cloudflare.net']
        already_using_cloudflare = any(
            any(cf_pattern in ns.lower() for cf_pattern in cloudflare_ns_patterns)
            for ns in current_nameservers
        )
        
        # Determine recommendation based on domain status
        if is_internal:
            recommendation_text = "This domain was purchased through HostBay. DNS is already configured - no changes needed."
        elif already_using_cloudflare:
            recommendation_text = "Domain already uses Cloudflare. Use the A Record method to point to our hosting server."
        else:
            recommendation_text = "Update nameservers to Cloudflare for full DNS management and automatic SSL."
        
        # Build nameserver method instructions (use zone-specific nameservers if available)
        nameserver_instructions = f"""1. Log in to your domain registrar (where you purchased the domain)
2. Navigate to DNS or Nameserver settings
3. Replace current nameservers with:
   - {ns1_effective}
   - {ns2_effective}
4. Save changes and wait 24-48 hours for propagation
5. Return to HostBay to verify the domain is linked"""
        
        # Build A record method instructions
        a_record_instructions = f"""1. Log in to your domain registrar or DNS provider
2. Navigate to DNS record management
3. Add or update the following A records:
   - Type: A, Name: @ (root), Value: {server_ip}
   - Type: A, Name: www, Value: {server_ip}
4. Save changes and wait 1-4 hours for propagation
5. Return to HostBay to verify the domain is linked"""
        
        # Build important notes based on domain status
        important_notes = []
        if is_internal:
            important_notes.append("This domain was purchased through HostBay - DNS is already configured automatically.")
        if already_using_cloudflare:
            important_notes.append("Your domain is already using Cloudflare. Use the A Record method to avoid conflicts.")
            important_notes.append("If you switch nameservers, you may lose existing Cloudflare settings.")
        important_notes.extend([
            "Nameserver changes can take 24-48 hours to fully propagate worldwide.",
            "A Record changes typically propagate within 1-4 hours.",
            "Do not change both nameservers and A records - choose one method only."
        ])
        
        response_data["dns_instructions"] = {
            "domain": domain_name,
            "domain_status": {
                "is_internal": is_internal,
                "already_using_cloudflare": already_using_cloudflare,
                "current_nameservers": current_nameservers,
                "recommendation": recommendation_text
            },
            "nameserver_method": {
                "nameservers": list(effective_ns) if effective_ns else list(cloudflare_ns_list),
                "instructions": nameserver_instructions,
                "estimated_propagation": "24-48 hours"
            },
            "a_record_method": {
                "server_ip": server_ip,
                "instructions": a_record_instructions,
                "records_to_add": [
                    {"type": "A", "name": "@", "value": server_ip, "ttl": "3600"},
                    {"type": "A", "name": "www", "value": server_ip, "ttl": "3600"}
                ],
                "estimated_propagation": "1-4 hours"
            },
            "important_notes": important_notes
        }
    
    return success_response(response_data)


@router.get("/hosting/calculate-price", response_model=dict)
async def calculate_hosting_price(
    plan: str = Query(..., regex="^(pro_7day|pro_30day)$"),
    period: int = Query(1, ge=1, le=12),
    key_data: dict = Depends(get_api_key_from_header)
):
    """Calculate hosting price with 10% API discount"""
    check_permission(key_data, "hosting", "read")
    
    prices = get_hosting_prices()
    price_per_period = float(prices.get(plan, 0))
    total_before_discount = price_per_period * period
    
    # Apply 10% API discount
    api_discount = total_before_discount * 0.10
    total = total_before_discount - api_discount
    
    return success_response({
        "plan": plan,
        "period": period,
        "price_per_period": price_per_period,
        "total_before_discount": total_before_discount,
        "api_discount": api_discount,
        "total_price": total
    })


@router.post("/hosting/order", response_model=dict)
async def unified_order_hosting(
    request: UnifiedOrderHostingRequest,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Unified endpoint to order hosting for any domain type.
    
    **domain_type options:**
    - `new`: Register a new domain + create cPanel hosting
    - `existing`: Use a domain already in your HostBay account + create cPanel hosting
    - `external`: Use a domain from another registrar + create cPanel hosting (returns DNS instructions)
    
    **Wallet is automatically debited** when cPanel account is created successfully.
    DNS/nameserver failures do NOT block payment - hosting works regardless.
    
    **For external domains**, the response includes:
    - `nameserver_status`: "manual_update_required"
    - `dns_instructions`: Step-by-step instructions to configure DNS at your registrar
    """
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    domain_type = request.domain_type
    
    # Validate domain_name requirement based on domain_type
    if domain_type in ("existing", "external") and not request.domain_name:
        raise BadRequestError(f"domain_name is required for domain_type '{domain_type}'")
    
    # For new domains, generate if not provided
    domain_name = request.domain_name or f"hosting_{secrets.token_hex(4)}.example.com"
    
    logger.info(f"🛒 API Unified Order - {domain_type} hosting order for user {user_id}, domain={domain_name}, plan={request.plan}")
    
    # PERFORMANCE OPTIMIZATION: Calculate pricing first, then fetch data in parallel
    price_per_period = HOSTING_PRICES.get(request.plan)
    if not price_per_period:
        raise BadRequestError(f"Invalid hosting plan: {request.plan}")
    
    total_before_discount = price_per_period * request.period
    api_discount = total_before_discount * Decimal("0.10")
    total_price = total_before_discount - api_discount
    
    # Map API plan names to database plan names
    plan_name_map = {
        "pro_7day": "Pro 7 Days",
        "pro_30day": "Pro 30 Days"
    }
    db_plan_name = plan_name_map.get(request.plan, request.plan)
    
    # Build parallel query tasks based on domain_type
    import asyncio
    balance_task = get_user_wallet_balance_by_id(user_id)
    plan_task = execute_query("""
        SELECT id FROM hosting_plans WHERE plan_name = %s AND is_active = true
    """, (db_plan_name,))
    
    domain_id = None
    if domain_type == "existing":
        domain_task = execute_query("""
            SELECT id, cloudflare_zone_id FROM domains WHERE domain_name = %s AND user_id = %s AND deleted_at IS NULL
        """, (domain_name, user_id))
        current_balance, plan_result, domain_result = await asyncio.gather(
            balance_task, plan_task, domain_task
        )
        if not domain_result:
            raise ResourceNotFoundError("Domain", domain_name)
        domain_id = domain_result[0]['id']
    else:
        current_balance, plan_result = await asyncio.gather(balance_task, plan_task)
    
    # Validate plan result before proceeding
    if not plan_result:
        raise BadRequestError(f"Hosting plan '{request.plan}' not found or is inactive")
    
    hosting_plan_id = plan_result[0]['id']
    
    if current_balance < total_price:
        raise BadRequestError(
            f"Insufficient wallet balance. Required: ${total_price:.2f}, Available: ${current_balance:.2f}",
            {"required": float(total_price), "available": float(current_balance)}
        )
    
    # Map domain_type to service_type
    service_type_map = {
        "new": "hosting_standalone",
        "existing": "hosting_with_existing_domain",
        "external": "hosting_with_external_domain"
    }
    service_type = service_type_map[domain_type]
    
    # Reserve wallet balance
    hold_transaction_id = await reserve_wallet_balance(
        user_id,
        total_price,
        f"Hosting order ({domain_type}): {domain_name}"
    )
    
    if not hold_transaction_id:
        raise InternalServerError("Failed to reserve wallet balance")
    logger.info(f"✅ Resolved hosting plan '{request.plan}' to plan_id={hosting_plan_id}")
    
    # Create hosting intent
    idempotency_key = f"hosting_intent_{user_id}_{domain_name}_{secrets.token_hex(8)}"
    try:
        intent_data = await execute_query("""
            INSERT INTO hosting_provision_intents (
                user_id, domain_id, domain_name, hosting_plan_id, service_type, quote_price,
                currency, status, idempotency_key
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            user_id, domain_id, domain_name, hosting_plan_id, service_type,
            float(total_price), 'USD', 'pending', idempotency_key
        ))
        
        if not intent_data or len(intent_data) == 0:
            raise ValueError("No intent_id returned from database")
            
        intent_id = intent_data[0]['id']
        logger.info(f"✅ Hosting provision intent created: intent_id={intent_id}")
    except Exception as e:
        logger.error(f"❌ Failed to create hosting provision intent: {str(e)}")
        await finalize_wallet_reservation(hold_transaction_id, success=False)
        raise InternalServerError(f"Failed to create hosting intent: {str(e)}")
    
    # Create order record
    try:
        order_data = await execute_query("""
            INSERT INTO orders (
                user_id, order_type, status, total_amount,
                external_order_id, created_at
            ) VALUES (%s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (
            user_id, service_type, 'pending', float(total_price),
            f"hosting_{domain_type}_{domain_name}_{user_id}_{secrets.token_hex(4)}"
        ))
        
        if not order_data or len(order_data) == 0:
            raise ValueError("No order_id returned from database")
            
        order_id = order_data[0]['id']
        logger.info(f"✅ Order record created: order_id={order_id}")
    except Exception as e:
        logger.error(f"❌ Failed to create order record: {str(e)}")
        await finalize_wallet_reservation(hold_transaction_id, success=False)
        raise InternalServerError(f"Failed to create order: {str(e)}")
    
    # Queue appropriate orchestrator based on domain_type
    import asyncio
    if domain_type == "new":
        asyncio.create_task(hosting_orchestrator.provision_standalone_hosting(
            order_id=order_id,
            intent_id=intent_id,
            user_id=user_id,
            domain_name=domain_name,
            plan=request.plan,
            hold_transaction_id=hold_transaction_id,
            auto_renew=request.auto_renew
        ))
    elif domain_type == "existing":
        asyncio.create_task(hosting_orchestrator.provision_hosting_for_existing_domain(
            order_id=order_id,
            intent_id=intent_id,
            user_id=user_id,
            domain_name=domain_name,
            plan=request.plan,
            hold_transaction_id=hold_transaction_id,
            auto_renew=request.auto_renew
        ))
    else:  # external
        asyncio.create_task(hosting_orchestrator.provision_hosting_for_external_domain(
            order_id=order_id,
            intent_id=intent_id,
            user_id=user_id,
            domain_name=domain_name,
            plan=request.plan,
            hold_transaction_id=hold_transaction_id,
            auto_renew=request.auto_renew,
            linking_mode=request.linking_mode or "nameserver"
        ))
    
    logger.info(f"🎉 Unified hosting order created - order_id={order_id}, type={domain_type}, domain={domain_name}")
    
    # Build response
    response_data = {
        "order_id": order_id,
        "intent_id": intent_id,
        "domain_name": domain_name,
        "domain_type": domain_type,
        "plan": request.plan,
        "status": "provisioning",
        "pricing": {
            "base_price_per_period": float(price_per_period),
            "periods": request.period,
            "price_before_discount": float(total_before_discount),
            "api_discount": float(api_discount),
            "final_price": float(total_price)
        },
        "amount_reserved": float(total_price),
        "hold_transaction_id": hold_transaction_id
    }
    
    # For external domains, add DNS instructions and nameserver_status
    if domain_type == "external":
        from services.cloudflare import CloudflareService
        cloudflare_service = CloudflareService()
        cloudflare_nameservers = await cloudflare_service.get_account_nameservers()
        server_ip = cpanel.default_server_ip
        
        response_data["nameserver_status"] = "manual_update_required"
        # New generic + legacy field names (backward compatibility)
        response_data["dns_nameservers"] = list(cloudflare_nameservers)
        response_data["cloudflare_nameservers"] = list(cloudflare_nameservers)
        response_data["server_ip"] = server_ip
        # Build instructions list without empty strings
        instructions_list = [
            f"1. Log in to your domain registrar where {domain_name} is registered",
            f"2. Navigate to the DNS/Nameserver settings",
            f"3. Update the nameservers to:"
        ]
        if cloudflare_nameservers:
            instructions_list.append(f"   - {cloudflare_nameservers[0]}")
            if len(cloudflare_nameservers) > 1:
                instructions_list.append(f"   - {cloudflare_nameservers[1]}")
        instructions_list.extend([
            f"4. Save the changes and wait for DNS propagation (24-48 hours)",
            f"5. Once nameservers are updated, your hosting will be fully configured"
        ])
        
        response_data["dns_instructions"] = {
            "message": "DNS records have been configured. Please update nameservers at your registrar to activate.",
            "nameservers": list(cloudflare_nameservers),
            "instructions": instructions_list,
            "estimated_propagation": "24-48 hours"
        }
        # A record status - orchestrator creates zone and A records asynchronously
        # New generic + legacy field names (backward compatibility)
        response_data["zone_id"] = None  # Available after provisioning completes
        response_data["cloudflare_zone_id"] = None
        response_data["a_record_status"] = "pending"
        response_data["a_records"] = {"root": "pending", "www": "pending"}
        response_data["provisioning_note"] = "DNS zone and A records are configured during provisioning. Check order status endpoint for final details."
    
    return success_response(response_data, f"Hosting order created ({domain_type}) with 10% API discount - provisioning started")


@router.get("/hosting/orders/{order_id}", response_model=dict)
async def get_hosting_order_status(
    order_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Get hosting order status by order ID
    
    Returns order status, provisioning progress, and related information.
    Useful for tracking orders that are in "provisioning" state.
    """
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    # Get order details
    order_result = await execute_query("""
        SELECT id, user_id, order_type, status, total_amount, external_order_id, created_at
        FROM orders
        WHERE id = %s AND user_id = %s
    """, (order_id, user_id))
    
    if not order_result:
        raise ResourceNotFoundError("Hosting order", str(order_id))
    
    order = order_result[0]
    
    # Try to find related hosting provision intent
    intent_result = None
    subscription_result = None
    
    # Extract domain name from external_order_id if possible
    external_id = order.get('external_order_id', '')
    domain_name = None
    if external_id.startswith('hosting_'):
        # Parse domain from external_order_id format:
        # - "hosting_{domain_type}_{domain_name}_{user_id}_{random_suffix}"
        # - e.g. "hosting_new_domain.sbs_3_abcd1234"
        # - e.g. "hosting_existing_example.com_3_abcd1234"
        # - e.g. "hosting_external_mysite.org_3_abcd1234"
        parts = external_id.split('_')
        if len(parts) >= 4:
            domain_type_keywords = {'new', 'existing', 'external'}
            # Check if second part is a domain_type keyword
            if parts[1] in domain_type_keywords:
                # Skip 'hosting' and domain_type, exclude user_id and random suffix
                # parts[2:-2] gives us the domain name parts (may contain underscores)
                domain_name = '_'.join(parts[2:-2]) if len(parts) > 4 else parts[2]
            else:
                # Legacy format without domain_type: "hosting_{domain_name}_{user_id}_{random_suffix}"
                domain_name = '_'.join(parts[1:-2]) if len(parts) > 3 else parts[1]
    
    if domain_name:
        # Get hosting provision intent
        intent_result = await execute_query("""
            SELECT id, domain_name, service_type, status, quote_price, error_message, last_error, created_at, updated_at
            FROM hosting_provision_intents
            WHERE domain_name = %s AND user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (domain_name, user_id))
        
        # Get hosting subscription if it was created (with cPanel account status and deletion metadata)
        subscription_result = await execute_query("""
            SELECT hs.id, hs.status AS subscription_status, hs.cpanel_username,
                   hs.created_at, hs.next_billing_date, hs.suspended_at,
                   hs.grace_period_started, hs.auto_renew, 
                   hs.updated_at AS subscription_updated_at,
                   hs.deleted_at AS subscription_deleted_at,
                   hs.deleted_by AS subscription_deleted_by,
                   ca.status AS cpanel_status, 
                   ca.deleted_at AS cpanel_deleted_at,
                   ca.updated_at AS cpanel_updated_at,
                   ca.deleted_by AS cpanel_deleted_by,
                   hp.plan_name
            FROM hosting_subscriptions hs
            LEFT JOIN cpanel_accounts ca ON ca.subscription_id = hs.id
            LEFT JOIN hosting_plans hp ON hp.id = hs.hosting_plan_id
            WHERE hs.domain_name = %s AND hs.user_id = %s
            ORDER BY hs.created_at DESC
            LIMIT 1
        """, (domain_name, user_id))
    
    # Build response
    response_data = {
        "order_id": order['id'],
        "order_type": order['order_type'],
        "status": order['status'],
        "amount": float(order['total_amount']) if order['total_amount'] else 0.0,
        "created_at": order['created_at'].isoformat() if order['created_at'] else None,
        "domain_name": domain_name
    }
    
    # Add provision intent details if available
    if intent_result and len(intent_result) > 0:
        intent = intent_result[0]
        response_data["provisioning"] = {
            "intent_id": intent['id'],
            "status": intent['status'],
            "service_type": intent['service_type'],
            "error_message": intent.get('error_message'),
            "last_error": intent.get('last_error'),
            "updated_at": intent['updated_at'].isoformat() if intent.get('updated_at') else None
        }
    
    # Add subscription details if hosting was created
    if subscription_result and len(subscription_result) > 0:
        subscription = subscription_result[0]
        sub_status = subscription['subscription_status']
        cpanel_status = subscription.get('cpanel_status')  # Can be None if no cPanel record
        
        subscription_data = {
            "id": subscription['id'],
            "status": sub_status,
            "cpanel_username": subscription.get('cpanel_username'),
            "plan_name": subscription.get('plan_name'),
            "created_at": subscription['created_at'].isoformat() if subscription['created_at'] else None,
            "expires_at": subscription['next_billing_date'].isoformat() if subscription.get('next_billing_date') else None,
            "auto_renew": subscription.get('auto_renew', False)
        }
        
        # Add subscription updated_at timestamp when available
        if subscription.get('subscription_updated_at'):
            subscription_data["updated_at"] = subscription['subscription_updated_at'].isoformat()
        
        # Add subscription deletion metadata when available
        if subscription.get('subscription_deleted_at'):
            subscription_data["deleted_at"] = subscription['subscription_deleted_at'].isoformat()
        if subscription.get('subscription_deleted_by'):
            subscription_data["deleted_by"] = subscription['subscription_deleted_by']
        
        # Add cPanel-specific status information (or None if no record exists)
        cpanel_info = {}
        if cpanel_status is not None:
            cpanel_info["status"] = cpanel_status
            if subscription.get('cpanel_deleted_at'):
                cpanel_info["deleted_at"] = subscription['cpanel_deleted_at'].isoformat()
            if subscription.get('cpanel_updated_at'):
                cpanel_info["updated_at"] = subscription['cpanel_updated_at'].isoformat()
            if subscription.get('cpanel_deleted_by'):
                cpanel_info["deleted_by"] = subscription['cpanel_deleted_by']
        else:
            # No cPanel account record found - leave as None, let client interpret
            cpanel_info["status"] = None
            cpanel_info["note"] = "No cPanel account record in database"
        
        subscription_data["cpanel_account"] = cpanel_info
        
        # Add suspension details if applicable
        if subscription.get('suspended_at'):
            subscription_data["suspended_at"] = subscription['suspended_at'].isoformat()
        
        # Add grace period details if applicable
        if subscription.get('grace_period_started'):
            subscription_data["grace_period_started"] = subscription['grace_period_started'].isoformat()
        
        # Add credentials endpoint reference (only for active/suspended - not deleted)
        if sub_status in ['active', 'suspended', 'grace_period']:
            subscription_data["credentials_endpoint"] = f"/api/v1/hosting/{subscription['id']}/credentials"
        
        # Add status-specific warnings (prioritized by severity)
        status_warnings = []
        
        # CRITICAL: Subscription active but cPanel deleted (data corruption)
        if sub_status == 'active' and cpanel_status == 'deleted':
            status_warnings.append("CRITICAL: Subscription shows active but cPanel account is deleted - contact support immediately")
        
        # WARNING: Subscription deleted but cPanel still active (incomplete deletion)
        elif sub_status == 'deleted' and cpanel_status == 'active':
            status_warnings.append("WARNING: Subscription deleted but cPanel account may still exist on server")
        
        # INFO: No cPanel record but subscription exists (provisioning may be incomplete)
        elif cpanel_status is None and sub_status not in ['pending', 'provisioning']:
            status_warnings.append("INFO: No cPanel account record found - provisioning may be incomplete")
        
        # Grace period warning
        if sub_status == 'grace_period':
            status_warnings.append("Subscription in grace period - renew soon to avoid service interruption")
        
        # Suspended warning
        if sub_status == 'suspended':
            status_warnings.append("Service is suspended - files preserved but website/email unavailable")
        
        if status_warnings:
            subscription_data["warnings"] = status_warnings
        
        response_data["subscription"] = subscription_data
    
    # Add comprehensive helpful status messages (prioritize critical subscription issues)
    status_messages = []
    critical_issues = []
    
    # PRIORITY 1: Check for critical subscription/cPanel mismatches first
    if subscription_result and len(subscription_result) > 0:
        sub_status = subscription_result[0]['subscription_status']
        cpanel_status = subscription_result[0].get('cpanel_status')
        
        # Critical data corruption issues
        if sub_status == 'active' and cpanel_status == 'deleted':
            critical_issues.append("❌ CRITICAL: Database shows active but cPanel account is deleted")
        elif sub_status == 'deleted' and cpanel_status == 'active':
            critical_issues.append("⚠️ WARNING: Subscription deleted but cPanel account may still exist on server")
        
        # PRIORITY 2: Subscription-level status messages
        if sub_status == 'active':
            if cpanel_status == 'active':
                status_messages.append("✅ Hosting is active and fully operational")
            elif cpanel_status == 'suspended':
                status_messages.append("⚠️ Hosting account is suspended on cPanel server")
            elif cpanel_status is None:
                status_messages.append("⚠️ No cPanel account record found")
        
        elif sub_status == 'suspended':
            status_messages.append("🔒 Hosting suspended - website and email are offline, files preserved")
        
        elif sub_status == 'grace_period':
            status_messages.append("⏰ Grace period active - renew soon to prevent suspension")
        
        elif sub_status == 'deleted':
            if cpanel_status == 'deleted':
                status_messages.append("🗑️ Hosting completely deleted from both database and server")
            elif not (cpanel_status == 'active'):  # Already handled in critical_issues
                status_messages.append("🗑️ Hosting subscription has been deleted")
        
        elif sub_status == 'provisioning':
            status_messages.append("⏳ Hosting is currently being provisioned - check back shortly")
        
        elif sub_status == 'failed':
            status_messages.append("❌ Hosting provisioning failed - contact support for assistance")
        
        elif sub_status == 'pending_renewal':
            status_messages.append("💳 Renewal payment pending - complete payment to continue service")
    
    # PRIORITY 3: Order-level status (only if no critical subscription issues)
    if not critical_issues:
        if order['status'] == 'pending':
            status_messages.insert(0, "Order is queued for provisioning")
        elif order['status'] == 'completed':
            status_messages.insert(0, "Order completed successfully")
        elif order['status'] == 'failed':
            base_msg = "Order failed - please contact support or try again"
            if intent_result and len(intent_result) > 0:
                error = intent_result[0].get('error_message') or intent_result[0].get('last_error')
                if error:
                    base_msg = f"Order failed: {error}"
            status_messages.insert(0, base_msg)
    
    # Combine with critical issues first
    all_messages = critical_issues + status_messages
    response_data["message"] = " | ".join(all_messages) if all_messages else "Order status retrieved"
    response_data["status_details"] = all_messages
    
    return success_response(response_data)


@router.get("/hosting", response_model=dict)
async def list_hosting_subscriptions(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    key_data: dict = Depends(get_api_key_from_header)
):
    """List all hosting subscriptions"""
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    offset = (page - 1) * per_page
    
    subscriptions = await execute_query("""
        SELECT hs.id, hs.domain_name, hp.plan_name, hs.status, hs.created_at, hs.next_billing_date
        FROM hosting_subscriptions hs
        JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id
        WHERE hs.user_id = %s
        ORDER BY hs.created_at DESC
        LIMIT %s OFFSET %s
    """, (user_id, per_page, offset))
    
    sub_list = [{
        "id": s['id'],
        "domain_name": s['domain_name'],
        "plan": s['plan_name'],
        "status": s['status'],
        "created_at": s['created_at'].isoformat() if s['created_at'] else None,
        "expires_at": s['next_billing_date'].isoformat() if s['next_billing_date'] else None
    } for s in subscriptions]
    
    return success_response({"subscriptions": sub_list, "total": len(sub_list)})


@router.get("/hosting/{subscription_id}", response_model=dict)
async def get_hosting_subscription(
    subscription_id: int,
    include: str = Query(None, description="Comma-separated list of additional data to include: credentials, usage"),
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Get hosting subscription details with optional additional data.
    
    **Query Parameters:**
    - `include`: Comma-separated values to include additional data
      - `credentials`: Include cPanel/FTP login details
      - `usage`: Include disk and bandwidth statistics (fetched live from cPanel)
    
    **Examples:**
    - `GET /hosting/123` - Basic subscription info
    - `GET /hosting/123?include=credentials` - Include login credentials
    - `GET /hosting/123?include=usage` - Include usage statistics
    - `GET /hosting/123?include=credentials,usage` - Include everything
    """
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT hs.id, hs.domain_name, hp.plan_name, hs.status, hs.cpanel_username, 
               hs.created_at, hs.next_billing_date, hs.server_ip, hs.auto_renew
        FROM hosting_subscriptions hs
        JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id
        WHERE hs.id = %s AND hs.user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    s = result[0]
    server_ip = s.get('server_ip') or cpanel.default_server_ip
    
    response_data = {
        "id": s['id'],
        "domain_name": s['domain_name'],
        "plan": s['plan_name'],
        "status": s['status'],
        # New generic field name
        "username": s['cpanel_username'],
        # Legacy field name (backward compatibility)
        "cpanel_username": s['cpanel_username'],
        "created_at": s['created_at'].isoformat() if s['created_at'] else None,
        "expires_at": s['next_billing_date'].isoformat() if s['next_billing_date'] else None,
        "server_ip": server_ip,
        "is_active": s['status'] == "active"
    }
    
    include_list = [x.strip().lower() for x in include.split(',')] if include else []
    
    if 'credentials' in include_list:
        if s['status'] not in ('deleted', 'terminated'):
            response_data['credentials'] = {
                # New generic field names
                "control_panel_url": f"https://{server_ip}:2083",
                "username": s['cpanel_username'],
                # Legacy field names (backward compatibility)
                "cpanel_url": f"https://{server_ip}:2083",
                "cpanel_username": s['cpanel_username'],
                "password_note": "Contact support to reset password - not stored for security",
                "ftp_host": server_ip,
                "ftp_port": 21,
                "security_note": "Passwords are not stored. Use 'Reset Password' endpoint to generate new credentials."
            }
        else:
            response_data['credentials'] = None
            response_data['credentials_note'] = "Credentials unavailable for deleted/terminated subscriptions"
    
    if 'usage' in include_list:
        if s['status'] == 'active':
            try:
                usage = await cpanel.get_account_usage(s['cpanel_username'])
                if usage:
                    response_data['usage'] = {
                        "disk_used_mb": usage.get('disk_used_mb', 0),
                        "disk_limit_mb": usage.get('disk_limit_mb', 0),
                        "bandwidth_used_mb": usage.get('bandwidth_used_mb', 0),
                        "bandwidth_limit_mb": usage.get('bandwidth_limit_mb', 0),
                        "fetched_at": __import__('datetime').datetime.utcnow().isoformat() + "Z"
                    }
                else:
                    response_data['usage'] = None
                    response_data['usage_note'] = "Failed to retrieve usage statistics"
            except Exception as e:
                logger.warning(f"Failed to fetch usage for subscription {subscription_id}: {e}")
                response_data['usage'] = None
                response_data['usage_note'] = "Usage temporarily unavailable"
        elif s['status'] == 'suspended':
            response_data['usage'] = None
            response_data['usage_note'] = "Usage unavailable for suspended subscriptions"
        else:
            response_data['usage'] = None
            response_data['usage_note'] = f"Usage unavailable for {s['status']} subscriptions"
    
    return success_response(response_data)


@router.post("/hosting/{subscription_id}/renew", response_model=dict)
async def renew_hosting(
    subscription_id: int,
    request: RenewHostingRequest,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Renew hosting subscription with automatic wallet debit.
    
    Supports plan switching: pass optional 'plan' parameter to switch to a different plan during renewal.
    - Omit 'plan' to renew with current plan
    - Specify 'plan' (pro_7day or pro_30day) to switch plans
    
    Note: Downgrading may fail if current resource usage exceeds the new plan's limits.
    """
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    from datetime import datetime, timezone, timedelta
    from database import finalize_wallet_reservation
    
    result = await execute_query("""
        SELECT hp.id as plan_id, hp.plan_name, hp.plan_code, hs.next_billing_date, 
               hs.status, hs.cpanel_username
        FROM hosting_subscriptions hs
        JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id
        WHERE hs.id = %s AND hs.user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    subscription = result[0]
    current_plan_name = subscription['plan_name']
    current_plan_code = subscription['plan_code']
    current_plan_id = subscription['plan_id']
    status = subscription['status']
    cpanel_username = subscription['cpanel_username']
    
    if status in ['suspended', 'cancelled', 'terminated']:
        raise BadRequestError(f"Cannot renew {status} subscription. Please contact support.")
    
    plan_switching = False
    target_plan_name = current_plan_name
    target_plan_code = current_plan_code
    target_plan_id = current_plan_id
    
    if request.plan:
        target_plan_code = request.plan
        target_plan_result = await execute_query("""
            SELECT id, plan_name, plan_code, disk_space_gb, bandwidth_gb FROM hosting_plans WHERE plan_code = %s
        """, (target_plan_code,))
        
        if not target_plan_result:
            raise BadRequestError(f"Invalid plan: {request.plan}. Available: pro_7day, pro_30day")
        
        target_plan_id = target_plan_result[0]['id']
        target_plan_name = target_plan_result[0]['plan_name']
        target_disk_gb = target_plan_result[0].get('disk_space_gb', 100)
        
        if target_plan_id != current_plan_id:
            plan_switching = True
            logger.info(f"📦 Plan switch requested: {current_plan_name} -> {target_plan_name}")
            
            current_plan_data = await execute_query("""
                SELECT disk_space_gb FROM hosting_plans WHERE id = %s
            """, (current_plan_id,))
            current_disk_gb = current_plan_data[0].get('disk_space_gb', 100) if current_plan_data else 100
            
            is_downgrade = target_disk_gb < current_disk_gb
            
            if is_downgrade and status == 'active' and cpanel_username:
                try:
                    usage = await cpanel.get_account_usage(cpanel_username)
                    if usage:
                        disk_used_mb = usage.get('disk_used_mb', 0)
                        disk_used_gb = disk_used_mb / 1024
                        target_limit_mb = target_disk_gb * 1024
                        
                        if disk_used_mb > target_limit_mb * 0.9:
                            raise BadRequestError(
                                f"Cannot downgrade: Current disk usage ({disk_used_gb:.1f}GB) exceeds 90% of target plan limit ({target_disk_gb}GB). "
                                f"Please reduce disk usage before downgrading.",
                                {"current_usage_gb": round(disk_used_gb, 2), "target_limit_gb": target_disk_gb}
                            )
                except BadRequestError:
                    raise
                except Exception as e:
                    logger.warning(f"⚠️ Could not verify usage for downgrade check: {e}")
    
    price_per_period = HOSTING_PRICES.get(target_plan_name) or HOSTING_PRICES.get(target_plan_code)
    if not price_per_period:
        price_per_period = get_hosting_prices().get("pro_30day", Decimal("80.00"))
    
    total_before_discount = price_per_period * request.period
    api_discount = total_before_discount * Decimal("0.10")
    total_price = total_before_discount - api_discount
    
    current_balance = await get_user_wallet_balance_by_id(user_id)
    if current_balance < total_price:
        raise BadRequestError(
            f"Insufficient wallet balance. Required: ${total_price:.2f}, Available: ${current_balance:.2f}",
            {"required": float(total_price), "available": float(current_balance)}
        )
    
    hold_transaction_id = await reserve_wallet_balance(
        user_id,
        total_price,
        f"Hosting {'switch & ' if plan_switching else ''}renewal: subscription {subscription_id}"
    )
    
    if not hold_transaction_id:
        raise InternalServerError("Failed to reserve wallet balance")
    
    try:
        period_days = 7 if 'pro_7day' in target_plan_code or '7' in target_plan_name else 30
        extension_days = period_days * request.period
        
        if plan_switching:
            whm_package = target_plan_code
            if cpanel_username and status == 'active':
                package_changed = await cpanel.change_package(cpanel_username, whm_package)
                if not package_changed:
                    logger.error(f"❌ cPanel package change failed for {cpanel_username} to {whm_package}")
                    raise BadRequestError(
                        f"Plan switch failed: Could not change hosting package on server. Please try again or contact support."
                    )
            
            await execute_update("""
                UPDATE hosting_subscriptions
                SET hosting_plan_id = %s,
                    next_billing_date = next_billing_date + (%s || ' days')::interval,
                    updated_at = NOW()
                WHERE id = %s
            """, (target_plan_id, extension_days, subscription_id))
            logger.info(f"✅ Plan switched from {current_plan_name} to {target_plan_name} for subscription {subscription_id}")
        else:
            await execute_update("""
                UPDATE hosting_subscriptions
                SET next_billing_date = next_billing_date + (%s || ' days')::interval,
                    updated_at = NOW()
                WHERE id = %s
            """, (extension_days, subscription_id))
        
        await finalize_wallet_reservation(hold_transaction_id, success=True)
        
        is_upgrade = plan_switching and (target_plan_code == 'pro_30day' and current_plan_code == 'pro_7day')
        is_downgrade = plan_switching and (target_plan_code == 'pro_7day' and current_plan_code == 'pro_30day')
        
        response_data = {
            "subscription_id": subscription_id,
            "renewed": True,
            "period": request.period,
            "extension_days": extension_days,
            "plan": {
                "code": target_plan_code,
                "name": target_plan_name,
                "switched": plan_switching,
                "switch_type": "upgrade" if is_upgrade else ("downgrade" if is_downgrade else None)
            },
            "pricing": {
                "base_price_per_period": float(price_per_period),
                "periods": request.period,
                "price_before_discount": float(total_before_discount),
                "api_discount": float(api_discount),
                "final_price": float(total_price)
            },
            "amount_charged": float(total_price)
        }
        
        if plan_switching:
            response_data["previous_plan"] = current_plan_name
        
        message = "Hosting renewed successfully with 10% API discount"
        if plan_switching:
            message = f"Plan switched from {current_plan_name} to {target_plan_name} and renewed with 10% API discount"
        
        return success_response(response_data, message)
        
    except Exception as e:
        await finalize_wallet_reservation(hold_transaction_id, success=False)
        logger.error(f"❌ Renewal failed for subscription {subscription_id}: {e}")
        raise InternalServerError(f"Renewal failed: {str(e)}")


@router.get("/hosting/{subscription_id}/renewal-price", response_model=dict)
async def get_renewal_price(
    subscription_id: int,
    period: int = Query(1, ge=1, le=12),
    plan: str = Query(None, pattern="^(pro_7day|pro_30day)$", description="Optional: Get price for a different plan"),
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Get hosting renewal price with 10% API discount.
    
    Pass optional 'plan' parameter to get pricing for switching to a different plan.
    """
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT hp.plan_name, hp.plan_code
        FROM hosting_subscriptions hs
        JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id
        WHERE hs.id = %s AND hs.user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    current_plan_name = result[0]['plan_name']
    current_plan_code = result[0]['plan_code']
    
    target_plan_code = plan if plan else current_plan_code
    target_plan_name = current_plan_name
    is_switch = False
    
    if plan and plan != current_plan_code:
        target_plan_result = await execute_query("""
            SELECT plan_name FROM hosting_plans WHERE plan_code = %s
        """, (plan,))
        if target_plan_result:
            target_plan_name = target_plan_result[0]['plan_name']
            is_switch = True
    
    price_per_period = HOSTING_PRICES.get(target_plan_name) or HOSTING_PRICES.get(target_plan_code) or get_hosting_prices().get("pro_30day", Decimal("80.00"))
    total_before_discount = price_per_period * period
    
    api_discount = total_before_discount * Decimal("0.10")
    total_price = total_before_discount - api_discount
    
    period_days = 7 if 'pro_7day' in target_plan_code or '7' in target_plan_name else 30
    
    return success_response({
        "subscription_id": subscription_id,
        "current_plan": current_plan_name,
        "target_plan": target_plan_name,
        "is_plan_switch": is_switch,
        "period": period,
        "extension_days": period_days * period,
        "price_per_period": float(price_per_period),
        "total_before_discount": float(total_before_discount),
        "api_discount": float(api_discount),
        "total_price": float(total_price)
    })


@router.get("/hosting/{subscription_id}/renewal-options", response_model=dict)
async def get_renewal_options(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Get all available renewal options for a subscription.
    
    Returns all available plans with pricing for periods 1-6, perfect for populating a dropdown.
    Shows which plan is currently active and pricing for both same-plan renewal and plan switching.
    """
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT hp.id as plan_id, hp.plan_name, hp.plan_code, hs.next_billing_date, hs.status
        FROM hosting_subscriptions hs
        JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id
        WHERE hs.id = %s AND hs.user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    subscription = result[0]
    current_plan_code = subscription['plan_code']
    current_plan_name = subscription['plan_name']
    
    all_plans = await execute_query("""
        SELECT id, plan_name, plan_code, duration_days FROM hosting_plans ORDER BY duration_days
    """)
    
    current_balance = await get_user_wallet_balance_by_id(user_id)
    
    renewal_options = []
    
    for plan in all_plans:
        plan_code = plan['plan_code']
        plan_name = plan['plan_name']
        duration_days = plan['duration_days']
        is_current = plan_code == current_plan_code
        
        price_per_period = HOSTING_PRICES.get(plan_name) or HOSTING_PRICES.get(plan_code) or get_hosting_prices().get("pro_30day", Decimal("80.00"))
        
        periods = []
        for p in range(1, 7):
            total_before_discount = price_per_period * p
            api_discount = total_before_discount * Decimal("0.10")
            total_price = total_before_discount - api_discount
            extension_days = duration_days * p
            
            label = f"{extension_days} days" if extension_days < 30 else f"{extension_days // 30} month{'s' if extension_days >= 60 else ''}"
            
            periods.append({
                "period": p,
                "extension_days": extension_days,
                "label": label,
                "price_before_discount": float(total_before_discount),
                "api_discount": float(api_discount),
                "total_price": float(total_price),
                "can_afford": current_balance >= total_price
            })
        
        renewal_options.append({
            "plan_code": plan_code,
            "plan_name": plan_name,
            "duration_days": duration_days,
            "is_current_plan": is_current,
            "price_per_period": float(price_per_period),
            "periods": periods
        })
    
    return success_response({
        "subscription_id": subscription_id,
        "current_plan": {
            "code": current_plan_code,
            "name": current_plan_name
        },
        "next_billing_date": subscription['next_billing_date'].isoformat() if subscription['next_billing_date'] else None,
        "wallet_balance": float(current_balance),
        "renewal_options": renewal_options,
        "note": "Pass plan=pro_7day or plan=pro_30day to POST /hosting/{subscription_id}/renew to switch plans"
    })


@router.post("/hosting/{subscription_id}/suspend", response_model=dict)
async def suspend_hosting(
    subscription_id: int,
    reason: str = "Payment overdue",
    key_data: dict = Depends(get_api_key_from_header)
):
    """Suspend hosting account"""
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    # Get subscription details
    result = await execute_query("""
        SELECT cpanel_username FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    
    # Suspend via cPanel
    suspend_result = await cpanel.suspend_account(cpanel_username)
    
    if suspend_result:
        # Update database
        await execute_update("""
            UPDATE hosting_subscriptions
            SET status = 'suspended'
            WHERE id = %s
        """, (subscription_id,))
    
    return success_response({
        "subscription_id": subscription_id,
        "suspended": suspend_result,
        "reason": reason
    })


@router.post("/hosting/{subscription_id}/unsuspend", response_model=dict)
async def unsuspend_hosting(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """Unsuspend hosting account"""
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    # Get subscription details
    result = await execute_query("""
        SELECT cpanel_username FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    
    # Unsuspend via cPanel
    unsuspend_result = await cpanel.unsuspend_account(cpanel_username)
    
    if unsuspend_result:
        # Update database
        await execute_update("""
            UPDATE hosting_subscriptions
            SET status = 'active'
            WHERE id = %s
        """, (subscription_id,))
    
    return success_response({
        "subscription_id": subscription_id,
        "suspended": False,
        "active": unsuspend_result
    })


@router.delete("/hosting/{subscription_id}", response_model=dict)
async def delete_hosting(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Delete/cancel hosting subscription and remove cPanel account
    
    This will:
    1. Verify subscription ownership
    2. Delete cPanel account from server
    3. Mark subscription as deleted in database
    4. Preserve records for audit trail
    """
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    # Get subscription details
    result = await execute_query("""
        SELECT id, cpanel_username, domain_name, status
        FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    subscription = result[0]
    cpanel_username = subscription['cpanel_username']
    domain_name = subscription['domain_name']
    current_status = subscription['status']
    
    # Check if already deleted
    if current_status == 'deleted':
        return success_response({
            "subscription_id": subscription_id,
            "already_deleted": True,
            "message": "Subscription was already deleted"
        })
    
    logger.info(f"🗑️ Deleting hosting subscription {subscription_id} for user {user_id}, cpanel_username={cpanel_username}")
    
    # Delete from cPanel server (with confirmation safety)
    delete_success = await cpanel.delete_single_account(cpanel_username, cpanel_username)
    
    if not delete_success:
        logger.error(f"❌ Failed to delete cPanel account {cpanel_username} from server")
        raise InternalServerError(
            f"Failed to delete cPanel account from server. Please contact support.",
            {
                "subscription_id": subscription_id,
                "cpanel_username": cpanel_username,
                "error": "cPanel account deletion failed"
            }
        )
    
    # Only mark as deleted if cPanel deletion succeeded
    logger.info(f"✅ cPanel account {cpanel_username} deleted from server successfully")
    
    # Mark subscription as deleted in database (soft delete)
    await execute_update("""
        UPDATE hosting_subscriptions
        SET status = 'deleted', updated_at = NOW()
        WHERE id = %s
    """, (subscription_id,))
    
    # Mark associated cPanel account as deleted
    await execute_update("""
        UPDATE cpanel_accounts
        SET status = 'deleted', deleted_at = NOW(), deleted_by = %s
        WHERE subscription_id = %s
    """, (user_id, subscription_id))
    
    logger.info(f"✅ Hosting subscription {subscription_id} deleted successfully (both cPanel and database)")
    
    return success_response({
        "subscription_id": subscription_id,
        # New generic + legacy field names (backward compatibility)
        "username": cpanel_username,
        "cpanel_username": cpanel_username,
        "domain_name": domain_name,
        "deleted": True
    }, "Hosting subscription deleted successfully")


@router.get("/hosting/{subscription_id}/credentials", response_model=dict, deprecated=True)
async def get_hosting_credentials(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    **DEPRECATED** - Use `GET /hosting/{id}?include=credentials` instead.
    
    Get cPanel credentials.
    This endpoint will be removed in a future version.
    """
    from fastapi.responses import JSONResponse
    
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username, server_ip FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    sub_data = result[0]
    cpanel_username = sub_data['cpanel_username']
    server_ip = sub_data.get('server_ip', cpanel.default_server_ip)
    
    response = success_response({
        # New generic field names
        "control_panel_url": f"https://{server_ip}:2083",
        "username": cpanel_username,
        # Legacy field names (backward compatibility)
        "cpanel_url": f"https://{server_ip}:2083",
        "cpanel_username": cpanel_username,
        "password_note": "Contact support to reset password - not stored for security",
        "ftp_host": server_ip,
        "ftp_port": 21,
        "security_note": "Passwords are not stored. Use 'Reset Password' endpoint to generate new credentials.",
        "_deprecated": True,
        "_migration": "Use GET /api/v1/hosting/{id}?include=credentials instead"
    })
    return response


@router.post("/hosting/{subscription_id}/reset-password", response_model=dict)
async def reset_password(
    subscription_id: int,
    request: ResetPasswordRequest,
    key_data: dict = Depends(get_api_key_from_header)
):
    """Reset hosting control panel password"""
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    
    reset_result = await cpanel.reset_password(cpanel_username, request.new_password)
    
    if reset_result is False or reset_result is None:
        raise InternalServerError("Failed to reset password",  {"details": reset_result if reset_result else "Password reset returned None"})
    
    return success_response({
        "subscription_id": subscription_id,
        "password_reset": True,
        # New generic + legacy field names (backward compatibility)
        "username": cpanel_username,
        "cpanel_username": cpanel_username
    }, "Hosting password reset successfully")


@router.get("/hosting/{subscription_id}/usage", response_model=dict, deprecated=True)
async def get_hosting_usage(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    **DEPRECATED** - Use `GET /hosting/{id}?include=usage` instead.
    
    Get hosting usage statistics.
    This endpoint will be removed in a future version.
    """
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    
    usage = await cpanel.get_account_usage(cpanel_username)
    
    if not usage:
        raise InternalServerError("Failed to retrieve usage statistics")
    
    return success_response({
        "disk_used_mb": usage.get('disk_used_mb', 0),
        "disk_limit_mb": usage.get('disk_limit_mb', 0),
        "bandwidth_used_mb": usage.get('bandwidth_used_mb', 0),
        "bandwidth_limit_mb": usage.get('bandwidth_limit_mb', 0),
        "_deprecated": True,
        "_migration": "Use GET /api/v1/hosting/{id}?include=usage instead"
    })


@router.get("/hosting/{subscription_id}/emails", response_model=dict)
async def list_emails(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """List email accounts"""
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username, domain_name FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    domain_name = result[0]['domain_name']
    
    email_data = await cpanel.list_email_accounts(cpanel_username, domain_name)
    
    if not email_data:
        raise InternalServerError("Failed to retrieve email accounts")
    
    emails = email_data.get('emails', [])
    
    return success_response({"emails": emails, "total": len(emails)})


@router.post("/hosting/{subscription_id}/emails", response_model=dict)
async def create_email(
    subscription_id: int,
    request: dict,
    key_data: dict = Depends(get_api_key_from_header)
):
    """Create email account"""
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username, domain_name FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    domain_name = result[0]['domain_name']
    
    email_user = request.get('email_user')
    password = request.get('password')
    quota_mb = request.get('quota_mb', 250)
    
    if not email_user or not password:
        raise BadRequestError("email_user and password are required")
    
    email_result = await cpanel.create_email_account(
        cpanel_username, 
        domain_name, 
        email_user, 
        password, 
        quota_mb
    )
    
    if not email_result or not email_result.get('success'):
        raise InternalServerError("Failed to create email account")
    
    return success_response({
        "email": email_result.get('email'),
        "created": True
    }, "Email account created successfully")


@router.get("/hosting/{subscription_id}/databases", response_model=dict)
async def list_databases(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """List databases"""
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    
    db_data = await cpanel.list_databases(cpanel_username)
    
    if not db_data:
        raise InternalServerError("Failed to retrieve databases")
    
    databases = db_data.get('databases', [])
    
    return success_response({"databases": databases, "total": len(databases)})


@router.post("/hosting/{subscription_id}/databases", response_model=dict)
async def create_database(
    subscription_id: int,
    request: dict,
    key_data: dict = Depends(get_api_key_from_header)
):
    """Create database"""
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    database_name = request.get('database_name')
    
    if not database_name:
        raise BadRequestError("database_name is required")
    
    db_result = await cpanel.create_database(cpanel_username, database_name)
    
    if not db_result or not db_result.get('success'):
        raise InternalServerError("Failed to create database")
    
    return success_response({
        "database": db_result.get('database'),
        "created": True
    }, "Database created successfully")


@router.get("/hosting/{subscription_id}/ssl", response_model=dict)
async def get_ssl_status(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """Get SSL certificate status"""
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT domain_name FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    domain_name = result[0]['domain_name']
    
    ssl_info = await cpanel.get_ssl_status(domain_name)
    
    if not ssl_info:
        raise InternalServerError("Failed to retrieve SSL status")
    
    return success_response({
        "has_ssl": ssl_info.get('has_ssl', False),
        "issuer": ssl_info.get('issuer', 'N/A'),
        "expires_at": ssl_info.get('expires_at')
    })


@router.post("/hosting/{subscription_id}/ssl/install", response_model=dict)
async def install_ssl(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """Install SSL certificate"""
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT domain_name FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    domain_name = result[0]['domain_name']
    
    ssl_result = await cpanel.install_ssl_certificate(domain_name)
    
    if not ssl_result or not ssl_result.get('success'):
        raise InternalServerError("Failed to install SSL certificate")
    
    return success_response({
        "ssl_installed": True,
        "issuer": ssl_result.get('issuer', 'Let\'s Encrypt')
    }, "SSL certificate installed successfully")




@router.get("/hosting/{subscription_id}/addon-domains", response_model=dict)
async def list_addon_domains(
    subscription_id: int,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    List all addon domains for a hosting subscription.
    
    Returns a list of addon domains attached to the cPanel account,
    including their document roots and status. Also includes pending
    addon domains that are awaiting DNS propagation.
    """
    check_permission(key_data, "hosting", "read")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username, domain_name FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    primary_domain = result[0]['domain_name']
    
    addon_result = await cpanel.list_addon_domains(cpanel_username)
    
    if not addon_result:
        raise InternalServerError("Failed to retrieve addon domains")
    
    addon_domains = addon_result.get('addon_domains', [])
    
    pending_jobs = await execute_query("""
        SELECT addon_domain, domain_type, status, retry_count, max_retries, 
               next_attempt_at, last_error, created_at
        FROM addon_domain_pending_jobs
        WHERE subscription_id = %s AND user_id = %s AND status IN ('pending', 'processing')
        ORDER BY created_at DESC
    """, (subscription_id, user_id))
    
    pending_addon_domains = []
    for job in (pending_jobs or []):
        cpanel_addon_domains = [a.get('domain', '').lower() for a in addon_domains]
        if job['addon_domain'].lower() not in cpanel_addon_domains:
            pending_addon_domains.append({
                "domain": job['addon_domain'],
                "type": job['domain_type'],
                "status": "pending_dns_propagation",
                "cpanel_status": job['status'],
                "retry_count": job['retry_count'],
                "max_retries": job['max_retries'],
                "next_attempt_at": job['next_attempt_at'].isoformat() if job['next_attempt_at'] else None,
                "last_error": job['last_error'],
                "created_at": job['created_at'].isoformat() if job['created_at'] else None
            })
    
    all_domains = [{"domain": primary_domain, "type": "primary"}]
    for addon in addon_domains:
        all_domains.append({
            "domain": addon.get('domain'),
            "type": "addon",
            "status": "active",
            "subdomain": addon.get('subdomain'),
            "document_root": addon.get('document_root')
        })
    for pending in pending_addon_domains:
        all_domains.append({
            "domain": pending['domain'],
            "type": "addon",
            "status": "pending_dns_propagation",
            "cpanel_status": pending['cpanel_status'],
            "retry_count": pending['retry_count'],
            "next_attempt_at": pending['next_attempt_at']
        })
    
    return success_response({
        "subscription_id": subscription_id,
        "primary_domain": primary_domain,
        "addon_domains": addon_domains,
        "pending_addon_domains": pending_addon_domains,
        "all_domains": all_domains,
        "total_addon": len(addon_domains),
        "total_pending": len(pending_addon_domains),
        "total_all": len(all_domains)
    })


@router.post("/hosting/{subscription_id}/addon-domains", response_model=dict)
async def add_addon_domain(
    subscription_id: int,
    request: dict,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Add an addon domain to a hosting subscription.
    
    Addon domains allow you to host additional websites on the same cPanel account.
    Each addon domain gets its own document root directory.
    
    **Domain Types:**
    - register_new=true: Register a NEW domain (requires wallet balance, charges registration fee)
    - register_new=false (default): Add an existing domain
      - If domain is in your HostBay account, nameservers are auto-updated to Cloudflare
      - If domain is external, you receive nameserver instructions
    
    **Request Body:**
    - domain: The addon domain to add (e.g., 'example.com') - required
    - register_new: If true, register the domain first (default: false)
    - period: Registration period in years if registering new (default: 1)
    - auto_renew_domain: Auto-renew domain registration (default: true)
    - subdomain: Optional subdomain prefix (defaults to domain name without TLD)
    - document_root: Optional custom document root path
    - dns_only: If true, only set up DNS records without adding to cPanel (default: false)
      Use this for external domains that need DNS configured before cPanel will accept them.
      Once DNS propagates, call this endpoint again without dns_only to complete the setup.
    """
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    addon_domain = request.get('domain')
    if not addon_domain:
        raise BadRequestError("domain is required")
    
    register_new = request.get('register_new', False)
    period = request.get('period', 1)
    auto_renew_domain = request.get('auto_renew_domain', True)
    dns_only = request.get('dns_only', False)
    
    result = await execute_query("""
        SELECT cpanel_username, domain_name, server_ip FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    primary_domain = result[0]['domain_name']
    server_ip = result[0].get('server_ip') or cpanel.default_server_ip
    
    subdomain = request.get('subdomain')
    document_root = request.get('document_root')
    
    from services.cloudflare import cloudflare
    cloudflare_nameservers = await cloudflare.get_account_nameservers()
    
    # Zone-specific nameservers (will be updated after zone creation to use actual assigned NS)
    zone_specific_nameservers = None
    
    nameserver_update_result = None
    a_record_result = None
    dns_instructions = None
    domain_registration_result = None
    domain_price = None
    
    # NEW DOMAIN REGISTRATION FLOW
    if register_new:
        logger.info(f"🆕 Registering NEW addon domain: {addon_domain} for subscription {subscription_id}")
        
        from services.openprovider import OpenProviderService
        from decimal import Decimal
        from api.services.domain_coordinator import DomainRegistrationCoordinator
        from api.schemas.domain import RegisterDomainRequest
        
        openprovider = OpenProviderService()
        domain_coordinator = DomainRegistrationCoordinator()
        
        # Step 1: Get domain pricing (with 10% API discount)
        try:
            pricing_result = await openprovider.get_domain_price(addon_domain, period, is_api_purchase=True)
            if not pricing_result or pricing_result.get('create_price', 0) <= 0:
                raise BadRequestError(f"Could not get pricing for domain: {addon_domain}")
            
            domain_price = Decimal(str(pricing_result.get('create_price')))
            logger.info(f"💰 Domain price for {addon_domain}: ${domain_price:.2f}")
        except Exception as e:
            raise BadRequestError(f"Pricing error: {str(e)}")
        
        # Step 2: Check wallet balance
        current_balance = await get_user_wallet_balance_by_id(user_id)
        if current_balance < domain_price:
            raise BadRequestError(
                f"Insufficient wallet balance. Required: ${domain_price:.2f}, Available: ${current_balance:.2f}",
                {"required": float(domain_price), "available": float(current_balance)}
            )
        
        # Step 3: Reserve wallet balance
        hold_transaction_id = await reserve_wallet_balance(
            user_id,
            domain_price,
            f"Addon domain registration: {addon_domain}"
        )
        
        if not hold_transaction_id:
            raise InternalServerError("Failed to reserve wallet balance")
        
        # Step 4: Register the domain
        try:
            reg_request = RegisterDomainRequest(
                domain_name=addon_domain,
                period=period,
                auto_renew=auto_renew_domain,
                use_hostbay_contacts=True,
                privacy_protection=False
            )
            
            domain_registration_result = await domain_coordinator.register_domain(reg_request, user_id)
            registration_success = bool(domain_registration_result and domain_registration_result.get('success', False))
            
        except Exception as e:
            registration_success = False
            domain_registration_result = {'success': False, 'error': str(e)}
        
        # Step 5: Finalize wallet payment
        finalization_success = await finalize_wallet_reservation(
            hold_transaction_id,
            success=registration_success
        )
        
        if not registration_success:
            error_msg = domain_registration_result.get('error', 'Domain registration failed') if domain_registration_result else 'Unknown error'
            raise BadRequestError(f"Domain registration failed: {error_msg}. Wallet balance refunded.")
        
        if not finalization_success:
            raise InternalServerError("Financial settlement failed - please contact support")
        
        logger.info(f"✅ Domain {addon_domain} registered successfully for addon domain")
        
        # Step 6: Send notifications for new domain registration
        try:
            await send_info_alert(
                "AddonDomainAPI",
                f"✅ Addon domain registered via API: {addon_domain} for user {user_id} (subscription {subscription_id})",
                "addon_domain_registration",
                {
                    "addon_domain": addon_domain,
                    "subscription_id": subscription_id,
                    "user_id": user_id,
                    "payment_method": "API (wallet)",
                    "amount": float(domain_price)
                }
            )
            
            # Send user Telegram notification
            user_message = (
                f"✅ Domain Registered\n\n"
                f"🌐 Domain: {addon_domain}\n"
                f"💰 Amount: ${float(domain_price):.2f}\n"
                f"📅 Period: {period} {'year' if period == 1 else 'years'}\n"
                f"🖥️ Added to hosting subscription #{subscription_id}\n\n"
                f"💼 Ordered via API"
            )
            await queue_user_message(user_id, user_message)
            logger.info(f"📱 Sent addon domain registration notification to user {user_id}")
        except Exception as e:
            logger.warning(f"⚠️ Failed to send notifications for addon domain registration: {e}")
        
        # Step 7: Set up Cloudflare zone and A records for newly registered domain
        try:
            logger.info(f"🔄 Setting up Cloudflare zone and A records for new addon domain {addon_domain}")
            
            # Update nameservers to Cloudflare
            from services.openprovider import OpenProviderService
            openprovider_svc = OpenProviderService()
            nameserver_update_result = await openprovider_svc.update_nameservers(
                addon_domain,
                cloudflare_nameservers
            )
            if nameserver_update_result and nameserver_update_result.get('success'):
                logger.info(f"✅ Nameservers updated for new addon domain {addon_domain}")
            else:
                logger.warning(f"⚠️ Nameserver update failed for {addon_domain}: {nameserver_update_result}")
            
            # Create Cloudflare zone
            zone_info = await cloudflare.get_zone_by_name(addon_domain)
            zone_id = None
            
            if zone_info:
                zone_id = zone_info.get('id')
                # Extract zone-specific nameservers (dynamic per zone)
                zone_specific_nameservers = zone_info.get('name_servers', [])
                logger.info(f"✅ Cloudflare zone already exists for {addon_domain}: {zone_id}, NS: {zone_specific_nameservers}")
            else:
                zone_result = await cloudflare.create_zone(addon_domain, standalone=True)
                if zone_result and zone_result.get('success'):
                    zone_id = zone_result.get('zone_id')
                    # Extract zone-specific nameservers from creation result
                    zone_specific_nameservers = zone_result.get('result', {}).get('name_servers', []) or zone_result.get('nameservers', [])
                    logger.info(f"✅ Created Cloudflare zone for {addon_domain}: {zone_id}, NS: {zone_specific_nameservers}")
                else:
                    zone_info = await cloudflare.get_zone_by_name(addon_domain)
                    if zone_info:
                        zone_id = zone_info.get('id')
                        zone_specific_nameservers = zone_info.get('name_servers', [])
            
            # Create A records
            if zone_id:
                records_status: dict = {'root': 'pending', 'www': 'pending'}
                
                existing_records = await cloudflare.list_dns_records(zone_id, record_type="A")
                existing_by_name = {r.get('name', '').lower(): r for r in existing_records} if existing_records else {}
                
                # Root A record
                root_name = addon_domain.lower()
                if root_name in existing_by_name:
                    existing = existing_by_name[root_name]
                    if existing.get('content') == server_ip:
                        records_status['root'] = 'already_configured'
                    else:
                        existing_proxied = existing.get('proxied', False)
                        update_result = await cloudflare.update_dns_record(
                            zone_id, existing['id'], "A", addon_domain, server_ip, ttl=3600, proxied=existing_proxied
                        )
                        records_status['root'] = 'updated' if update_result.get('success') else 'update_failed'
                else:
                    root_result = await cloudflare.create_dns_record(
                        zone_id, "A", addon_domain, server_ip, ttl=3600, proxied=False
                    )
                    records_status['root'] = 'created' if root_result.get('success') else 'create_failed'
                
                # www A record
                www_name = f"www.{addon_domain}".lower()
                if www_name in existing_by_name:
                    existing = existing_by_name[www_name]
                    if existing.get('content') == server_ip:
                        records_status['www'] = 'already_configured'
                    else:
                        existing_proxied = existing.get('proxied', False)
                        update_result = await cloudflare.update_dns_record(
                            zone_id, existing['id'], "A", f"www.{addon_domain}", server_ip, ttl=3600, proxied=existing_proxied
                        )
                        records_status['www'] = 'updated' if update_result.get('success') else 'update_failed'
                else:
                    www_result = await cloudflare.create_dns_record(
                        zone_id, "A", f"www.{addon_domain}", server_ip, ttl=3600, proxied=False
                    )
                    records_status['www'] = 'created' if www_result.get('success') else 'create_failed'
                
                success_states = ['created', 'updated', 'already_configured']
                all_success = records_status['root'] in success_states and records_status['www'] in success_states
                
                if all_success:
                    logger.info(f"✅ A records configured for new addon domain {addon_domain}: {records_status}")
                    a_record_result = {'success': True, 'records': records_status, 'zone_id': zone_id}
                    # Sync DNS records to database for dashboard display
                    try:
                        all_records = await cloudflare.list_dns_records(zone_id)
                        if all_records:
                            await save_dns_records_to_db(addon_domain, all_records)
                            logger.info(f"✅ DNS records synced to database for addon domain {addon_domain}")
                    except Exception as sync_err:
                        logger.warning(f"⚠️ Failed to sync DNS records to database: {sync_err}")
                else:
                    a_record_result = {'success': False, 'records': records_status, 'error': 'Partial record configuration'}
            else:
                a_record_result = {'success': False, 'error': 'Zone creation failed'}
        except Exception as e:
            logger.error(f"❌ Error setting up DNS for new addon domain {addon_domain}: {e}")
            a_record_result = {'success': False, 'error': str(e)}
    
    # Check if domain is already in user's account (for existing domain flow)
    domain_in_account = await execute_query("""
        SELECT id, domain_name FROM domains 
        WHERE domain_name = %s AND user_id = %s
    """, (addon_domain, user_id))
    
    # EXISTING DOMAIN FLOW (only if not registering new)
    if not register_new and domain_in_account:
        from services.openprovider import OpenProviderService
        openprovider_existing = OpenProviderService()
        
        try:
            domain_details = await openprovider_existing.get_domain_details(addon_domain)
            current_nameservers = []
            if domain_details:
                ns_data = domain_details.get('name_servers', [])
                current_nameservers = [ns.get('name', '').lower() for ns in ns_data if ns.get('name')]
            
            cf_ns_lower = [ns.lower() for ns in cloudflare_nameservers]
            already_using_cloudflare = all(ns in cf_ns_lower for ns in current_nameservers) if current_nameservers else False
            
            if not already_using_cloudflare:
                logger.info(f"🔄 Auto-updating nameservers for addon domain {addon_domain} to Cloudflare")
                nameserver_update_result = await openprovider_existing.update_nameservers(
                    addon_domain, 
                    cloudflare_nameservers
                )
                if nameserver_update_result and nameserver_update_result.get('success'):
                    logger.info(f"✅ Nameservers updated for addon domain {addon_domain}")
                else:
                    logger.warning(f"⚠️ Nameserver update failed for {addon_domain}: {nameserver_update_result}")
            else:
                logger.info(f"✅ Addon domain {addon_domain} already using Cloudflare nameservers")
                nameserver_update_result = {'success': True, 'already_configured': True}
            
            # Ensure Cloudflare zone exists and create A records
            try:
                logger.info(f"🔄 Setting up Cloudflare zone and A records for addon domain {addon_domain}")
                
                # Check if zone already exists first
                zone_info = await cloudflare.get_zone_by_name(addon_domain)
                zone_id = None
                
                if zone_info:
                    zone_id = zone_info.get('id')
                    # Extract zone-specific nameservers (dynamic per zone)
                    zone_specific_nameservers = zone_info.get('name_servers', [])
                    logger.info(f"✅ Cloudflare zone already exists for {addon_domain}: {zone_id}, NS: {zone_specific_nameservers}")
                else:
                    # Create the zone (standalone=True for addon domains not in domains table with zone)
                    zone_result = await cloudflare.create_zone(addon_domain, standalone=True)
                    if zone_result and zone_result.get('success'):
                        zone_id = zone_result.get('zone_id')
                        # Extract zone-specific nameservers from creation result
                        zone_specific_nameservers = zone_result.get('result', {}).get('name_servers', []) or zone_result.get('nameservers', [])
                        logger.info(f"✅ Created Cloudflare zone for {addon_domain}: {zone_id}, NS: {zone_specific_nameservers}")
                    else:
                        # Fallback: try get_zone_by_name again in case zone was created by another process
                        zone_info = await cloudflare.get_zone_by_name(addon_domain)
                        if zone_info:
                            zone_id = zone_info.get('id')
                            zone_specific_nameservers = zone_info.get('name_servers', [])
                            logger.info(f"✅ Found existing Cloudflare zone for {addon_domain} on retry: {zone_id}, NS: {zone_specific_nameservers}")
                        else:
                            logger.warning(f"⚠️ Could not create/find Cloudflare zone for {addon_domain}")
                
                if zone_id:
                    # Create or update A records - handle duplicates gracefully
                    records_status: dict = {'root': 'pending', 'www': 'pending'}
                    
                    # Check existing A records first
                    existing_records = await cloudflare.list_dns_records(zone_id, record_type="A")
                    existing_by_name = {r.get('name', '').lower(): r for r in existing_records} if existing_records else {}
                    
                    # Root A record (@)
                    root_name = addon_domain.lower()
                    if root_name in existing_by_name:
                        existing = existing_by_name[root_name]
                        if existing.get('content') == server_ip:
                            logger.info(f"✅ Root A record for {addon_domain} already exists with correct IP")
                            records_status['root'] = 'already_configured'
                        else:
                            # Update existing record - preserve proxied setting
                            existing_proxied = existing.get('proxied', False)
                            update_result = await cloudflare.update_dns_record(
                                zone_id, existing['id'], "A", addon_domain, server_ip, ttl=3600, proxied=existing_proxied
                            )
                            records_status['root'] = 'updated' if update_result.get('success') else 'update_failed'
                    else:
                        root_result = await cloudflare.create_dns_record(
                            zone_id, "A", addon_domain, server_ip, ttl=3600, proxied=False
                        )
                        records_status['root'] = 'created' if root_result.get('success') else 'create_failed'
                    
                    # www A record
                    www_name = f"www.{addon_domain}".lower()
                    if www_name in existing_by_name:
                        existing = existing_by_name[www_name]
                        if existing.get('content') == server_ip:
                            logger.info(f"✅ www A record for {addon_domain} already exists with correct IP")
                            records_status['www'] = 'already_configured'
                        else:
                            # Update existing record - preserve proxied setting
                            existing_proxied = existing.get('proxied', False)
                            update_result = await cloudflare.update_dns_record(
                                zone_id, existing['id'], "A", f"www.{addon_domain}", server_ip, ttl=3600, proxied=existing_proxied
                            )
                            records_status['www'] = 'updated' if update_result.get('success') else 'update_failed'
                    else:
                        www_result = await cloudflare.create_dns_record(
                            zone_id, "A", f"www.{addon_domain}", server_ip, ttl=3600, proxied=False
                        )
                        records_status['www'] = 'created' if www_result.get('success') else 'create_failed'
                    
                    # Determine overall success
                    success_states = ['created', 'updated', 'already_configured']
                    all_success = records_status['root'] in success_states and records_status['www'] in success_states
                    
                    if all_success:
                        logger.info(f"✅ A records configured for addon domain {addon_domain}: {records_status}")
                        a_record_result = {'success': True, 'records': records_status, 'zone_id': zone_id}
                        # Sync DNS records to database for dashboard display
                        try:
                            all_records = await cloudflare.list_dns_records(zone_id)
                            if all_records:
                                await save_dns_records_to_db(addon_domain, all_records)
                                logger.info(f"✅ DNS records synced to database for addon domain {addon_domain}")
                        except Exception as sync_err:
                            logger.warning(f"⚠️ Failed to sync DNS records to database: {sync_err}")
                    else:
                        logger.warning(f"⚠️ Partial A record setup for {addon_domain}: {records_status}")
                        a_record_result = {'success': False, 'records': records_status, 'error': 'Partial record configuration'}
                else:
                    logger.warning(f"⚠️ Could not get/create Cloudflare zone for {addon_domain}")
                    a_record_result = {'success': False, 'error': 'Zone creation failed'}
            except Exception as e:
                logger.error(f"❌ Error creating A records for addon domain {addon_domain}: {e}")
                a_record_result = {'success': False, 'error': str(e)}
                
        except Exception as e:
            logger.error(f"❌ Error updating nameservers for addon domain {addon_domain}: {e}")
            nameserver_update_result = {'success': False, 'error': str(e)}
    elif not register_new:
        # External domain - create Cloudflare zone and A records, then provide nameserver instructions
        logger.info(f"📋 External addon domain {addon_domain} - setting up Cloudflare zone and A records")
        
        try:
            # Check if zone already exists first
            zone_info = await cloudflare.get_zone_by_name(addon_domain)
            zone_id = None
            
            if zone_info:
                zone_id = zone_info.get('id')
                # Extract zone-specific nameservers (dynamic per zone)
                zone_specific_nameservers = zone_info.get('name_servers', [])
                logger.info(f"✅ Cloudflare zone already exists for external domain {addon_domain}: {zone_id}, NS: {zone_specific_nameservers}")
            else:
                # Create the zone for external domain
                zone_result = await cloudflare.create_zone(addon_domain, standalone=True)
                if zone_result and zone_result.get('success'):
                    zone_id = zone_result.get('zone_id')
                    # Extract zone-specific nameservers from creation result
                    zone_specific_nameservers = zone_result.get('result', {}).get('name_servers', []) or zone_result.get('nameservers', [])
                    logger.info(f"✅ Created Cloudflare zone for external domain {addon_domain}: {zone_id}, NS: {zone_specific_nameservers}")
                else:
                    # Fallback: try get_zone_by_name again
                    zone_info = await cloudflare.get_zone_by_name(addon_domain)
                    if zone_info:
                        zone_id = zone_info.get('id')
                        zone_specific_nameservers = zone_info.get('name_servers', [])
                        logger.info(f"✅ Found existing Cloudflare zone for external domain {addon_domain}: {zone_id}, NS: {zone_specific_nameservers}")
                    else:
                        logger.warning(f"⚠️ Could not create/find Cloudflare zone for external domain {addon_domain}")
            
            if zone_id:
                # Create or update A records - same logic as HostBay domains
                records_status: dict = {'root': 'pending', 'www': 'pending'}
                
                existing_records = await cloudflare.list_dns_records(zone_id, record_type="A")
                existing_by_name = {r.get('name', '').lower(): r for r in existing_records} if existing_records else {}
                
                # Root A record (@)
                root_name = addon_domain.lower()
                if root_name in existing_by_name:
                    existing = existing_by_name[root_name]
                    if existing.get('content') == server_ip:
                        records_status['root'] = 'already_configured'
                    else:
                        existing_proxied = existing.get('proxied', False)
                        update_result = await cloudflare.update_dns_record(
                            zone_id, existing['id'], "A", addon_domain, server_ip, ttl=3600, proxied=existing_proxied
                        )
                        records_status['root'] = 'updated' if update_result.get('success') else 'update_failed'
                else:
                    root_result = await cloudflare.create_dns_record(
                        zone_id, "A", addon_domain, server_ip, ttl=3600, proxied=False
                    )
                    records_status['root'] = 'created' if root_result.get('success') else 'create_failed'
                
                # www A record
                www_name = f"www.{addon_domain}".lower()
                if www_name in existing_by_name:
                    existing = existing_by_name[www_name]
                    if existing.get('content') == server_ip:
                        records_status['www'] = 'already_configured'
                    else:
                        existing_proxied = existing.get('proxied', False)
                        update_result = await cloudflare.update_dns_record(
                            zone_id, existing['id'], "A", f"www.{addon_domain}", server_ip, ttl=3600, proxied=existing_proxied
                        )
                        records_status['www'] = 'updated' if update_result.get('success') else 'update_failed'
                else:
                    www_result = await cloudflare.create_dns_record(
                        zone_id, "A", f"www.{addon_domain}", server_ip, ttl=3600, proxied=False
                    )
                    records_status['www'] = 'created' if www_result.get('success') else 'create_failed'
                
                success_states = ['created', 'updated', 'already_configured']
                all_success = records_status['root'] in success_states and records_status['www'] in success_states
                
                if all_success:
                    logger.info(f"✅ A records configured for external addon domain {addon_domain}: {records_status}")
                    a_record_result = {'success': True, 'records': records_status, 'zone_id': zone_id}
                    # Sync DNS records to database for dashboard display
                    try:
                        all_records = await cloudflare.list_dns_records(zone_id)
                        if all_records:
                            await save_dns_records_to_db(addon_domain, all_records)
                            logger.info(f"✅ DNS records synced to database for external addon domain {addon_domain}")
                    except Exception as sync_err:
                        logger.warning(f"⚠️ Failed to sync DNS records to database: {sync_err}")
                else:
                    logger.warning(f"⚠️ Partial A record setup for external domain {addon_domain}: {records_status}")
                    a_record_result = {'success': False, 'records': records_status, 'error': 'Partial record configuration'}
            else:
                a_record_result = {'success': False, 'error': 'Zone creation failed'}
        except Exception as e:
            logger.error(f"❌ Error setting up Cloudflare for external addon domain {addon_domain}: {e}")
            a_record_result = {'success': False, 'error': str(e)}
        
        # Always provide nameserver instructions for external domains
        # Use zone-specific nameservers if available, otherwise fallback to account-level
        effective_nameservers = zone_specific_nameservers if zone_specific_nameservers else cloudflare_nameservers
        
        # Build instructions list without empty strings
        instructions_list = [
            f"1. Log in to your domain registrar where {addon_domain} is registered",
            f"2. Navigate to the DNS/Nameserver settings",
            f"3. Update the nameservers to:"
        ]
        if effective_nameservers:
            instructions_list.append(f"   - {effective_nameservers[0]}")
            if len(effective_nameservers) > 1:
                instructions_list.append(f"   - {effective_nameservers[1]}")
        instructions_list.extend([
            f"4. Save the changes and wait for DNS propagation (24-48 hours)",
            f"5. Once nameservers are updated, your addon domain will be fully configured"
        ])
        
        dns_instructions = {
            "message": "DNS records have been configured in Cloudflare. Please update nameservers at your registrar to activate.",
            "nameservers": list(effective_nameservers) if effective_nameservers else [],
            "instructions": instructions_list,
            "estimated_propagation": "24-48 hours"
        }
        logger.info(f"📋 External addon domain {addon_domain} - Cloudflare setup complete, returning NS instructions")
    
    # DNS-only mode: Skip cPanel add (for external domains that need DNS configured first)
    if dns_only:
        logger.info(f"📋 DNS-only mode for {addon_domain} - skipping cPanel add, returning DNS setup info")
        
        response_data = {
            "subscription_id": subscription_id,
            "primary_domain": primary_domain,
            "addon_domain": addon_domain,
            "dns_only": True,
            "cpanel_status": "pending"
        }
        
        # Include DNS info based on domain type - use zone-specific nameservers if available
        effective_ns = zone_specific_nameservers if zone_specific_nameservers else cloudflare_nameservers
        response_data["dns_nameservers"] = effective_ns
        response_data["cloudflare_nameservers"] = effective_ns  # Legacy
        response_data["server_ip"] = server_ip
        
        # Determine domain type for job queuing
        domain_type_for_job = "newly_registered" if register_new else ("existing" if domain_in_account else "external")
        zone_id_for_job = a_record_result.get('zone_id') if a_record_result else None
        
        # Set nameserver status based on actual update result
        if register_new:
            # Newly registered domain - nameservers were auto-updated
            response_data["nameserver_status"] = "auto_updated" if nameserver_update_result and nameserver_update_result.get('success') else "update_pending"
            response_data["domain_type"] = "newly_registered"
            response_data["message"] = "Domain registered and DNS configured. Nameservers auto-updated to Cloudflare. System will automatically add to cPanel."
        elif domain_in_account:
            # Existing domain in account - nameservers were auto-updated or already configured
            if nameserver_update_result and nameserver_update_result.get('already_configured'):
                response_data["nameserver_status"] = "already_configured"
            elif nameserver_update_result and nameserver_update_result.get('success'):
                response_data["nameserver_status"] = "auto_updated"
            else:
                response_data["nameserver_status"] = "update_failed"
            response_data["domain_type"] = "existing"
            response_data["message"] = "DNS configured for existing domain. Nameservers auto-updated. System will automatically add to cPanel."
        else:
            # External domain - manual nameserver update required
            response_data["nameserver_status"] = "manual_update_required"
            response_data["domain_type"] = "external"
            response_data["message"] = "DNS records configured. Update nameservers at your registrar. System will automatically retry adding to cPanel every 10 minutes."
            if dns_instructions:
                response_data["dns_instructions"] = dns_instructions
        
        # Include A record status
        if a_record_result:
            response_data["a_record_status"] = "configured" if a_record_result.get('success') else "failed"
            if a_record_result.get('records'):
                response_data["a_records"] = a_record_result['records']
            if a_record_result.get('zone_id'):
                response_data["zone_id"] = a_record_result['zone_id']
        
        # Queue the addon domain for automatic cPanel addition
        try:
            from services.addon_domain_job_service import addon_domain_job_service
            
            job_id = await addon_domain_job_service.enqueue_addon_domain(
                subscription_id=subscription_id,
                user_id=user_id,
                addon_domain=addon_domain,
                domain_type=domain_type_for_job,
                subdomain=subdomain,
                document_root=document_root,
                zone_id=zone_id_for_job
            )
            
            if job_id:
                response_data["job_id"] = job_id
                response_data["auto_retry"] = True
                response_data["retry_interval"] = "10 minutes"
                response_data["max_retries"] = 6
                logger.info(f"📋 Queued addon domain job #{job_id} for automatic cPanel addition")
        except Exception as job_error:
            logger.warning(f"⚠️ Could not queue addon domain job: {job_error}")
            response_data["auto_retry"] = False
        
        return success_response(response_data, response_data.get("message", "DNS configured. System will automatically add to cPanel."))
    
    addon_result = await cpanel.add_addon_domain(
        cpanel_username,
        addon_domain,
        subdomain=subdomain,
        document_root=document_root
    )
    
    if not addon_result:
        raise InternalServerError("Failed to add addon domain")
    
    if not addon_result.get('success'):
        raise BadRequestError(addon_result.get('error', 'Failed to add addon domain'))
    
    logger.info(f"✅ Addon domain {addon_domain} added to subscription {subscription_id} by user {user_id}")
    
    response_data = {
        "subscription_id": subscription_id,
        "primary_domain": primary_domain,
        "addon_domain": addon_result.get('addon_domain'),
        "subdomain": addon_result.get('subdomain'),
        "document_root": addon_result.get('document_root'),
        "created": True
    }
    
    # Handle response based on domain type (with backward compatibility for legacy field names)
    # Use zone-specific nameservers if available, otherwise fallback to account-level
    effective_ns = zone_specific_nameservers if zone_specific_nameservers else cloudflare_nameservers
    
    if register_new:
        # Newly registered domain - include registration details
        response_data["domain_type"] = "newly_registered"
        response_data["registration"] = {
            "registered": True,
            "period": period,
            "auto_renew": auto_renew_domain,
            "amount_charged": float(domain_price) if domain_price else 0
        }
        response_data["nameserver_status"] = "auto_updated" if nameserver_update_result and nameserver_update_result.get('success') else "update_pending"
        response_data["dns_nameservers"] = effective_ns
        response_data["cloudflare_nameservers"] = effective_ns  # Legacy
        response_data["server_ip"] = server_ip
        # A record status
        if a_record_result:
            response_data["a_record_status"] = "configured" if a_record_result.get('success') else "failed"
            if a_record_result.get('records'):
                response_data["a_records"] = a_record_result['records']
            if a_record_result.get('zone_id'):
                response_data["zone_id"] = a_record_result['zone_id']
                response_data["cloudflare_zone_id"] = a_record_result['zone_id']  # Legacy
            if a_record_result.get('error'):
                response_data["a_record_error"] = a_record_result['error']
        else:
            response_data["a_record_status"] = "not_attempted"
    elif domain_in_account:
        response_data["nameserver_status"] = "auto_updated" if nameserver_update_result and nameserver_update_result.get('success') and not nameserver_update_result.get('already_configured') else "already_configured" if nameserver_update_result and nameserver_update_result.get('already_configured') else "update_failed"
        response_data["dns_nameservers"] = effective_ns
        response_data["cloudflare_nameservers"] = effective_ns  # Legacy
        response_data["server_ip"] = server_ip
        # A record status with detailed breakdown
        if a_record_result:
            response_data["a_record_status"] = "configured" if a_record_result.get('success') else "failed"
            if a_record_result.get('records'):
                response_data["a_records"] = a_record_result['records']
            if a_record_result.get('zone_id'):
                response_data["zone_id"] = a_record_result['zone_id']
                response_data["cloudflare_zone_id"] = a_record_result['zone_id']  # Legacy
            if a_record_result.get('error'):
                response_data["a_record_error"] = a_record_result['error']
        else:
            response_data["a_record_status"] = "not_attempted"
    else:
        response_data["nameserver_status"] = "manual_update_required"
        response_data["dns_nameservers"] = effective_ns
        response_data["cloudflare_nameservers"] = effective_ns  # Legacy
        response_data["server_ip"] = server_ip
        response_data["dns_instructions"] = dns_instructions
        # A record status for external domains (zone created, awaiting NS update)
        if a_record_result:
            response_data["a_record_status"] = "configured" if a_record_result.get('success') else "failed"
            if a_record_result.get('records'):
                response_data["a_records"] = a_record_result['records']
            if a_record_result.get('zone_id'):
                response_data["zone_id"] = a_record_result['zone_id']
                response_data["cloudflare_zone_id"] = a_record_result['zone_id']  # Legacy
            if a_record_result.get('error'):
                response_data["a_record_error"] = a_record_result['error']
        else:
            response_data["a_record_status"] = "not_attempted"
    
    return success_response(response_data, f"Addon domain {addon_domain} added successfully")


@router.delete("/hosting/{subscription_id}/addon-domains/{addon_domain}", response_model=dict)
async def delete_addon_domain(
    subscription_id: int,
    addon_domain: str,
    key_data: dict = Depends(get_api_key_from_header)
):
    """
    Delete an addon domain from a hosting subscription.
    
    This will remove the addon domain from the cPanel account and/or pending jobs.
    The document root directory and its contents may be preserved.
    
    **Path Parameters:**
    - subscription_id: The hosting subscription ID
    - addon_domain: The addon domain to delete (e.g., 'example.com')
    """
    check_permission(key_data, "hosting", "write")
    user_id = key_data["user_id"]
    
    result = await execute_query("""
        SELECT cpanel_username, domain_name FROM hosting_subscriptions
        WHERE id = %s AND user_id = %s
    """, (subscription_id, user_id))
    
    if not result:
        raise ResourceNotFoundError("Hosting subscription", str(subscription_id))
    
    cpanel_username = result[0]['cpanel_username']
    primary_domain = result[0]['domain_name']
    
    if addon_domain.lower() == primary_domain.lower():
        raise BadRequestError("Cannot delete the primary domain. Use DELETE /hosting/{subscription_id} to delete the entire hosting subscription.")
    
    # Check if addon is in pending jobs table
    pending_job = await execute_query("""
        SELECT id, status FROM addon_domain_pending_jobs
        WHERE subscription_id = %s AND addon_domain = %s
    """, (subscription_id, addon_domain))
    
    cpanel_deleted = False
    pending_deleted = False
    
    # Try to delete from cPanel (will fail gracefully if not found)
    delete_result = await cpanel.delete_addon_domain(cpanel_username, addon_domain)
    
    if delete_result and delete_result.get('success'):
        cpanel_deleted = True
        logger.info(f"✅ Addon domain {addon_domain} deleted from cPanel for subscription {subscription_id}")
    
    # Mark pending job as cancelled (preserve audit trail)
    if pending_job:
        await execute_update("""
            UPDATE addon_domain_pending_jobs
            SET status = 'cancelled', updated_at = NOW()
            WHERE subscription_id = %s AND addon_domain = %s
        """, (subscription_id, addon_domain))
        pending_deleted = True
        logger.info(f"✅ Pending addon domain job for {addon_domain} marked as cancelled for subscription {subscription_id}")
    
    # If neither existed, return error
    if not cpanel_deleted and not pending_deleted:
        error_msg = delete_result.get('error', 'Domain not found') if delete_result else 'Failed to access cPanel'
        raise BadRequestError(f"Addon domain {addon_domain} not found: {error_msg}")
    
    logger.info(f"✅ Addon domain {addon_domain} deleted from subscription {subscription_id} by user {user_id}")
    
    return success_response({
        "subscription_id": subscription_id,
        "primary_domain": primary_domain,
        "deleted_domain": addon_domain,
        "deleted": True,
        "cpanel_deleted": cpanel_deleted,
        "pending_job_cancelled": pending_deleted
    }, f"Addon domain {addon_domain} deleted successfully")
