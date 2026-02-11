"""
Job Queue Event Signals

Lightweight event-driven signaling for job processors.
Instead of polling the database every N seconds, webhook handlers signal
an asyncio.Event when new work is enqueued. The processor wakes immediately
on signal, or after a long fallback timeout as a safety net.

This eliminates ~2,880 idle DB polls/day from the two job processors.
"""

import asyncio
import logging

logger = logging.getLogger(__name__)

# Global events — one per job type
_domain_registration_event: asyncio.Event | None = None
_hosting_order_event: asyncio.Event | None = None

# Fallback poll interval (safety net in case signal is missed)
FALLBACK_POLL_SECONDS = 300  # 5 minutes


def _get_or_create_event(attr_name: str) -> asyncio.Event:
    """Get or lazily create an asyncio.Event (must be called from async context)."""
    global _domain_registration_event, _hosting_order_event
    if attr_name == 'domain':
        if _domain_registration_event is None:
            _domain_registration_event = asyncio.Event()
        return _domain_registration_event
    else:
        if _hosting_order_event is None:
            _hosting_order_event = asyncio.Event()
        return _hosting_order_event


def signal_domain_registration_job():
    """Signal that a new domain registration job has been enqueued.
    Call this from webhook_handler after enqueue_registration()."""
    global _domain_registration_event
    if _domain_registration_event is not None:
        _domain_registration_event.set()
        logger.debug("Domain registration job signal sent")


def signal_hosting_order_job():
    """Signal that a new hosting order job has been enqueued.
    Call this from webhook_handler after enqueue_hosting()."""
    global _hosting_order_event
    if _hosting_order_event is not None:
        _hosting_order_event.set()
        logger.debug("Hosting order job signal sent")


async def run_event_driven_domain_processor():
    """
    Event-driven domain registration job processor.
    Wakes immediately on signal, or every FALLBACK_POLL_SECONDS as safety net.
    Replaces the APScheduler 30s polling job.
    """
    from services.domain_registration_job_service import get_domain_registration_job_service
    
    event = _get_or_create_event('domain')
    service = get_domain_registration_job_service()
    
    logger.info(f"Event-driven domain registration processor started (fallback: {FALLBACK_POLL_SECONDS}s)")
    
    while True:
        try:
            # Wait for signal OR fallback timeout
            try:
                await asyncio.wait_for(event.wait(), timeout=FALLBACK_POLL_SECONDS)
                logger.debug("Domain processor woke on signal")
            except asyncio.TimeoutError:
                logger.debug("Domain processor woke on fallback timeout")
            
            # Clear the event for next signal
            event.clear()
            
            # Process all pending jobs
            processed = await service.process_pending_jobs()
            if processed > 0:
                logger.info(f"Domain registration processor: completed {processed} jobs (event-driven)")
                
        except asyncio.CancelledError:
            logger.info("Domain registration processor shutting down")
            break
        except Exception as e:
            logger.error(f"Domain registration processor error: {e}")
            await asyncio.sleep(10)  # Brief cooldown on error


async def run_event_driven_hosting_processor():
    """
    Event-driven hosting order job processor.
    Wakes immediately on signal, or every FALLBACK_POLL_SECONDS as safety net.
    Replaces the APScheduler 30s polling job.
    """
    from services.domain_registration_job_service import get_hosting_order_job_service
    
    event = _get_or_create_event('hosting')
    service = get_hosting_order_job_service()
    
    logger.info(f"Event-driven hosting order processor started (fallback: {FALLBACK_POLL_SECONDS}s)")
    
    while True:
        try:
            # Wait for signal OR fallback timeout
            try:
                await asyncio.wait_for(event.wait(), timeout=FALLBACK_POLL_SECONDS)
                logger.debug("Hosting processor woke on signal")
            except asyncio.TimeoutError:
                logger.debug("Hosting processor woke on fallback timeout")
            
            # Clear the event for next signal
            event.clear()
            
            # Process all pending jobs
            processed = await service.process_pending_jobs()
            if processed > 0:
                logger.info(f"Hosting order processor: completed {processed} jobs (event-driven)")
                
        except asyncio.CancelledError:
            logger.info("Hosting order processor shutting down")
            break
        except Exception as e:
            logger.error(f"Hosting order processor error: {e}")
            await asyncio.sleep(10)  # Brief cooldown on error
