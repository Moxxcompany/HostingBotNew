"""
Enhanced Production Logging with Anomaly Detection
Provides structured logging, metrics collection, and real-time anomaly detection
"""

import logging
import time
import json
import os
import asyncio
import statistics
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from enum import Enum
import threading

# Register custom AUDIT log level (between INFO and WARNING)
AUDIT_LEVEL = 25
logging.addLevelName(AUDIT_LEVEL, 'AUDIT')
logging.AUDIT = AUDIT_LEVEL  # type: ignore

# Structured logging setup
class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"

@dataclass
class LogEntry:
    """Structured log entry"""
    timestamp: str
    level: LogLevel
    component: str
    message: str
    context: Dict[str, Any]
    trace_id: Optional[str] = None
    user_id: Optional[int] = None
    order_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class Metric:
    """Production metric with metadata"""
    name: str
    value: float
    metric_type: MetricType
    timestamp: float
    tags: Dict[str, str]
    component: str

class AnomalyDetector:
    """Real-time anomaly detection for production metrics"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.metric_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.baselines: Dict[str, Dict] = {}  # Statistical baselines
        self.anomaly_thresholds = {
            'error_rate': 0.05,  # 5% error rate threshold
            'response_time': 2.0,  # 2 second response time threshold
            'payment_failure_rate': 0.02,  # 2% payment failure threshold
            'webhook_failure_rate': 0.01,  # 1% webhook failure threshold
        }
    
    def add_metric(self, metric: Metric) -> Optional[Dict]:
        """Add metric and check for anomalies"""
        metric_key = f"{metric.component}.{metric.name}"
        self.metric_windows[metric_key].append(metric.value)
        
        # Calculate baseline if we have enough data
        if len(self.metric_windows[metric_key]) >= 20:
            window_data = list(self.metric_windows[metric_key])
            self.baselines[metric_key] = {
                'mean': statistics.mean(window_data),
                'std': statistics.stdev(window_data) if len(window_data) > 1 else 0,
                'median': statistics.median(window_data),
                'p95': self._percentile(window_data, 95),
                'last_updated': time.time()
            }
            
            # Check for anomalies
            return self._detect_anomaly(metric, metric_key)
        
        return None
    
    def _detect_anomaly(self, metric: Metric, metric_key: str) -> Optional[Dict]:
        """Detect if metric represents an anomaly"""
        baseline = self.baselines.get(metric_key)
        if not baseline:
            return None
        
        # Z-score based anomaly detection
        if baseline['std'] > 0:
            z_score = abs(metric.value - baseline['mean']) / baseline['std']
            if z_score > 3:  # 3 sigma rule
                return {
                    'type': 'statistical_anomaly',
                    'metric': metric_key,
                    'value': metric.value,
                    'expected_mean': baseline['mean'],
                    'z_score': z_score,
                    'severity': 'high' if z_score > 4 else 'medium'
                }
        
        # Threshold based detection
        for threshold_name, threshold_value in self.anomaly_thresholds.items():
            if threshold_name in metric_key.lower():
                if metric.value > threshold_value:
                    return {
                        'type': 'threshold_violation',
                        'metric': metric_key,
                        'value': metric.value,
                        'threshold': threshold_value,
                        'severity': 'high'
                    }
        
        return None
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of data"""
        sorted_data = sorted(data)
        index = (percentile / 100) * (len(sorted_data) - 1)
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))

class ProductionLogger:
    """Enhanced production logger with structured logging and metrics"""
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.metrics_buffer: List[Metric] = []
        self.metrics_lock = threading.Lock()
        self.log_handlers: List[Callable] = []
        self.metric_handlers: List[Callable] = []
        
        # Setup structured logging
        self._setup_structured_logging()
        
        # Defer async initialization until needed
        self._background_tasks_started = False
    
    def _setup_structured_logging(self):
        """Setup structured logging for production - OPTIMIZED: no-op to prevent duplicate handlers.
        JSON logging is now configured once in fastapi_server.py startup."""
        # OPTIMIZED: Removed duplicate handler addition. The root logger's JSON formatter
        # is set up in fastapi_server.py. Adding another handler here was causing every
        # log line to be emitted twice (doubling Railway log volume).
        pass
    
    def _start_background_tasks(self):
        """Start background tasks for metrics processing"""
        async def metrics_processor():
            while True:
                try:
                    await self._process_metrics_batch()
                    await asyncio.sleep(10)  # Process every 10 seconds
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logging.error(f"❌ Metrics processor error: {e}")
        
        asyncio.create_task(metrics_processor())
    
    async def _process_metrics_batch(self):
        """Process accumulated metrics"""
        with self.metrics_lock:
            if not self.metrics_buffer:
                return
            
            batch = self.metrics_buffer.copy()
            self.metrics_buffer.clear()
        
        # Process each metric
        anomalies = []
        for metric in batch:
            anomaly = self.anomaly_detector.add_metric(metric)
            if anomaly:
                anomalies.append(anomaly)
        
        # Handle anomalies
        for anomaly in anomalies:
            await self._handle_anomaly(anomaly)
        
        # Send metrics to external systems
        await self._send_metrics_to_external_systems(batch)
    
    async def _handle_anomaly(self, anomaly: Dict):
        """Handle detected anomaly"""
        from decimal import Decimal
        
        # Reuse DecimalEncoder for consistency
        class DecimalEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, Decimal):
                    return float(obj)
                return super().default(obj)
        
        severity = anomaly.get('severity', 'medium')
        
        if severity == 'high':
            logging.critical(f"🚨 ANOMALY DETECTED: {json.dumps(anomaly, cls=DecimalEncoder)}")
            # Send critical alert
            try:
                from admin_alerts import send_critical_alert, AlertCategory
                await send_critical_alert(
                    component="Production Monitoring",
                    message=f"Anomaly detected in {anomaly['metric']}: {anomaly['type']}",
                    category="system_health",
                    details=anomaly
                )
            except Exception as e:
                logging.error(f"❌ Failed to send anomaly alert: {e}")
        else:
            logging.warning(f"⚠️ ANOMALY DETECTED: {json.dumps(anomaly, cls=DecimalEncoder)}")
    
    async def _send_metrics_to_external_systems(self, metrics: List[Metric]):
        """Send metrics to external monitoring systems"""
        from decimal import Decimal
        
        # Reuse DecimalEncoder for consistency
        class DecimalEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, Decimal):
                    return float(obj)
                return super().default(obj)
        
        try:
            # In production, send to Prometheus, DataDog, etc.
            # For now, use structured logging
            for metric in metrics:
                metric_data = {
                    'type': 'metric',
                    'timestamp': metric.timestamp,
                    'component': metric.component,
                    'name': metric.name,
                    'value': metric.value,
                    'metric_type': metric.metric_type.value,
                    'tags': metric.tags
                }
                logging.info(f"📊 METRIC: {json.dumps(metric_data, cls=DecimalEncoder)}")
        except Exception as e:
            logging.error(f"❌ Failed to send metrics to external systems: {e}")
    
    def log_structured(
        self,
        level: LogLevel,
        component: str,
        message: str,
        context: Optional[Dict] = None,
        trace_id: Optional[str] = None,
        user_id: Optional[int] = None,
        order_id: Optional[str] = None
    ):
        """Log structured message"""
        log_entry = LogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level,
            component=component,
            message=message,
            context=context or {},
            trace_id=trace_id,
            user_id=user_id,
            order_id=order_id
        )
        
        # Log using standard logging
        logger = logging.getLogger(component)
        log_level = getattr(logging, level.value)
        
        # Add extra fields to record
        extra = {
            'component': component,
            'trace_id': trace_id,
            'user_id': user_id,
            'order_id': order_id,
            'context': context or {}
        }
        
        logger.log(log_level, message, extra=extra)
        
        # Call custom handlers
        for handler in self.log_handlers:
            try:
                handler(log_entry)
            except Exception as e:
                logging.error(f"❌ Log handler error: {e}")
    
    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType,
        component: str,
        tags: Optional[Dict[str, str]] = None
    ):
        """Record production metric"""
        metric = Metric(
            name=name,
            value=value,
            metric_type=metric_type,
            timestamp=time.time(),
            tags=tags or {},
            component=component
        )
        
        with self.metrics_lock:
            self.metrics_buffer.append(metric)
        
        # Call custom handlers
        for handler in self.metric_handlers:
            try:
                handler(metric)
            except Exception as e:
                logging.error(f"❌ Metric handler error: {e}")
    
    def add_log_handler(self, handler: Callable[[LogEntry], None]):
        """Add custom log handler"""
        self.log_handlers.append(handler)
    
    def add_metric_handler(self, handler: Callable[[Metric], None]):
        """Add custom metric handler"""
        self.metric_handlers.append(handler)
    
    def get_anomaly_stats(self) -> Dict:
        """Get anomaly detection statistics"""
        return {
            'metrics_tracked': len(self.anomaly_detector.metric_windows),
            'baselines_calculated': len(self.anomaly_detector.baselines),
            'thresholds': self.anomaly_detector.anomaly_thresholds,
            'window_size': self.anomaly_detector.window_size
        }

# Global production logger instance
_production_logger: Optional[ProductionLogger] = None

def get_production_logger() -> ProductionLogger:
    """Get global production logger instance"""
    global _production_logger
    if _production_logger is None:
        _production_logger = ProductionLogger()
    return _production_logger

# Convenience functions for common logging patterns
def log_business_event(component: str, event: str, details: Dict, user_id: Optional[int] = None, order_id: Optional[str] = None):
    """Log business event with structured context"""
    logger = get_production_logger()
    logger.log_structured(
        LogLevel.INFO,
        component,
        f"Business event: {event}",
        context=details,
        user_id=user_id,
        order_id=order_id
    )

def log_performance_metric(component: str, operation: str, duration_ms: float, success: bool = True):
    """Log performance metric"""
    logger = get_production_logger()
    logger.record_metric(
        f"{operation}_duration_ms",
        duration_ms,
        MetricType.HISTOGRAM,
        component,
        {'operation': operation, 'success': str(success)}
    )
    
    # Also log success/failure rate
    logger.record_metric(
        f"{operation}_success_rate",
        1.0 if success else 0.0,
        MetricType.GAUGE,
        component,
        {'operation': operation}
    )

def log_error_with_context(component: str, error: Exception, context: Dict, user_id: Optional[int] = None, order_id: Optional[str] = None):
    """Log error with full context"""
    logger = get_production_logger()
    error_context = {
        'error_type': type(error).__name__,
        'error_message': str(error),
        **context
    }
    
    logger.log_structured(
        LogLevel.ERROR,
        component,
        f"Error occurred: {error}",
        context=error_context,
        user_id=user_id,
        order_id=order_id
    )
    
    # Record error metric
    logger.record_metric(
        'error_count',
        1.0,
        MetricType.COUNTER,
        component,
        {'error_type': type(error).__name__}
    )