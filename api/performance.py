"""
Performance Monitoring and Metrics
Tracks API performance, response times, and system metrics
"""

import time
import psutil
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path

logger = logging.getLogger('performance')

class PerformanceMonitor:
    def __init__(self):
        self.metrics = {
            'request_times': deque(maxlen=1000),
            'endpoint_stats': defaultdict(lambda: {
                'count': 0,
                'total_time': 0,
                'avg_time': 0,
                'min_time': float('inf'),
                'max_time': 0,
                'errors': 0
            }),
            'system_metrics': deque(maxlen=100),
            'slow_requests': deque(maxlen=100)
        }
        self.lock = threading.Lock()
        self.metrics_file = Path('performance_metrics.json')
        self._load_metrics()
    
    def record_request(self, endpoint, method, response_time, status_code, user_email=None):
        """Record API request metrics"""
        with self.lock:
            # Record request time
            timestamp = datetime.now()
            self.metrics['request_times'].append({
                'timestamp': timestamp.isoformat(),
                'endpoint': endpoint,
                'method': method,
                'response_time': response_time,
                'status_code': status_code,
                'user_email': user_email
            })
            
            # Update endpoint statistics
            endpoint_key = f"{method} {endpoint}"
            stats = self.metrics['endpoint_stats'][endpoint_key]
            stats['count'] += 1
            stats['total_time'] += response_time
            stats['avg_time'] = stats['total_time'] / stats['count']
            stats['min_time'] = min(stats['min_time'], response_time)
            stats['max_time'] = max(stats['max_time'], response_time)
            
            if status_code >= 400:
                stats['errors'] += 1
            
            # Record slow requests (>2 seconds)
            if response_time > 2.0:
                self.metrics['slow_requests'].append({
                    'timestamp': timestamp.isoformat(),
                    'endpoint': endpoint,
                    'method': method,
                    'response_time': response_time,
                    'user_email': user_email
                })
                
                logger.warning(f'Slow request: {method} {endpoint} - {response_time:.2f}s - User: {user_email}')
    
    def record_system_metrics(self):
        """Record system performance metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available': memory.available,
                'disk_percent': disk.percent,
                'disk_free': disk.free
            }
            
            with self.lock:
                self.metrics['system_metrics'].append(metrics)
                
                # Log high resource usage
                if cpu_percent > 80:
                    logger.warning(f'High CPU usage: {cpu_percent}%')
                if memory.percent > 80:
                    logger.warning(f'High memory usage: {memory.percent}%')
                if disk.percent > 90:
                    logger.warning(f'High disk usage: {disk.percent}%')
                    
        except Exception as e:
            logger.error(f'Failed to record system metrics: {str(e)}')
    
    def get_performance_summary(self):
        """Get performance summary"""
        with self.lock:
            # Calculate overall statistics
            request_times = [r['response_time'] for r in self.metrics['request_times']]
            
            if not request_times:
                return {
                    'total_requests': 0,
                    'avg_response_time': 0,
                    'slow_requests': 0,
                    'error_rate': 0,
                    'top_endpoints': [],
                    'system_health': 'unknown'
                }
            
            total_requests = len(request_times)
            avg_response_time = sum(request_times) / len(request_times)
            slow_requests = len([r for r in request_times if r > 2.0])
            
            # Calculate error rate
            error_requests = len([r for r in self.metrics['request_times'] if r['status_code'] >= 400])
            error_rate = (error_requests / total_requests) * 100 if total_requests > 0 else 0
            
            # Get top endpoints by request count
            endpoint_stats = sorted(
                self.metrics['endpoint_stats'].items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )[:5]
            
            top_endpoints = [
                {
                    'endpoint': endpoint,
                    'count': stats['count'],
                    'avg_time': stats['avg_time'],
                    'error_rate': (stats['errors'] / stats['count']) * 100 if stats['count'] > 0 else 0
                }
                for endpoint, stats in endpoint_stats
            ]
            
            # System health assessment
            system_health = self._assess_system_health()
            
            return {
                'total_requests': total_requests,
                'avg_response_time': avg_response_time,
                'slow_requests': slow_requests,
                'error_rate': error_rate,
                'top_endpoints': top_endpoints,
                'system_health': system_health
            }
    
    def get_endpoint_performance(self, endpoint=None):
        """Get detailed endpoint performance"""
        with self.lock:
            if endpoint:
                stats = self.metrics['endpoint_stats'].get(endpoint, {})
                return {
                    'endpoint': endpoint,
                    'count': stats.get('count', 0),
                    'avg_time': stats.get('avg_time', 0),
                    'min_time': stats.get('min_time', 0),
                    'max_time': stats.get('max_time', 0),
                    'error_rate': (stats.get('errors', 0) / stats.get('count', 1)) * 100
                }
            else:
                return dict(self.metrics['endpoint_stats'])
    
    def get_slow_requests(self, limit=10):
        """Get recent slow requests"""
        with self.lock:
            return list(self.metrics['slow_requests'])[-limit:]
    
    def get_system_metrics(self, hours=24):
        """Get system metrics for the last N hours"""
        with self.lock:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            recent_metrics = [
                m for m in self.metrics['system_metrics']
                if datetime.fromisoformat(m['timestamp']) > cutoff_time
            ]
            return recent_metrics
    
    def _assess_system_health(self):
        """Assess overall system health"""
        if not self.metrics['system_metrics']:
            return 'unknown'
        
        latest_metrics = self.metrics['system_metrics'][-1]
        
        # Check for critical issues
        if (latest_metrics['cpu_percent'] > 90 or 
            latest_metrics['memory_percent'] > 90 or 
            latest_metrics['disk_percent'] > 95):
            return 'critical'
        
        # Check for warnings
        if (latest_metrics['cpu_percent'] > 70 or 
            latest_metrics['memory_percent'] > 70 or 
            latest_metrics['disk_percent'] > 80):
            return 'warning'
        
        return 'healthy'
    
    def _load_metrics(self):
        """Load metrics from file"""
        try:
            if self.metrics_file.exists():
                with open(self.metrics_file, 'r') as f:
                    data = json.load(f)
                    
                # Convert back to defaultdict and deque
                self.metrics['endpoint_stats'] = defaultdict(lambda: {
                    'count': 0,
                    'total_time': 0,
                    'avg_time': 0,
                    'min_time': float('inf'),
                    'max_time': 0,
                    'errors': 0
                })
                
                for endpoint, stats in data.get('endpoint_stats', {}).items():
                    self.metrics['endpoint_stats'][endpoint] = stats
                    
                # Load other metrics
                self.metrics['request_times'] = deque(data.get('request_times', []), maxlen=1000)
                self.metrics['system_metrics'] = deque(data.get('system_metrics', []), maxlen=100)
                self.metrics['slow_requests'] = deque(data.get('slow_requests', []), maxlen=100)
                
        except Exception as e:
            logger.error(f'Failed to load metrics: {str(e)}')
    
    def save_metrics(self):
        """Save metrics to file"""
        try:
            with self.lock:
                # Convert defaultdict to regular dict for JSON serialization
                endpoint_stats = dict(self.metrics['endpoint_stats'])
                
                data = {
                    'endpoint_stats': endpoint_stats,
                    'request_times': list(self.metrics['request_times']),
                    'system_metrics': list(self.metrics['system_metrics']),
                    'slow_requests': list(self.metrics['slow_requests']),
                    'last_updated': datetime.now().isoformat()
                }
                
                with open(self.metrics_file, 'w') as f:
                    json.dump(data, f, indent=2)
                    
        except Exception as e:
            logger.error(f'Failed to save metrics: {str(e)}')

# Global performance monitor instance
performance_monitor = PerformanceMonitor() 