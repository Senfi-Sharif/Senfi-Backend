import logging
import time
from django.utils.deprecation import MiddlewareMixin
from .performance import performance_monitor

logger = logging.getLogger('security')

class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log all API requests for security monitoring
    """
    
    def process_request(self, request):
        # Store start time for calculating response time
        request.start_time = time.time()
        
        # Log request details
        user_email = getattr(request.user, 'email', 'anonymous') if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous'
        ip_address = request.META.get('REMOTE_ADDR', 'unknown')
        user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
        
        # Only log API requests
        if request.path.startswith('/api/'):
            logger.info(f'API Request: {request.method} {request.path} - User: {user_email} - IP: {ip_address} - UA: {user_agent[:100]}')
    
    def process_response(self, request, response):
        # Calculate response time
        if hasattr(request, 'start_time'):
            response_time = time.time() - request.start_time
            
            # Log response details for API requests
            if request.path.startswith('/api/'):
                user_email = getattr(request.user, 'email', 'anonymous') if hasattr(request, 'user') and request.user.is_authenticated else 'anonymous'
                ip_address = request.META.get('REMOTE_ADDR', 'unknown')
                
                # Record performance metrics
                performance_monitor.record_request(
                    endpoint=request.path,
                    method=request.method,
                    response_time=response_time,
                    status_code=response.status_code,
                    user_email=user_email
                )
                
                # Log slow requests (>2 seconds)
                if response_time > 2.0:
                    logger.warning(f'Slow API Response: {request.method} {request.path} - {response_time:.2f}s - User: {user_email} - IP: {ip_address}')
                
                # Log error responses
                if response.status_code >= 400:
                    logger.warning(f'API Error Response: {request.method} {request.path} - {response.status_code} - User: {user_email} - IP: {ip_address}')
        
        return response 