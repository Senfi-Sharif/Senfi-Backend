from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger('security')

def custom_exception_handler(exc, context):
    """
    Custom exception handler for better error management
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    if response is not None:
        # Log the error for security monitoring
        request = context.get('request')
        user_email = getattr(request.user, 'email', 'anonymous') if request and hasattr(request, 'user') else 'anonymous'
        ip_address = request.META.get('REMOTE_ADDR', 'unknown') if request else 'unknown'
        
        logger.warning(f'API Error: {exc.__class__.__name__} - User: {user_email} - IP: {ip_address} - Path: {request.path if request else "unknown"}')
        
        # Sanitize error messages in production
        if hasattr(context.get('request'), 'META') and context['request'].META.get('SERVER_NAME') != 'localhost':
            # Production environment - hide detailed errors
            if response.status_code >= 500:
                response.data = {
                    'success': False,
                    'detail': 'خطای داخلی سرور. لطفاً بعداً تلاش کنید.'
                }
            elif response.status_code == 404:
                response.data = {
                    'success': False,
                    'detail': 'منبع مورد نظر یافت نشد.'
                }
            elif response.status_code == 403:
                response.data = {
                    'success': False,
                    'detail': 'دسترسی غیرمجاز.'
                }
    
    return response 