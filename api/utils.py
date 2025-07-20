import logging
from django.utils import timezone

logger = logging.getLogger('security')

def log_security_event(event_type, user_email, ip_address, details=None, success=True):
    """
    Log security events for monitoring
    """
    status = "SUCCESS" if success else "FAILED"
    timestamp = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_message = f"[{timestamp}] {status} - {event_type} - User: {user_email} - IP: {ip_address}"
    if details:
        log_message += f" - Details: {details}"
    
    if success:
        logger.info(log_message)
    else:
        logger.warning(log_message)

def log_data_access(model_name, record_id, user_email, ip_address, action="view"):
    """
    Log data access for audit trail
    """
    timestamp = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] DATA_ACCESS - {action.upper()} - Model: {model_name} - ID: {record_id} - User: {user_email} - IP: {ip_address}"
    logger.info(log_message)

def log_admin_action(action, user_email, ip_address, target=None, details=None):
    """
    Log admin actions for audit trail
    """
    timestamp = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] ADMIN_ACTION - {action.upper()} - User: {user_email} - IP: {ip_address}"
    if target:
        log_message += f" - Target: {target}"
    if details:
        log_message += f" - Details: {details}"
    logger.info(log_message) 