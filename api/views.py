from django.shortcuts import render
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
import random
from .models import Campaign, CampaignSignature, User, BlogPost
from .serializers import CampaignSerializer, CampaignSignatureSerializer, BlogPostSerializer, BlogPostListSerializer
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework import status as drf_status
from django.utils import timezone
from .models import CampaignSignature, User, BlogPost
from .serializers import CampaignSignatureSerializer, BlogPostSerializer, BlogPostListSerializer
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.utils.decorators import method_decorator
from .utils import log_security_event, log_data_access, log_admin_action
from .performance import performance_monitor
from rest_framework.exceptions import ValidationError
import logging
import sys
from django.db import models
from datetime import timedelta
from .choices import CAMPAIGN_CATEGORY_CHOICES
from .models import Poll, PollOption, PollVote, PollParticipation
from .serializers import PollSerializer, PollOptionSerializer, PollVoteSerializer

# Security logger
security_logger = logging.getLogger('security')

User = get_user_model()

# In-memory store for verification codes (like FastAPI version)
verification_codes = {}
# In-memory store for mobile verification codes
mobile_verification_codes = {}

def is_sharif_email(email):
    return email.lower().endswith("@sharif.edu")

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def check_email(request):
    email = request.data.get('email', '').lower().strip()
    if not is_sharif_email(email):
        return Response({"exists": False})
    exists = User.objects.filter(email=email).exists()
    return Response({"exists": exists})

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@ratelimit(key='ip', rate='5/h', method='POST')
def send_verification_code(request):
    email = request.data.get('email', '').lower().strip()
    
    # Input validation
    if not email:
        return Response({"success": False, "detail": "Email is required"}, status=400)
    
    if len(email) > 254:
        return Response({"success": False, "detail": "Email is too long"}, status=400)
    
    if not is_sharif_email(email):
        return Response({"success": False, "detail": "Email must end with @sharif.edu"}, status=400)
    code = ''.join(random.choices('0123456789', k=6))
    verification_codes[email] = code
    try:
        send_mail(
            'Sharif Verification Code',
            f'Your verification code is: {code}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False
        )
        return Response({"success": True})
    except Ratelimited:
        return Response({"success": False, "detail": "تعداد درخواست‌های کد تایید بیش از حد مجاز است. لطفاً یک ساعت دیگر تلاش کنید."}, status=429)
    except Exception as e:
        return Response({"success": False, "detail": f"Failed to send verification code: {str(e)}"}, status=500)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def test_email_config(request):
    """Test email configuration - for debugging only"""
    try:
        # Test SMTP connection
        import smtplib
        from email.mime.text import MIMEText
        
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, timeout=10)
        if settings.EMAIL_USE_TLS:
            server.starttls()
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        server.quit()
        
        return Response({"success": True, "message": "Email configuration is working"})
    except Exception as e:
        return Response({"success": False, "error": str(e)}, status=500)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_code(request):
    email = request.data.get('email', '').lower().strip()
    code = request.data.get('code', '').strip()
    
    # Input validation
    if not email:
        return Response({"valid": False, "detail": "Email is required"}, status=400)
    
    if not code:
        return Response({"valid": False, "detail": "Verification code is required"}, status=400)
    
    if len(code) != 6 or not code.isdigit():
        return Response({"valid": False, "detail": "Invalid verification code format"}, status=400)
    
    if not is_sharif_email(email):
        return Response({"valid": False, "detail": "Email must end with @sharif.edu"}, status=400)
    
    valid = verification_codes.get(email) == code
    return Response({"valid": valid})

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@ratelimit(key='ip', rate='5/h', method='POST')
def send_mobile_verification_code(request):
    """Send verification code to mobile phone for existing users"""
    email = request.data.get('email', '').lower().strip()
    
    # Input validation
    if not email:
        return Response({"success": False, "detail": "Email is required"}, status=400)
    
    if len(email) > 254:
        return Response({"success": False, "detail": "Email is too long"}, status=400)
    
    if not is_sharif_email(email):
        return Response({"success": False, "detail": "Email must end with @sharif.edu"}, status=400)
    
    # Check if user exists
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"success": False, "detail": "User not found"}, status=404)
    
    # Generate verification code
    code = ''.join(random.choices('0123456789', k=6))
    mobile_verification_codes[email] = code
    
    # For now, we'll send the code via email as a fallback
    # In production, this should be replaced with SMS service
    try:
        send_mail(
            'Sharif Mobile Verification Code',
            f'Your mobile verification code is: {code}\n\nThis code will expire in 10 minutes.',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False
        )
        
        # Log security event
        log_security_event("MOBILE_VERIFICATION_SENT", email, request.META.get("REMOTE_ADDR", "unknown"), success=True)
        
        return Response({"success": True, "message": "Verification code sent to your email"})
    except Exception as e:
        return Response({"success": False, "detail": f"Failed to send verification code: {str(e)}"}, status=500)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_mobile_code(request):
    """Verify mobile code and log in user"""
    email = request.data.get('email', '').lower().strip()
    code = request.data.get('code', '').strip()
    
    # Input validation
    if not email:
        return Response({"success": False, "detail": "Email is required"}, status=400)
    
    if not code:
        return Response({"success": False, "detail": "Verification code is required"}, status=400)
    
    if len(code) != 6 or not code.isdigit():
        return Response({"success": False, "detail": "Invalid verification code format"}, status=400)
    
    if not is_sharif_email(email):
        return Response({"success": False, "detail": "Email must end with @sharif.edu"}, status=400)
    
    # Check if user exists
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"success": False, "detail": "User not found"}, status=404)
    
    # Verify code
    stored_code = mobile_verification_codes.get(email)
    if not stored_code or stored_code != code:
        log_security_event("MOBILE_VERIFICATION_FAILED", email, request.META.get("REMOTE_ADDR", "unknown"), success=False)
        return Response({"success": False, "detail": "Invalid verification code"}, status=400)
    
    # Code is valid, log in user
    refresh = RefreshToken.for_user(user)
    
    # Clear the used code
    mobile_verification_codes.pop(email, None)
    
    # Log successful mobile login
    log_security_event("MOBILE_LOGIN_SUCCESS", user.email, request.META.get("REMOTE_ADDR", "unknown"), success=True)
    
    return Response({
        "success": True,
        "token": str(refresh.access_token),
        "user": UserSerializer(user).data,
        "message": "ورود با موفقیت انجام شد"
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='3/h', method='POST')
def change_password(request):
    """Change user password with current password verification"""
    current_password = request.data.get('current_password', '').strip()
    new_password = request.data.get('new_password', '').strip()
    confirm_password = request.data.get('confirm_password', '').strip()
    
    # Input validation
    if not current_password:
        return Response({"success": False, "detail": "رمز عبور فعلی الزامی است"}, status=400)
    
    if not new_password:
        return Response({"success": False, "detail": "رمز عبور جدید الزامی است"}, status=400)
    
    if not confirm_password:
        return Response({"success": False, "detail": "تکرار رمز عبور جدید الزامی است"}, status=400)
    
    if new_password != confirm_password:
        return Response({"success": False, "detail": "رمز عبور جدید و تکرار آن یکسان نیستند"}, status=400)
    
    # Comprehensive password validation - return only specific errors
    if len(new_password) < 8:
        return Response({"success": False, "detail": "رمز عبور باید حداقل ۸ کاراکتر باشد"}, status=400)
    
    if not any(c.isupper() for c in new_password):
        return Response({"success": False, "detail": "رمز عبور باید شامل حروف بزرگ باشد"}, status=400)
    
    if not any(c.islower() for c in new_password):
        return Response({"success": False, "detail": "رمز عبور باید شامل حروف کوچک باشد"}, status=400)
    
    if not any(c.isdigit() for c in new_password):
        return Response({"success": False, "detail": "رمز عبور باید شامل اعداد باشد"}, status=400)
    
    if not any(c in '!@#$%^&*(),.?":{}|<>' for c in new_password):
        return Response({"success": False, "detail": "رمز عبور باید شامل کاراکترهای خاص باشد"}, status=400)
    
    # Check if new password is different from current
    if current_password == new_password:
        return Response({"success": False, "detail": "رمز عبور جدید باید متفاوت از رمز عبور فعلی باشد"}, status=400)
    
    # Verify current password
    user = request.user
    if not user.check_password(current_password):
        log_security_event("PASSWORD_CHANGE_FAILED", user.email, request.META.get("REMOTE_ADDR", "unknown"), success=False, details="Invalid current password")
        return Response({"success": False, "detail": "رمز عبور فعلی اشتباه است"}, status=400)
    
    # Update password
    try:
        user.set_password(new_password)
        user.save()
        
        # Log successful password change
        log_security_event("PASSWORD_CHANGE_SUCCESS", user.email, request.META.get("REMOTE_ADDR", "unknown"), success=True)
        
        # Invalidate all existing tokens for security
        from rest_framework_simplejwt.tokens import RefreshToken
        RefreshToken.for_user(user)
        
        return Response({
            "success": True, 
            "message": "رمز عبور با موفقیت تغییر یافت. لطفاً دوباره وارد شوید."
        })
    except Exception as e:
        log_security_event("PASSWORD_CHANGE_ERROR", user.email, request.META.get("REMOTE_ADDR", "unknown"), success=False, details=str(e))
        return Response({"success": False, "detail": "خطا در تغییر رمز عبور"}, status=500)

# Create your views here.

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    @method_decorator(ratelimit(key='ip', rate='3/h', method='POST'))
    def post(self, request, *args, **kwargs):
        try:
            # ایمیل را فقط lowercase و trim کن
            if 'email' in request.data:
                request.data['email'] = request.data['email'].lower().strip()
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            
            # Automatically log in the user by generating JWT tokens
            refresh = RefreshToken.for_user(user)
            
            # Log successful registration and auto-login
            log_security_event("REGISTRATION_SUCCESS", user.email, request.META.get("REMOTE_ADDR", "unknown"), success=True)
            log_security_event("AUTO_LOGIN_SUCCESS", user.email, request.META.get("REMOTE_ADDR", "unknown"), success=True)
            
            return Response({
                "success": True,
                "token": str(refresh.access_token),
                "user": UserSerializer(user).data,
                "message": "ثبت نام با موفقیت انجام شد و وارد سیستم شدید"
            })
        except Ratelimited:
            return Response({"success": False, "detail": "تعداد تلاش‌های ثبت نام بیش از حد مجاز است. لطفاً یک ساعت دیگر تلاش کنید."}, status=429)
        except ValidationError as e:
            # Handle validation errors - return the first error message
            if hasattr(e, 'detail') and isinstance(e.detail, dict):
                # Get the first error message from any field
                for field, errors in e.detail.items():
                    if isinstance(errors, list) and errors:
                        error_message = errors[0]
                        break
                    elif isinstance(errors, str):
                        error_message = errors
                        break
                else:
                    error_message = "اطلاعات وارد شده نامعتبر است"
            else:
                error_message = "اطلاعات وارد شده نامعتبر است"
            
            # Log validation error
            email = request.data.get('email', 'unknown')
            log_security_event("REGISTRATION_VALIDATION_ERROR", email, request.META.get("REMOTE_ADDR", "unknown"), 
                             details=error_message, success=False)
            
            return Response({"success": False, "detail": error_message}, status=400)
        except Exception as e:
            security_logger.error(f'Registration error: {str(e)} - IP: {request.META.get("REMOTE_ADDR", "unknown")}')
            return Response({"success": False, "detail": "خطا در ثبت نام"}, status=500)

class LoginView(APIView):
    """
    User login endpoint
    
    Authenticates user with email and password, returns JWT tokens.
    Rate limited to 5 attempts per minute per IP.
    """
    permission_classes = [permissions.AllowAny]
    
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST'))
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            # validated_data is always a dict after is_valid(), linter warning is a false positive
            email = serializer.validated_data['email']  # type: ignore
            password = serializer.validated_data['password']  # type: ignore
            email = email.lower().strip()
            user = authenticate(request, email=email, password=password)
            if not user:
                # Log failed login attempt
                log_security_event("LOGIN_ATTEMPT", email, request.META.get("REMOTE_ADDR", "unknown"), success=False)
                return Response({"success": False, "detail": "Invalid credentials"}, status=401)
            remember_me = request.data.get('remember_me', False)
            refresh = RefreshToken.for_user(user)
            if remember_me:
                refresh.set_exp(lifetime=timedelta(days=14))
                refresh.access_token.set_exp(lifetime=timedelta(days=14))
            # Log successful login
            log_security_event("LOGIN_SUCCESS", user.email, request.META.get("REMOTE_ADDR", "unknown"), success=True)
            return Response({
                "success": True,
                "token": str(refresh.access_token),
                "user": UserSerializer(user).data
            })
        except Ratelimited:
            return Response({"success": False, "detail": "تعداد تلاش‌های ورود بیش از حد مجاز است. لطفاً ۵ دقیقه دیگر تلاش کنید."}, status=429)
        except Exception as e:
            security_logger.error(f'Login error: {str(e)} - IP: {request.META.get("REMOTE_ADDR", "unknown")}')
            return Response({"success": False, "detail": "خطا در ورود به سیستم"}, status=500)

class UserInfoView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        return Response(UserSerializer(request.user).data)

class RefreshTokenView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({"success": False, "detail": "Refresh token is required"}, status=400)
            
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            
            # Log token refresh
            security_logger.info(f'Token refreshed for user: {refresh.payload.get("user_id")} from IP: {request.META.get("REMOTE_ADDR", "unknown")}')
            
            return Response({
                "success": True,
                "access_token": access_token,
                "refresh_token": str(refresh)
            })
        except Exception as e:
            security_logger.warning(f'Invalid refresh token attempt from IP: {request.META.get("REMOTE_ADDR", "unknown")}')
            return Response({"success": False, "detail": "Invalid refresh token"}, status=401)

class ValidateTokenView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        return Response({
            "valid": True,
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "unit": user.unit
            }
        })

# --- Campaign Endpoints ---

def check_user_rate_limit(user_id):
    """Check current rate limit usage for a user"""
    from django.core.cache import cache
    rate_limit_key = f"campaign_submit:{user_id}"
    return cache.get(rate_limit_key, 0)

def reset_user_rate_limit(user_id):
    """Reset rate limit for a user (for testing purposes)"""
    from django.core.cache import cache
    rate_limit_key = f"campaign_submit:{user_id}"
    cache.delete(rate_limit_key)
    return True

class SubmitCampaignView(APIView):
    """
    Submit a new campaign for approval
    Creates a new campaign with pending status.
    Requires authentication.
    Rate limited to 3 campaigns per hour per user.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            # Manual rate limiting check
            from django.core.cache import cache
            from datetime import timedelta
            
            # Create rate limit key
            rate_limit_key = f"campaign_submit:{request.user.id}"
            
            # Check current usage
            current_usage = cache.get(rate_limit_key, 0)
            
            if current_usage >= 3:
                return Response({
                    "success": False, 
                    "detail": "شما بیش از حد مجاز کارزار ایجاد کرده‌اید. لطفاً یک ساعت دیگر تلاش کنید."
                }, status=429)
            
            # Increment usage
            cache.set(rate_limit_key, current_usage + 1, 3600)  # 1 hour timeout
            
            # Content size validation
            content = request.data.get('content', '')
            if len(content) > 50000:
                return Response({"success": False, "detail": "متن کارزار نباید بیشتر از ۵۰,۰۰۰ کاراکتر باشد"}, status=400)
            
            # ایمیل را فقط lowercase و trim کن
            if 'email' in request.data:
                request.data['email'] = request.data['email'].lower().strip()
            # اگر کاربر عادی است و faculty یا dormitory فرستاده، دسته‌بندی را بر اساس آن ست کن
            user = request.user
            if user.role == 'simple_user':
                faculty = request.data.get('faculty')
                dormitory = request.data.get('dormitory')
                if faculty and faculty != 'نامشخص':
                    request.data['category'] = faculty
                elif dormitory and dormitory != 'خوابگاهی نیستم':
                    request.data['category'] = dormitory
            # جلوگیری از ثبت کارزار با دسته‌بندی خوابگاهی نیستم
            if request.data.get('category') == 'خوابگاهی نیستم':
                return Response({"success": False, "detail": "دسته‌بندی نامعتبر است."}, status=400)
            serializer = CampaignSerializer(data=request.data)
            if serializer.is_valid():
                if serializer.validated_data['deadline'] <= timezone.now():
                    return Response({"success": False, "detail": "تاریخ پایان باید بعد از اکنون باشد."}, status=400)
                campaign = serializer.save(status="pending", author=request.user, anonymous_allowed=request.data.get('anonymous_allowed', True))
                return Response({
                    "success": True,
                    "campaignId": campaign.id,
                    "status": campaign.status,
                    "created_at": campaign.created_at,
                    "deadline": campaign.deadline
                })
            return Response(serializer.errors, status=400)
        except Exception as e:
            security_logger.error(f'Campaign submission error: {str(e)} - User: {request.user.email} - IP: {request.META.get("REMOTE_ADDR", "unknown")}')
            return Response({"success": False, "detail": "خطا در ثبت کارزار"}, status=500)

class ApprovedCampaignsView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]
    def get(self, request):
        user = request.user
        all_categories = list(Campaign.objects.filter(status="approved").values_list('category', flat=True))
        allowed_categories = None
        # اگر کاربر authenticated است
        if user.is_authenticated:
            # اگر نقش ادمین دارد، همه را ببیند
            if hasattr(user, 'role') and user.role in ["superadmin", "head", "center_member"]:
                campaigns = Campaign.objects.filter(status="approved")
            else:
                allowed_categories = []
                if hasattr(user, 'faculty') and user.faculty and user.faculty != "نامشخص":
                    allowed_categories.append(user.faculty.strip().lower())
                allowed_categories.append('مسائل دانشگاهی'.strip().lower())
                if hasattr(user, 'dormitory') and user.dormitory and user.dormitory != 'خوابگاهی نیستم':
                    allowed_categories.append(user.dormitory.strip().lower())
                all_campaigns = Campaign.objects.filter(status="approved")
                campaigns = [c for c in all_campaigns if c.category and c.category.strip().lower() in allowed_categories]
        else:
            # anonymous user: همه کارزارهای تایید شده را نمایش بده
            campaigns = Campaign.objects.filter(status="approved")
        serializer = CampaignSerializer(campaigns, many=True, context={'request': request})
        return Response({
            "success": True,
            "campaigns": serializer.data,
            "total": len(serializer.data),
            "debug_user_faculty": getattr(user, 'faculty', None),
            "debug_user_dormitory": getattr(user, 'dormitory', None),
            "debug_all_categories": all_categories,
            "debug_allowed_categories": allowed_categories,
            "debug_user_role": getattr(user, 'role', None),
            "debug_is_authenticated": user.is_authenticated,
        })

class RejectedCampaignsView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        campaigns = Campaign.objects.filter(status="rejected")
        serializer = CampaignSerializer(campaigns, many=True)
        return Response({"success": True, "campaigns": serializer.data, "total": len(serializer.data)})

class PendingCampaignsAdminView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        if user.role in ["superadmin", "head", "center_member"]:
            campaigns = Campaign.objects.all().order_by('-created_at')
        elif user.role == "dorm_member" and user.dormitory and user.dormitory != "خوابگاهی نیستم":
            campaigns = Campaign.objects.filter(category=user.dormitory).order_by('-created_at')
        elif user.role == "faculty_member" and user.faculty and user.faculty != "نامشخص":
            campaigns = Campaign.objects.filter(category=user.faculty).order_by('-created_at')
        else:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        serializer = CampaignSerializer(campaigns, many=True)
        return Response({"success": True, "campaigns": serializer.data, "total": len(serializer.data)})

class ApproveCampaignView(APIView):
    """
    Approve or reject a pending campaign
    
    Admin endpoint to approve/reject campaigns.
    Requires admin role (superadmin, head, center_member).
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        campaign_id = request.data.get('campaign_id')
        approved = request.data.get('approved')
        if campaign_id is None or approved is None:
            return Response({"success": False, "detail": "campaign_id و approved الزامی است."}, status=400)
        try:
            campaign = Campaign.objects.get(id=campaign_id)
        except Campaign.DoesNotExist:
            return Response({"success": False, "detail": "Campaign not found"}, status=404)
        if user.role in ["superadmin", "head", "center_member"]:
            pass
        elif user.role == "dorm_member" and user.dormitory and user.dormitory != "خوابگاهی نیستم" and campaign.category == user.dormitory:
            pass
        elif user.role == "faculty_member" and user.faculty and user.faculty != "نامشخص" and campaign.category == user.faculty:
            pass
        else:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        campaign.status = "approved" if approved else "rejected"
        campaign.save()
        
        # Log admin action
        action = "APPROVE_CAMPAIGN" if approved else "REJECT_CAMPAIGN"
        log_admin_action(action, request.user.email, request.META.get("REMOTE_ADDR", "unknown"), 
                        target=f"Campaign ID: {campaign_id}")
        
        return Response({
            "success": True,
            "message": "کمپین تأیید شد" if approved else "کمپین رد شد",
            "campaign_id": campaign.id,
            "new_status": campaign.status
        })

class UpdateCampaignStatusView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, campaign_id):
        user = request.user
        try:
            campaign = Campaign.objects.get(id=campaign_id)
        except Campaign.DoesNotExist:
            return Response({"success": False, "detail": "کارزار یافت نشد"}, status=404)
        if user.role in ["superadmin", "head", "center_member"]:
            pass
        elif user.role == "dorm_member" and user.dormitory and user.dormitory != "خوابگاهی نیستم" and campaign.category == user.dormitory:
            pass
        elif user.role == "faculty_member" and user.faculty and user.faculty != "نامشخص" and campaign.category == user.faculty:
            pass
        else:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        status_val = request.data.get('status')
        approved = request.data.get('approved')
        if status_val:
            if status_val not in ["approved", "rejected", "pending"]:
                return Response({"success": False, "detail": "وضعیت نامعتبر است"}, status=400)
            campaign.status = status_val
            campaign.save()
            return Response({"success": True, "message": f"وضعیت کارزار به {status_val} تغییر یافت"})
        elif approved is not None:
            campaign.status = "approved" if approved else "rejected"
            campaign.save()
            return Response({"success": True, "message": "کارزار با موفقیت تایید شد" if approved else "کارزار با موفقیت رد شد"})
        else:
            return Response({"success": False, "detail": "باید یکی از status یا approved ارسال شود"}, status=400)

class DeleteCampaignView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, campaign_id):
        user = request.user
        try:
            campaign = Campaign.objects.get(id=campaign_id)
        except Campaign.DoesNotExist:
            return Response({"detail": "کارزار پیدا نشد"}, status=404)
        if user.role in ["superadmin", "head", "center_member"]:
            pass
        elif user.role == "dorm_member" and user.dormitory and user.dormitory != "خوابگاهی نیستم" and campaign.category == user.dormitory:
            pass
        elif user.role == "faculty_member" and user.faculty and user.faculty != "نامشخص" and campaign.category == user.faculty:
            pass
        else:
            return Response({"detail": "دسترسی ندارید."}, status=403)
        campaign.delete()
        return Response({"success": True, "message": "کارزار با موفقیت حذف شد."})

# --- Signature Endpoints ---

class SignCampaignView(APIView):
    permission_classes = [IsAuthenticated]
    
    @method_decorator(ratelimit(key='user', rate='10/m', method='POST'))
    def post(self, request, campaign_id):
        from .models import Campaign
        try:
            campaign = Campaign.objects.get(id=campaign_id)
        except Campaign.DoesNotExist:
            return Response({"success": False, "detail": "کارزار یافت نشد"}, status=404)
        
        # Check if campaign is approved
        if campaign.status != 'approved':
            return Response({"success": False, "detail": "فقط کارزارهای تایید شده قابل امضا هستند"}, status=400)
        
        # Check if already signed
        if CampaignSignature.objects.filter(campaign_id=campaign_id, user=request.user).exists():
            return Response({"success": False, "detail": "شما قبلاً این کارزار را امضا کرده‌اید"}, status=400)
        
        is_anonymous = request.data.get('is_anonymous', 'public')
        signature = CampaignSignature.objects.create(
            campaign=campaign,
            user=request.user,
            user_email=request.user.email,
            is_anonymous=is_anonymous
        )
        total_signatures = CampaignSignature.objects.filter(campaign_id=campaign_id).count()
        return Response({
            "success": True,
            "message": "کارزار با موفقیت امضا شد",
            "signature_id": signature.id,
            "total_signatures": total_signatures
        })

class CampaignSignaturesView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request, campaign_id):
        from .models import Campaign
        try:
            campaign = Campaign.objects.get(id=campaign_id)
        except Campaign.DoesNotExist:
            return Response({"success": False, "detail": "کارزار یافت نشد"}, status=404)
        
        # Only show signatures for approved campaigns
        if campaign.status != 'approved':
            return Response({
                "success": True,
                "signatures": [],
                "total": 0,
                "campaign_anonymous_allowed": campaign.anonymous_allowed
            })
        
        # اگر کارزار شناس است، لیست کامل امضاکنندگان را بده
        if not campaign.anonymous_allowed:
            signatures = CampaignSignature.objects.filter(campaign_id=campaign_id)
            signature_list = [
                {
                    "id": s.id,
                    "user_email": s.user_email,
                    "signed_at": s.signed_at,
                    "is_anonymous": s.is_anonymous
                } for s in signatures
            ]
            return Response({
                "success": True,
                "signatures": signature_list,
                "total": len(signature_list),
                "campaign_anonymous_allowed": False
            })
        # اگر کارزار ناشناس است، فقط تعداد را بده
        signatures = CampaignSignature.objects.filter(campaign_id=campaign_id)
        signature_list = [
            {
                "id": s.id,
                "user_email": "ناشناس",
                "signed_at": s.signed_at,
                "is_anonymous": s.is_anonymous
            } for s in signatures
        ]
        return Response({
            "success": True,
            "signatures": [],
            "total": len(signature_list),
            "campaign_anonymous_allowed": True
        })

class CheckUserSignatureView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, campaign_id):
        from .models import Campaign
        try:
            campaign = Campaign.objects.get(id=campaign_id)
        except Campaign.DoesNotExist:
            return Response({"success": False, "detail": "کارزار یافت نشد"}, status=404)
        signature = CampaignSignature.objects.filter(campaign_id=campaign_id, user=request.user).first()
        if signature:
            return Response({
                "has_signed": True,
                "signature": {
                    "id": signature.id,
                    "signed_at": signature.signed_at,
                    "is_anonymous": signature.is_anonymous
                }
            })
        else:
            return Response({"has_signed": False, "signature": None})

class UserSignedCampaignsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        signatures = CampaignSignature.objects.filter(user=request.user)
        campaign_list = []
        for sig in signatures:
            campaign = sig.campaign
            campaign_list.append({
                "campaign_id": campaign.id,
                "campaign_title": campaign.title,
                "signed_at": sig.signed_at,
                "is_anonymous": sig.is_anonymous
            })
        return Response({
            "success": True,
            "campaigns": campaign_list,
            "total": len(campaign_list)
        })

class UserIdSignedCampaignsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, user_id):
        if request.user.role not in ["superadmin", "head"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"success": False, "detail": "کاربر یافت نشد"}, status=404)
        signatures = CampaignSignature.objects.filter(user=user)
        campaign_list = []
        for sig in signatures:
            campaign = sig.campaign
            campaign_list.append({
                "campaign_id": campaign.id,
                "campaign_title": campaign.title,
                "signed_at": sig.signed_at,
                "is_anonymous": sig.is_anonymous
            })
        return Response({
            "success": True,
            "campaigns": campaign_list,
            "total": len(campaign_list)
        })

# --- User List and Role Management Endpoints ---

class UserListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        if request.user.role not in ["superadmin", "head"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        users = User.objects.all().order_by('-id')
        data = [
            {
                "id": u.id,
                "email": u.email,
                "role": u.role,
                "unit": u.unit
            } for u in users
        ]
        return Response(data)

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, user_id):
        if request.user.role not in ["superadmin", "head"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"success": False, "detail": "کاربر پیدا نشد"}, status=404)
        return Response({
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "unit": user.unit
        })

class UpdateUserRoleView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, user_id):
        if request.user.role != "superadmin":
            return Response({"success": False, "detail": "Only superadmin can change user roles."}, status=403)
        new_role = request.data.get('new_role')
        if not new_role:
            return Response({"success": False, "detail": "new_role is required."}, status=400)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"success": False, "detail": "User not found."}, status=404)
        if user.role == "superadmin":
            return Response({"success": False, "detail": "Cannot change role of another superadmin."}, status=400)
        if new_role == "superadmin":
            return Response({"success": False, "detail": "Cannot assign superadmin role."}, status=400)
        user.role = new_role
        user.save()
        return Response({
            "success": True,
            "message": "User role updated successfully.",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "unit": user.unit
            }
        })

# --- Performance Monitoring Endpoints ---

class PerformanceSummaryView(APIView):
    """
    Get performance summary
    
    Returns overall performance metrics and system health.
    Requires admin role.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if request.user.role not in ["superadmin", "head"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        
        summary = performance_monitor.get_performance_summary()
        return Response({
            "success": True,
            "performance": summary
        })

class EndpointPerformanceView(APIView):
    """
    Get detailed endpoint performance
    
    Returns performance metrics for specific endpoints.
    Requires admin role.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, endpoint=None):
        if request.user.role not in ["superadmin", "head"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        
        if endpoint:
            performance = performance_monitor.get_endpoint_performance(endpoint)
        else:
            performance = performance_monitor.get_endpoint_performance()
        
        return Response({
            "success": True,
            "endpoint_performance": performance
        })

class SlowRequestsView(APIView):
    """
    Get recent slow requests
    
    Returns list of recent slow requests (>2 seconds).
    Requires admin role.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if request.user.role not in ["superadmin", "head"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        
        limit = request.query_params.get('limit', 10)
        try:
            limit = int(limit)
        except ValueError:
            limit = 10
        
        slow_requests = performance_monitor.get_slow_requests(limit)
        return Response({
            "success": True,
            "slow_requests": slow_requests
        })

class SystemMetricsView(APIView):
    """
    Get system metrics
    
    Returns system performance metrics (CPU, memory, disk).
    Requires admin role.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if request.user.role not in ['superadmin', 'head', 'center_member']:
            return Response({"detail": "Access denied"}, status=403)
        
        try:
            import psutil
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            metrics = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_gb': round(memory.available / (1024**3), 2),
                'disk_percent': disk.percent,
                'disk_free_gb': round(disk.free / (1024**3), 2)
            }
            
            return Response(metrics)
        except ImportError:
            return Response({"detail": "psutil not available"}, status=500)

# BlogPost Views
class BlogPostListView(APIView):
    """
    Get list of published blog posts
    
    Returns published blog posts with pagination.
    Public endpoint - no authentication required.
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        try:
            # Get query parameters
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 10))
            category = request.GET.get('category', '')
            search = request.GET.get('search', '')
            
            # Filter published posts
            queryset = BlogPost.objects.filter(is_published=True)
            
            # Apply filters
            if category:
                queryset = queryset.filter(category=category)
            
            if search:
                queryset = queryset.filter(
                    models.Q(title__icontains=search) |
                    models.Q(content__icontains=search) |
                    models.Q(excerpt__icontains=search)
                )
            
            # Pagination
            total_count = queryset.count()
            start = (page - 1) * page_size
            end = start + page_size
            posts = queryset[start:end]
            
            serializer = BlogPostListSerializer(posts, many=True)
            
            return Response({
                'posts': serializer.data,
                'pagination': {
                    'page': page,
                    'page_size': page_size,
                    'total_count': total_count,
                    'total_pages': (total_count + page_size - 1) // page_size
                }
            })
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class BlogPostDetailView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request, slug):
        try:
            # First try to get published post (public access)
            try:
                post = BlogPost.objects.get(slug=slug, is_published=True)
                serializer = BlogPostSerializer(post)
                return Response(serializer.data)
            except BlogPost.DoesNotExist:
                pass
            
            # If not published, check for unpublished post with access control
            try:
                post = BlogPost.objects.get(slug=slug, is_published=False)
                
                # Check access permissions for unpublished posts
                user = request.user
                
                # Check if user is authenticated
                if not user.is_authenticated:
                    return Response({"detail": "Blog post not found"}, status=404)
                
                # Check if user is the author or has admin role
                is_author = post.author == user
                is_admin = hasattr(user, 'role') and user.role in ['superadmin', 'head', 'center_member']
                is_dorm_admin = hasattr(user, 'role') and user.role == 'dorm_member' and hasattr(user, 'dormitory') and user.dormitory and user.dormitory != 'خوابگاهی نیستم' and post.category == user.dormitory
                is_faculty_admin = hasattr(user, 'role') and user.role == 'faculty_member' and hasattr(user, 'faculty') and user.faculty and user.faculty != 'نامشخص' and post.category == user.faculty
                
                if not (is_author or is_admin or is_dorm_admin or is_faculty_admin):
                    return Response({"detail": "Blog post not found"}, status=404)
                
                serializer = BlogPostSerializer(post)
                return Response(serializer.data)
                
            except BlogPost.DoesNotExist:
                return Response({"detail": "Blog post not found"}, status=404)
                
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class BlogPostCreateView(APIView):
    """
    Create new blog post
    
    Creates a new blog post. Any authenticated user can create posts.
    Posts are created as unpublished and need admin approval.
    Rate limited to 2 posts per hour per user.
    """
    permission_classes = [IsAuthenticated]
    
    @method_decorator(ratelimit(key='user', rate='2/h', method='POST'))
    def post(self, request):
        try:
            # Content size validation
            content = request.data.get('content', '')
            if len(content) > 50000:
                return Response({"success": False, "detail": "محتوای بلاگ نباید بیشتر از ۵۰,۰۰۰ کاراکتر باشد"}, status=400)
            
            serializer = BlogPostSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(author=request.user)
                return Response({
                    "success": True,
                    "message": "مطلب شما با موفقیت ایجاد شد و در انتظار تایید ادمین است.",
                    "post": serializer.data
                }, status=201)
            else:
                error_messages = []
                for field, errors in serializer.errors.items():
                    if field == 'title':
                        error_messages.append("عنوان مطلب الزامی است و باید بین 3 تا 255 کاراکتر باشد.")
                    elif field == 'content':
                        error_messages.append("محتوای مطلب الزامی است.")
                    elif field == 'category':
                        error_messages.append("دسته‌بندی مطلب الزامی است.")
                    elif field == 'slug':
                        error_messages.append("نامک مطلب باید فقط شامل حروف کوچک، اعداد، خط تیره و زیرخط باشد.")
                    else:
                        error_messages.append(f"خطا در فیلد {field}: {errors[0]}")
                return Response({
                    "success": False,
                    "detail": "خطا در ایجاد مطلب",
                    "errors": error_messages
                }, status=400)
        except Ratelimited:
            return Response({"success": False, "detail": "شما بیش از حد مجاز مطلب ایجاد کرده‌اید. لطفاً یک ساعت دیگر تلاش کنید."}, status=429)
        except Exception as e:
            return Response({
                "success": False,
                "detail": "خطای داخلی سرور در ایجاد مطلب"
            }, status=500)

class BlogPostUpdateView(APIView):
    """
    Update blog post
    
    Updates an existing blog post. Only superadmin, center_member, head, faculty_member, dorm_member can update posts (faculty/dorm only their own category).
    """
    permission_classes = [IsAuthenticated]
    def put(self, request, post_id):
        user = request.user
        try:
            post = BlogPost.objects.get(id=post_id)
        except BlogPost.DoesNotExist:
            return Response({"detail": "Blog post not found"}, status=404)
        # Permission check
        if user.role in ['superadmin', 'center_member', 'head']:
            pass
        elif user.role == 'faculty_member' and user.faculty and user.faculty != 'نامشخص' and post.category == user.faculty:
            pass
        elif user.role == 'dorm_member' and user.dormitory and user.dormitory != 'خوابگاهی نیستم' and post.category == user.dormitory:
            pass
        else:
            return Response({"detail": "Only superadmin, center_member, head, faculty_member (for their faculty), or dorm_member (for their dormitory) can update blog posts"}, status=403)
        serializer = BlogPostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

class BlogPostDeleteView(APIView):
    """
    Delete blog post
    
    Deletes a blog post. Only superadmin, center_member, head, faculty_member, dorm_member can delete posts (faculty/dorm only their own category).
    """
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, post_id):
        user = request.user
        try:
            post = BlogPost.objects.get(id=post_id)
        except BlogPost.DoesNotExist:
            return Response({"detail": "Blog post not found"}, status=404)
        # Permission check
        if user.role in ['superadmin', 'center_member', 'head']:
            pass
        elif user.role == 'faculty_member' and user.faculty and user.faculty != 'نامشخص' and post.category == user.faculty:
            pass
        elif user.role == 'dorm_member' and user.dormitory and user.dormitory != 'خوابگاهی نیستم' and post.category == user.dormitory:
            pass
        else:
            return Response({"detail": "Only superadmin, center_member, head, faculty_member (for their faculty), or dorm_member (for their dormitory) can delete blog posts"}, status=403)
        post.delete()
        return Response({"detail": "Blog post deleted successfully"})

class BlogPostAdminListView(APIView):
    """
    Get all blog posts for admin management
    
    Returns all blog posts (published and unpublished) for admin management.
    Only superadmin, center_member, head, faculty_member, dorm_member can access.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        # Determine queryset based on role
        if user.role in ['superadmin', 'center_member', 'head']:
            queryset = BlogPost.objects.all()
        elif user.role == 'faculty_member' and user.faculty and user.faculty != 'نامشخص':
            queryset = BlogPost.objects.filter(category=user.faculty)
        elif user.role == 'dorm_member' and user.dormitory and user.dormitory != 'خوابگاهی نیستم':
            queryset = BlogPost.objects.filter(category=user.dormitory)
        else:
            return Response({"detail": "Only superadmin, center_member, head, faculty_member, or dorm_member can access admin blog list"}, status=403)
        try:
            status_filter = request.GET.get('status', 'all')  # all, published, unpublished
            # Apply status filter
            if status_filter == 'published':
                queryset = queryset.filter(is_published=True)
            elif status_filter == 'unpublished':
                queryset = queryset.filter(is_published=False)
            posts = queryset.order_by('-created_at')
            serializer = BlogPostSerializer(posts, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class BlogPostPublishView(APIView):
    """
    Publish or unpublish blog post
    
    Toggles the published status of a blog post.
    Only superadmin, center_member, head, faculty_member, dorm_member can publish/unpublish posts (faculty/dorm only their own category).
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request, post_id):
        user = request.user
        try:
            post = BlogPost.objects.get(id=post_id)
        except BlogPost.DoesNotExist:
            return Response({"detail": "Blog post not found"}, status=404)
        # Permission check
        if user.role in ['superadmin', 'center_member', 'head']:
            pass
        elif user.role == 'faculty_member' and user.faculty and user.faculty != 'نامشخص' and post.category == user.faculty:
            pass
        elif user.role == 'dorm_member' and user.dormitory and user.dormitory != 'خوابگاهی نیستم' and post.category == user.dormitory:
            pass
        else:
            return Response({"detail": "Only superadmin, center_member, head, faculty_member (for their faculty), or dorm_member (for their dormitory) can publish/unpublish blog posts"}, status=403)
        action = request.data.get('action', 'toggle')  # toggle, approve, reject
        if action == 'approve':
            post.is_published = True
            if not post.published_at:
                post.published_at = timezone.now()
        elif action == 'reject':
            post.is_published = False
        else:  # toggle
            post.is_published = not post.is_published
            if post.is_published and not post.published_at:
                post.published_at = timezone.now()
        post.save()
        serializer = BlogPostSerializer(post)
        return Response(serializer.data)

class CampaignDetailView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request, campaign_id):
        try:
            campaign = Campaign.objects.get(id=campaign_id)
            
            # Check access permissions based on campaign status
            user = request.user
            
            # If campaign is approved, anyone can view it
            if campaign.status == 'approved':
                serializer = CampaignSerializer(campaign, context={'request': request})
                return Response(serializer.data)
            
            # If campaign is pending or rejected, only author and admins can view it
            if campaign.status in ['pending', 'rejected']:
                # Check if user is authenticated
                if not user.is_authenticated:
                    return Response({"detail": "Campaign not found"}, status=404)
                
                # Check if user is the author or has admin role
                is_author = campaign.author == user
                is_admin = hasattr(user, 'role') and user.role in ['superadmin', 'head', 'center_member']
                is_dorm_admin = hasattr(user, 'role') and user.role == 'dorm_member' and hasattr(user, 'dormitory') and user.dormitory and user.dormitory != 'خوابگاهی نیستم' and campaign.category == user.dormitory
                is_faculty_admin = hasattr(user, 'role') and user.role == 'faculty_member' and hasattr(user, 'faculty') and user.faculty and user.faculty != 'نامشخص' and campaign.category == user.faculty
                
                if not (is_author or is_admin or is_dorm_admin or is_faculty_admin):
                    return Response({"detail": "Campaign not found"}, status=404)
                
                serializer = CampaignSerializer(campaign, context={'request': request})
                return Response(serializer.data)
            
            # For any other status, return 404
            return Response({"detail": "Campaign not found"}, status=404)
            
        except Campaign.DoesNotExist:
            return Response({"detail": "Campaign not found"}, status=404)
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class CampaignCategoryChoicesView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        user = request.user
        def filter_out_invalid(categories):
            return [c for c in categories if c != 'خوابگاهی نیستم']
        if not user.is_authenticated:
            return Response({
                "categories": ["مسائل دانشگاهی"]
            })
        allowed = ["مسائل دانشگاهی"]
        if hasattr(user, 'faculty') and user.faculty and user.faculty != "نامشخص":
            allowed.append(user.faculty)
        if hasattr(user, 'dormitory') and user.dormitory and user.dormitory != 'خوابگاهی نیستم':
            allowed.append(user.dormitory)
        # اضافه کردن شورای عمومی برای اعضا و ناظران شورا
        if (hasattr(user, 'council_member_status') and user.council_member_status in ["member", "observer"]) or \
           (hasattr(user, 'role') and user.role in ["superadmin", "head"]):
            allowed.append("شورای عمومی")
        # اگر نقش ادمین دارد، همه را ببیند (و شورای عمومی هم اضافه شود)
        if hasattr(user, 'role') and user.role in ["superadmin", "head", "center_member"]:
            from .choices import CAMPAIGN_CATEGORY_CHOICES
            all_labels = [c[0] for c in CAMPAIGN_CATEGORY_CHOICES]
            if "شورای عمومی" not in all_labels:
                all_labels.append("شورای عمومی")
            return Response({
                "categories": filter_out_invalid(all_labels)
            })
        return Response({
            "categories": filter_out_invalid(allowed)
        })

# --- Poll Endpoints ---

class PollListCreateView(APIView):
    """
    List all approved polls or create a new poll (authenticated).
    Rate limited to 2 polls per hour per user.
    """
    def get(self, request):
        polls = Poll.objects.filter(status="approved").order_by('-created_at')
        if request.user.is_authenticated:
            polls = polls.prefetch_related(
                models.Prefetch('participations', to_attr='user_participations', queryset=PollParticipation.objects.filter(user=request.user))
            )
            polls = list(polls)  # Ensure prefetch works for serializer
        serializer = PollSerializer(polls, many=True, context={'request': request})
        return Response({"success": True, "polls": serializer.data, "total": len(serializer.data)})

    @method_decorator(ratelimit(key='user', rate='2/h', method='POST'))
    def post(self, request):
        try:
            if not request.user.is_authenticated:
                return Response({"success": False, "detail": "نیاز به ورود دارید."}, status=403)
            
            # Content size validation
            description = request.data.get('description', '')
            if len(description) > 10000:
                return Response({"success": False, "detail": "توضیحات نظرسنجی نباید بیشتر از ۱۰,۰۰۰ کاراکتر باشد"}, status=400)
            
            data = request.data.copy()
            # جلوگیری از ساخت نظرسنجی شورای عمومی توسط observer
            if data.get('category') == 'شورای عمومی' and getattr(request.user, 'council_member_status', None) == 'observer':
                return Response({"success": False, "detail": "شما به عنوان ناظر شورای عمومی مجاز به ایجاد نظرسنجی با این دسته‌بندی نیستید."}, status=403)
            data['author'] = request.user.id
            serializer = PollSerializer(data=data, context={'request': request})
            if serializer.is_valid():
                poll = serializer.save(status="pending", author=request.user)
                return Response({"success": True, "poll": PollSerializer(poll, context={'request': request}).data})
            return Response({"success": False, "errors": serializer.errors}, status=400)
        except Ratelimited:
            return Response({"success": False, "detail": "شما بیش از حد مجاز نظرسنجی ایجاد کرده‌اید. لطفاً یک ساعت دیگر تلاش کنید."}, status=429)

class PollDetailView(APIView):
    """
    Retrieve or update poll details (public for GET, admin/author for PUT).
    """
    def get(self, request, poll_id):
        try:
            poll = Poll.objects.get(id=poll_id)
            
            # Check access permissions based on poll status
            user = request.user
            
            # If poll is approved, anyone can view it
            if poll.status == 'approved':
                serializer = PollSerializer(poll, context={'request': request})
                return Response({"success": True, "poll": serializer.data})
            
            # If poll is pending or rejected, only author and admins can view it
            if poll.status in ['pending', 'rejected']:
                # Check if user is authenticated
                if not user.is_authenticated:
                    return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
                
                # Check if user is the author or has admin role
                is_author = poll.author == user
                is_admin = hasattr(user, 'role') and user.role in ['superadmin', 'head', 'center_member']
                
                if not (is_author or is_admin):
                    return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
                
                serializer = PollSerializer(poll, context={'request': request})
                return Response({"success": True, "poll": serializer.data})
            
            # For any other status, return 404
            return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
            
        except Poll.DoesNotExist:
            return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)

    def put(self, request, poll_id):
        try:
            poll = Poll.objects.get(id=poll_id)
        except Poll.DoesNotExist:
            return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
        user = request.user
        is_admin = getattr(user, 'role', None) in ["superadmin", "head", "center_member", "dorm_member", "faculty_member"]
        is_author = poll.author == user
        if not (is_admin or is_author):
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        serializer = PollSerializer(poll, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "poll": serializer.data})
        return Response({"success": False, "errors": serializer.errors}, status=400)

class PollVoteView(APIView):
    """
    Vote in a poll (authenticated). Supports single/multiple choice.
    """
    @method_decorator(ratelimit(key='user', rate='5/m', method='POST'))
    def post(self, request, poll_id):
        if not request.user.is_authenticated:
            return Response({"success": False, "detail": "نیاز به ورود دارید."}, status=403)
        try:
            poll = Poll.objects.get(id=poll_id)
        except Poll.DoesNotExist:
            return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
        
        # Check if poll is approved
        if poll.status != 'approved':
            return Response({"success": False, "detail": "فقط نظرسنجی‌های تایید شده قابل رای گیری هستند"}, status=400)
        
        if poll.is_expired():
            return Response({"success": False, "detail": "مهلت رأی دادن به پایان رسیده است."}, status=400)
        # Check if already participated
        if PollParticipation.objects.filter(poll=poll, user=request.user).exists():
            return Response({"success": False, "detail": "شما قبلاً در این نظرسنجی شرکت کرده‌اید."}, status=400)
        option_ids = request.data.get('option_ids')
        if not option_ids:
            return Response({"success": False, "detail": "گزینه‌ای انتخاب نشده است."}, status=400)
        if not isinstance(option_ids, list):
            option_ids = [option_ids]
        # Validate options
        valid_option_ids = set(poll.options.values_list('id', flat=True))
        for oid in option_ids:
            if oid not in valid_option_ids:
                return Response({"success": False, "detail": f"گزینه نامعتبر: {oid}"}, status=400)
        # For single choice, only one vote allowed
        if not poll.is_multiple_choice and len(option_ids) > 1:
            return Response({"success": False, "detail": "این نظرسنجی فقط یک گزینه را می‌پذیرد."}, status=400)
        # Register participation
        PollParticipation.objects.create(user=request.user, poll=poll)
        # Save votes (anonymous or identified based on poll setting)
        created_votes = []
        for oid in option_ids:
            vote_data = {
                'poll': poll,
                'option_id': oid
            }
            # If poll is not anonymous, save user info
            if not poll.is_anonymous:
                vote_data['user'] = request.user
            vote = PollVote.objects.create(**vote_data)
            created_votes.append(vote)
        return Response({"success": True, "message": "رأی شما ثبت شد.", "votes": PollVoteSerializer(created_votes, many=True).data})

class PollResultsView(APIView):
    """
    Get poll results (public if is_public, else only admin/author).
    """
    def get(self, request, poll_id):
        try:
            poll = Poll.objects.get(id=poll_id)
        except Poll.DoesNotExist:
            return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
        
        # Check access permissions based on poll status
        user = request.user
        
        # If poll is approved, anyone can view results
        if poll.status == 'approved':
            serializer = PollSerializer(poll, context={'request': request})
            return Response({"success": True, "results": serializer.data})
        
        # If poll is pending or rejected, only author and admins can view results
        if poll.status in ['pending', 'rejected']:
            # Check if user is authenticated
            if not user.is_authenticated:
                return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
            
            # Check if user is the author or has admin role
            is_author = poll.author == user
            is_admin = hasattr(user, 'role') and user.role in ['superadmin', 'head', 'center_member']
            
            if not (is_author or is_admin):
                return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
            
            serializer = PollSerializer(poll, context={'request': request})
            return Response({"success": True, "results": serializer.data})
        
        # For any other status, return 404
        return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)

class PollAdminListView(APIView):
    """
    List all polls for admin management (admin only).
    """
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        if getattr(user, 'role', None) in ["superadmin", "head", "center_member"]:
            polls = Poll.objects.all().order_by('-created_at')
        elif getattr(user, 'role', None) == "dorm_member" and user.dormitory and user.dormitory != "خوابگاهی نیستم":
            polls = Poll.objects.filter(category=user.dormitory).order_by('-created_at')
        elif getattr(user, 'role', None) == "faculty_member" and user.faculty and user.faculty != "نامشخص":
            polls = Poll.objects.filter(category=user.faculty).order_by('-created_at')
        else:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        serializer = PollSerializer(polls, many=True, context={'request': request})
        return Response({"success": True, "polls": serializer.data, "total": len(serializer.data)})

class PollApproveRejectView(APIView):
    """
    Approve or reject a poll (admin only).
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        if getattr(request.user, 'role', None) not in ["superadmin", "head", "center_member"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        poll_id = request.data.get('poll_id')
        approved = request.data.get('approved')
        if poll_id is None or approved is None:
            return Response({"success": False, "detail": "poll_id و approved الزامی است."}, status=400)
        try:
            poll = Poll.objects.get(id=poll_id)
        except Poll.DoesNotExist:
            return Response({"success": False, "detail": "Poll not found"}, status=404)
        poll.status = "approved" if approved else "rejected"
        poll.save()
        return Response({"success": True, "message": "نظرسنجی تایید شد" if approved else "نظرسنجی رد شد", "poll_id": poll.id, "new_status": poll.status})

class PollDeleteView(APIView):
    """
    Delete a poll (admin or author).
    """
    permission_classes = [IsAuthenticated]
    def delete(self, request, poll_id):
        try:
            poll = Poll.objects.get(id=poll_id)
        except Poll.DoesNotExist:
            return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
        is_admin = getattr(request.user, 'role', None) in ["superadmin", "head", "center_member"]
        is_author = poll.author == request.user
        if not (is_admin or is_author):
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        poll.delete()
        return Response({"success": True, "message": "نظرسنجی با موفقیت حذف شد."})


class PollVotersView(APIView):
    """
    Get list of voters for a poll (only for non-anonymous polls).
    """
    def get(self, request, poll_id):
        try:
            poll = Poll.objects.get(id=poll_id)
        except Poll.DoesNotExist:
            return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
        
        # Only show voters if poll is not anonymous
        if poll.is_anonymous:
            return Response({"success": False, "detail": "این نظرسنجی ناشناس است و لیست رأی‌دهندگان نمایش داده نمی‌شود."}, status=403)
        
        # Check permissions - only admin, author, or participants can see voters
        is_admin = request.user.is_authenticated and getattr(request.user, 'role', None) in ["superadmin", "head", "center_member"]
        is_author = request.user.is_authenticated and poll.author == request.user
        has_participated = request.user.is_authenticated and PollParticipation.objects.filter(poll=poll, user=request.user).exists()
        
        if not (is_admin or is_author or has_participated):
            return Response({"success": False, "detail": "دسترسی به لیست رأی‌دهندگان ندارید."}, status=403)
        
        # Get votes with user information
        votes = PollVote.objects.filter(poll=poll, user__isnull=False).select_related('user', 'option').order_by('-voted_at')
        
        voters_data = []
        for vote in votes:
            voters_data.append({
                'user_email': vote.user.email,
                'option_text': vote.option.text,
                'voted_at': vote.voted_at
            })
        
        return Response({
            "success": True, 
            "voters": voters_data,
            "total_voters": len(voters_data)
        })

class PollStatusUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, poll_id):
        user = request.user
        if getattr(user, 'role', None) not in ["superadmin", "head", "center_member"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        from .models import Poll
        try:
            poll = Poll.objects.get(id=poll_id)
        except Poll.DoesNotExist:
            return Response({"success": False, "detail": "نظرسنجی پیدا نشد"}, status=404)
        status_val = request.data.get('status')
        if status_val:
            if status_val not in ["approved", "rejected", "pending", "closed"]:
                return Response({"success": False, "detail": "وضعیت نامعتبر است"}, status=400)
            poll.status = status_val
            poll.save()
            return Response({"success": True, "message": f"وضعیت نظرسنجی به {status_val} تغییر یافت"})
        else:
            return Response({"success": False, "detail": "باید status ارسال شود"}, status=400)


class UserVotedPollsView(APIView):
    """
    Get list of polls that the user has voted on.
    Returns poll details including the user's vote for non-anonymous polls.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Get all polls where user has participated
        participations = PollParticipation.objects.filter(user=user).select_related('poll')
        
        voted_polls = []
        for participation in participations:
            poll = participation.poll
            
            # Get poll details
            poll_data = {
                'id': poll.id,
                'title': poll.title,
                'description': poll.description,
                'category': poll.category,
                'is_multiple_choice': poll.is_multiple_choice,
                'max_choices': poll.max_choices,
                'is_anonymous': poll.is_anonymous,
                'status': poll.status,
                'deadline': poll.deadline,
                'created_at': poll.created_at,
                'total_votes': poll.total_votes,
                'options': []
            }
            
            # Get poll options with vote counts
            options = PollOption.objects.filter(poll=poll)
            for option in options:
                option_data = {
                    'id': option.id,
                    'text': option.text,
                    'votes_count': option.votes_count
                }
                poll_data['options'].append(option_data)
            
            # If poll is not anonymous, include user's vote
            if not poll.is_anonymous:
                user_votes = PollVote.objects.filter(poll=poll, user=user).select_related('option')
                user_voted_options = []
                for vote in user_votes:
                    user_voted_options.append({
                        'option_id': vote.option.id,
                        'option_text': vote.option.text,
                        'voted_at': vote.voted_at
                    })
                poll_data['user_vote'] = user_voted_options
            else:
                poll_data['user_vote'] = None
            
            voted_polls.append(poll_data)
        
        # Sort by most recent vote first
        voted_polls.sort(key=lambda x: x.get('user_vote', [{}])[0].get('voted_at', x['created_at']) if x.get('user_vote') else x['created_at'], reverse=True)
        
        return Response({
            "success": True,
            "polls": voted_polls,
            "total": len(voted_polls)
        })

class UserCreatedCampaignsView(APIView):
    """
    Get list of campaigns created by the user.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        try:
            campaigns = Campaign.objects.filter(author=user).order_by('-created_at')
            serializer = CampaignSerializer(campaigns, many=True, context={'request': request})
            
            return Response({
                "success": True,
                "campaigns": serializer.data,
                "total": len(serializer.data)
            })
        except Exception as e:
            return Response({"success": False, "detail": "خطا در دریافت کارزارهای ایجاد شده"}, status=500)

class UserCreatedBlogPostsView(APIView):
    """
    Get list of blog posts created by the user.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        try:
            blog_posts = BlogPost.objects.filter(author=user).order_by('-created_at')
            serializer = BlogPostListSerializer(blog_posts, many=True, context={'request': request})
            
            return Response({
                "success": True,
                "blog_posts": serializer.data,
                "total": len(serializer.data)
            })
        except Exception as e:
            return Response({"success": False, "detail": "خطا در دریافت بلاگ‌های ایجاد شده"}, status=500)

class UserCreatedPollsView(APIView):
    """
    Get list of polls created by the user.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        try:
            polls = Poll.objects.filter(author=user).order_by('-created_at')
            serializer = PollSerializer(polls, many=True, context={'request': request})
            
            return Response({
                "success": True,
                "polls": serializer.data,
                "total": len(serializer.data)
            })
        except Exception as e:
            return Response({"success": False, "detail": "خطا در دریافت نظرسنجی‌های ایجاد شده"}, status=500)
