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
from .models import PendingCampaign
from .serializers import PendingCampaignSerializer
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from rest_framework import status as drf_status
from django.utils import timezone
from .models import CampaignSignature, User, BlogPost
from .serializers import CampaignSignatureSerializer, BlogPostSerializer, BlogPostListSerializer
from django_ratelimit.decorators import ratelimit
from .utils import log_security_event, log_data_access, log_admin_action
from .performance import performance_monitor
from rest_framework.exceptions import ValidationError
import logging
import sys
from django.db import models

# Security logger
security_logger = logging.getLogger('security')

User = get_user_model()

# In-memory store for verification codes (like FastAPI version)
verification_codes = {}

def is_sharif_email(email):
    return email.lower().endswith("@sharif.edu")

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def check_email(request):
    email = request.data.get('email', '').lower()
    if not is_sharif_email(email):
        return Response({"exists": False})
    exists = User.objects.filter(email=email).exists()
    return Response({"exists": exists})

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
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
        # Debug email configuration
        print(f"[DEBUG] Email config - HOST: {settings.EMAIL_HOST}, PORT: {settings.EMAIL_PORT}, USER: {settings.EMAIL_HOST_USER}")
        print(f"[DEBUG] Attempting to send email to: {email}")
        
        send_mail(
            'Sharif Verification Code',
            f'Your verification code is: {code}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False
        )
        print(f"[INFO] Verification code sent to {email}")
        return Response({"success": True})
    except Exception as e:
        print(f"[ERROR] Failed to send verification code to {email}: {str(e)}")
        print(f"[ERROR] Email settings - HOST: {settings.EMAIL_HOST}, PORT: {settings.EMAIL_PORT}, USER: {settings.EMAIL_HOST_USER}")
        return Response({"success": False, "detail": f"Failed to send verification code: {str(e)}"}, status=500)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def test_email_config(request):
    """Test email configuration - for debugging only"""
    try:
        print(f"[DEBUG] Testing email configuration...")
        print(f"[DEBUG] EMAIL_HOST: {settings.EMAIL_HOST}")
        print(f"[DEBUG] EMAIL_PORT: {settings.EMAIL_PORT}")
        print(f"[DEBUG] EMAIL_USE_TLS: {settings.EMAIL_USE_TLS}")
        print(f"[DEBUG] EMAIL_USE_SSL: {settings.EMAIL_USE_SSL}")
        print(f"[DEBUG] EMAIL_HOST_USER: {settings.EMAIL_HOST_USER}")
        print(f"[DEBUG] DEFAULT_FROM_EMAIL: {settings.DEFAULT_FROM_EMAIL}")
        
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
        print(f"[ERROR] Email configuration test failed: {str(e)}")
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

# Create your views here.

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        try:
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
    
    def post(self, request):
        try:
            serializer = LoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            # validated_data is always a dict after is_valid(), linter warning is a false positive
            email = serializer.validated_data['email']  # type: ignore
            password = serializer.validated_data['password']  # type: ignore
            user = authenticate(request, email=email, password=password)
            if not user:
                # Log failed login attempt
                log_security_event("LOGIN_ATTEMPT", email, request.META.get("REMOTE_ADDR", "unknown"), success=False)
                return Response({"success": False, "detail": "Invalid credentials"}, status=401)
            refresh = RefreshToken.for_user(user)
            # Log successful login
            log_security_event("LOGIN_SUCCESS", user.email, request.META.get("REMOTE_ADDR", "unknown"), success=True)
            return Response({
                "success": True,
                "token": str(refresh.access_token),
                "user": UserSerializer(user).data
            })
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

class SubmitCampaignView(APIView):
    """
    Submit a new campaign for approval
    
    Creates a new campaign with pending status.
    Requires authentication.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data.copy()
        data['email'] = request.user.email
        
        # Input validation
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        end_datetime = data.get('end_datetime')
        
        if not title:
            return Response({"success": False, "detail": "عنوان کارزار الزامی است."}, status=400)
        
        if len(title) < 3:
            return Response({"success": False, "detail": "عنوان کارزار باید حداقل 3 کاراکتر باشد."}, status=400)
        
        if len(title) > 255:
            return Response({"success": False, "detail": "عنوان کارزار خیلی طولانی است."}, status=400)
        
        if not description:
            return Response({"success": False, "detail": "توضیحات کارزار الزامی است."}, status=400)
        
        if len(description) < 10:
            return Response({"success": False, "detail": "توضیحات کارزار باید حداقل 10 کاراکتر باشد."}, status=400)
        
        if not end_datetime:
            return Response({"success": False, "detail": "تاریخ پایان الزامی است."}, status=400)
        
        try:
            serializer = PendingCampaignSerializer(data=data)
            if serializer.is_valid():
                if serializer.validated_data['end_datetime'] <= timezone.now():
                    return Response({"success": False, "detail": "تاریخ پایان باید بعد از اکنون باشد."}, status=400)
                campaign = serializer.save(status="pending")
                return Response({
                    "success": True,
                    "campaignId": campaign.id,
                    "status": campaign.status,
                    "created_at": campaign.created_at,
                    "end_datetime": campaign.end_datetime
                })
            return Response(serializer.errors, status=400)
        except Exception as e:
            security_logger.error(f'Campaign submission error: {str(e)} - User: {request.user.email} - IP: {request.META.get("REMOTE_ADDR", "unknown")}')
            return Response({"success": False, "detail": "خطا در ثبت کارزار"}, status=500)

class ApprovedCampaignsView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]
    def get(self, request):
        user = getattr(request, 'user', None)
        all_labels = list(PendingCampaign.objects.filter(status="approved").values_list('label', flat=True))
        allowed_labels = None
        # اگر کاربر authenticated است
        if user and hasattr(user, 'is_authenticated') and user.is_authenticated:
            # اگر نقش ادمین دارد، همه را ببیند
            if hasattr(user, 'role') and user.role in ["superadmin", "head", "center_member"]:
                campaigns = PendingCampaign.objects.filter(status="approved")
            else:
                allowed_labels = []
                if hasattr(user, 'faculty') and user.faculty and user.faculty != "نامشخص":
                    allowed_labels.append(user.faculty.strip().lower())
                allowed_labels.append('مسائل دانشگاهی'.strip().lower())
                if hasattr(user, 'dormitory') and user.dormitory and user.dormitory != 'خوابگاهی نیستم':
                    allowed_labels.append(user.dormitory.strip().lower())
                all_campaigns = PendingCampaign.objects.filter(status="approved")
                campaigns = [c for c in all_campaigns if c.label and c.label.strip().lower() in allowed_labels]
        else:
            # anonymous user: فقط مسائل دانشگاهی
            campaigns = PendingCampaign.objects.filter(status="approved", label='مسائل دانشگاهی')
        serializer = PendingCampaignSerializer(campaigns, many=True)
        return Response({
            "success": True,
            "campaigns": serializer.data,
            "total": len(serializer.data),
            "debug_user_faculty": getattr(user, 'faculty', None),
            "debug_user_dormitory": getattr(user, 'dormitory', None),
            "debug_all_labels": all_labels,
            "debug_allowed_labels": allowed_labels,
            "debug_user_role": getattr(user, 'role', None),
            "debug_is_authenticated": getattr(user, 'is_authenticated', None),
        })

class RejectedCampaignsView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        campaigns = PendingCampaign.objects.filter(status="rejected")
        serializer = PendingCampaignSerializer(campaigns, many=True)
        return Response({"success": True, "campaigns": serializer.data, "total": len(serializer.data)})

class PendingCampaignsAdminView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        if request.user.role not in ["superadmin", "head", "center_member"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        campaigns = PendingCampaign.objects.filter(status="pending")
        serializer = PendingCampaignSerializer(campaigns, many=True)
        return Response({"success": True, "campaigns": serializer.data, "total": len(serializer.data)})

class ApproveCampaignView(APIView):
    """
    Approve or reject a pending campaign
    
    Admin endpoint to approve/reject campaigns.
    Requires admin role (superadmin, head, center_member).
    """
    permission_classes = [IsAuthenticated]
    def post(self, request):
        if request.user.role not in ["superadmin", "head", "center_member"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        campaign_id = request.data.get('campaign_id')
        approved = request.data.get('approved')
        if campaign_id is None or approved is None:
            return Response({"success": False, "detail": "campaign_id و approved الزامی است."}, status=400)
        try:
            campaign = PendingCampaign.objects.get(id=campaign_id)
        except PendingCampaign.DoesNotExist:
            return Response({"success": False, "detail": "Campaign not found"}, status=404)
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
        if request.user.role not in ["superadmin", "head", "center_member"]:
            return Response({"success": False, "detail": "دسترسی ندارید."}, status=403)
        status_val = request.data.get('status')
        approved = request.data.get('approved')
        try:
            campaign = PendingCampaign.objects.get(id=campaign_id)
        except PendingCampaign.DoesNotExist:
            return Response({"success": False, "detail": "کارزار یافت نشد"}, status=404)
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

# --- Signature Endpoints ---

class SignCampaignView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, campaign_id):
        from .models import PendingCampaign
        try:
            campaign = PendingCampaign.objects.get(id=campaign_id)
        except PendingCampaign.DoesNotExist:
            return Response({"success": False, "detail": "کارزار یافت نشد"}, status=404)
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
        from .models import PendingCampaign
        try:
            campaign = PendingCampaign.objects.get(id=campaign_id)
        except PendingCampaign.DoesNotExist:
            return Response({"success": False, "detail": "کارزار یافت نشد"}, status=404)
        if campaign.is_anonymous == "anonymous":
            total_signatures = CampaignSignature.objects.filter(campaign_id=campaign_id).count()
            return Response({
                "success": True,
                "signatures": [],
                "total": total_signatures,
                "campaign_is_anonymous": "anonymous"
            })
        signatures = CampaignSignature.objects.filter(campaign_id=campaign_id)
        signature_list = [
            {
                "id": s.id,
                "user_email": s.user_email if s.is_anonymous == "public" else "ناشناس",
                "signed_at": s.signed_at,
                "is_anonymous": s.is_anonymous
            } for s in signatures
        ]
        return Response({
            "success": True,
            "signatures": signature_list,
            "total": len(signature_list),
            "campaign_is_anonymous": campaign.is_anonymous
        })

class CheckUserSignatureView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, campaign_id):
        from .models import PendingCampaign
        try:
            campaign = PendingCampaign.objects.get(id=campaign_id)
        except PendingCampaign.DoesNotExist:
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
    """
    Get single blog post by slug
    
    Returns detailed blog post information.
    Public endpoint - no authentication required.
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, slug):
        try:
            post = BlogPost.objects.get(slug=slug, is_published=True)
            serializer = BlogPostSerializer(post)
            return Response(serializer.data)
        except BlogPost.DoesNotExist:
            return Response({"detail": "Blog post not found"}, status=404)
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class BlogPostCreateView(APIView):
    """
    Create new blog post
    
    Creates a new blog post. Only superadmin can create posts.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        if request.user.role != 'superadmin':
            return Response({"detail": "Only superadmin can create blog posts"}, status=403)
        
        try:
            serializer = BlogPostSerializer(data=request.data)
            if serializer.is_valid():
                # Set author to current user
                serializer.save(author=request.user)
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class BlogPostUpdateView(APIView):
    """
    Update blog post
    
    Updates an existing blog post. Only superadmin can update posts.
    """
    permission_classes = [IsAuthenticated]
    
    def put(self, request, post_id):
        if request.user.role != 'superadmin':
            return Response({"detail": "Only superadmin can update blog posts"}, status=403)
        
        try:
            post = BlogPost.objects.get(id=post_id)
            serializer = BlogPostSerializer(post, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        except BlogPost.DoesNotExist:
            return Response({"detail": "Blog post not found"}, status=404)
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class BlogPostDeleteView(APIView):
    """
    Delete blog post
    
    Deletes a blog post. Only superadmin can delete posts.
    """
    permission_classes = [IsAuthenticated]
    
    def delete(self, request, post_id):
        if request.user.role != 'superadmin':
            return Response({"detail": "Only superadmin can delete blog posts"}, status=403)
        
        try:
            post = BlogPost.objects.get(id=post_id)
            post.delete()
            return Response({"detail": "Blog post deleted successfully"})
        except BlogPost.DoesNotExist:
            return Response({"detail": "Blog post not found"}, status=404)
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class BlogPostAdminListView(APIView):
    """
    Get all blog posts for admin management
    
    Returns all blog posts (published and unpublished) for admin management.
    Only superadmin can access.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if request.user.role != 'superadmin':
            return Response({"detail": "Only superadmin can access admin blog list"}, status=403)
        
        try:
            posts = BlogPost.objects.all().order_by('-created_at')
            serializer = BlogPostSerializer(posts, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"detail": str(e)}, status=500)

class BlogPostPublishView(APIView):
    """
    Publish or unpublish blog post
    
    Toggles the published status of a blog post.
    Only superadmin can publish/unpublish posts.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request, post_id):
        if request.user.role != 'superadmin':
            return Response({"detail": "Only superadmin can publish/unpublish blog posts"}, status=403)
        
        try:
            post = BlogPost.objects.get(id=post_id)
            post.is_published = not post.is_published
            
            if post.is_published and not post.published_at:
                post.published_at = timezone.now()
            
            post.save()
            serializer = BlogPostSerializer(post)
            return Response(serializer.data)
        except BlogPost.DoesNotExist:
            return Response({"detail": "Blog post not found"}, status=404)
        except Exception as e:
            return Response({"detail": str(e)}, status=500)
