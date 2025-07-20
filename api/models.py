from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
import re

def validate_sharif_email(value):
    """Validate that email ends with @sharif.edu"""
    if not value.lower().endswith('@sharif.edu'):
        raise ValidationError('Email must end with @sharif.edu')

def validate_no_special_chars(value):
    """Validate that text doesn't contain special characters"""
    if re.search(r'[<>{}[\]]', value):
        raise ValidationError('Text contains invalid special characters')

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, role="simple_user", unit=None):
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, role=role, unit=unit)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):
        user = self.create_user(email, password, role="superadmin")
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

FACULTY_CHOICES = [
    ("فیزیک", "فیزیک"),
    ("صنایع", "صنایع"),
    ("کامپیوتر", "کامپیوتر"),
    ("برق", "برق"),
    ("عمران", "عمران"),
    ("مواد", "مواد"),
    ("مهندسی شیمی و نفت", "مهندسی شیمی و نفت"),
    ("ریاضی", "ریاضی"),
    ("هوافضا", "هوافضا"),
    ("انرژی", "انرژی"),
    ("مدیریت و اقتصاد", "مدیریت و اقتصاد"),
    ("شیمی", "شیمی"),
    ("مکانیک", "مکانیک"),
]
DORMITORY_CHOICES = [
    ("احمدی روشن", "احمدی روشن"),
    ("طرشت ۲", "طرشت ۲"),
    ("طرشت ۳", "طرشت ۳"),
    ("خوابگاهی نیستم", "خوابگاهی نیستم"),
]

CAMPAIGN_LABEL_CHOICES = [
    ("مسائل دانشگاهی", "مسائل دانشگاهی"),
] + FACULTY_CHOICES + DORMITORY_CHOICES

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=32, default="simple_user")
    unit = models.CharField(max_length=64, null=True, blank=True)
    faculty = models.CharField(max_length=64, choices=FACULTY_CHOICES, default="نامشخص")  # دانشکده (اجباری)
    dormitory = models.CharField(max_length=64, choices=DORMITORY_CHOICES, null=True, blank=True, default="خوابگاهی نیستم")  # خوابگاه (می‌تواند null باشد)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

class PendingCampaign(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    email = models.EmailField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=32, default="pending")
    is_anonymous = models.CharField(max_length=16, default="public")
    end_datetime = models.DateTimeField()
    label = models.CharField(max_length=64, choices=CAMPAIGN_LABEL_CHOICES, default="مسائل دانشگاهی")

    def __str__(self):
        return self.title

class CampaignSignature(models.Model):
    campaign = models.ForeignKey(PendingCampaign, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user_email = models.EmailField()
    signed_at = models.DateTimeField(auto_now_add=True)
    is_anonymous = models.CharField(max_length=16, default="public")

    def __str__(self):
        # campaign is a ForeignKey, so access .campaign (Django resolves to object)
        return f"{self.user_email} signed {self.campaign}"  # campaign.__str__ returns title
