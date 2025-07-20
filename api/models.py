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

class BlogPost(models.Model):
    """Blog post model for the blog system"""
    CATEGORY_CHOICES = [
        ('اخبار', 'اخبار'),
        ('مقالات', 'مقالات'),
        ('آموزش', 'آموزش'),
        ('گزارش', 'گزارش'),
        ('مصاحبه', 'مصاحبه'),
        ('سایر', 'سایر'),
    ]
    
    title = models.CharField(max_length=255, verbose_name='عنوان')
    slug = models.SlugField(max_length=255, unique=True, verbose_name='نامک')
    content = models.TextField(verbose_name='محتوای اصلی')
    excerpt = models.TextField(max_length=500, blank=True, verbose_name='خلاصه')
    author = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='نویسنده')
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='سایر', verbose_name='دسته‌بندی')
    tags = models.CharField(max_length=500, blank=True, verbose_name='برچسب‌ها')
    image_url = models.URLField(blank=True, null=True, verbose_name='آدرس تصویر')
    is_published = models.BooleanField(default=False, verbose_name='منتشر شده')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاریخ ایجاد')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='تاریخ بروزرسانی')
    published_at = models.DateTimeField(null=True, blank=True, verbose_name='تاریخ انتشار')
    reading_time = models.IntegerField(default=5, verbose_name='زمان مطالعه (دقیقه)')
    
    class Meta:
        verbose_name = 'مطلب بلاگ'
        verbose_name_plural = 'مطالب بلاگ'
        ordering = ['-created_at']
    
    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        # Auto-generate slug if not provided
        if not self.slug:
            from django.utils.text import slugify
            self.slug = slugify(self.title)
        
        # Set published_at when publishing for the first time
        if self.is_published and not self.published_at:
            from django.utils import timezone
            self.published_at = timezone.now()
        
        super().save(*args, **kwargs)
    
    def get_tags_list(self):
        """Return tags as a list"""
        if not self.tags:
            return []
        
        # Handle different formats of tags
        tags_str = self.tags.strip()
        
        # If it looks like a JSON array, try to parse it
        if tags_str.startswith('[') and tags_str.endswith(']'):
            try:
                import json
                import ast
                # Try to parse as JSON first
                tags_list = json.loads(tags_str)
                if isinstance(tags_list, list):
                    return [str(tag).strip() for tag in tags_list if tag.strip()]
            except (json.JSONDecodeError, ValueError):
                try:
                    # Try to parse as Python literal
                    tags_list = ast.literal_eval(tags_str)
                    if isinstance(tags_list, list):
                        return [str(tag).strip() for tag in tags_list if tag.strip()]
                except (ValueError, SyntaxError):
                    pass
        
        # Fallback to comma-separated string
        return [tag.strip() for tag in tags_str.split(',') if tag.strip()]
    
    def set_tags_list(self, tags_list):
        """Set tags from a list"""
        self.tags = ', '.join(tags_list)
    
    @property
    def reading_time_text(self):
        """Return reading time as text"""
        if self.reading_time <= 1:
            return "کمتر از 1 دقیقه"
        elif self.reading_time < 60:
            return f"{self.reading_time} دقیقه"
        else:
            hours = self.reading_time // 60
            minutes = self.reading_time % 60
            if minutes == 0:
                return f"{hours} ساعت"
            else:
                return f"{hours} ساعت و {minutes} دقیقه"
