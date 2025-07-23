from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
import re
from .choices import CAMPAIGN_CATEGORY_CHOICES, FACULTY_CHOICES, DORMITORY_CHOICES, CAMPAIGN_LABEL_CHOICES, USER_ROLE_CHOICES
from .choices import POLL_CATEGORY_CHOICES

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
        email = self.normalize_email(email)
        user = self.create_user(email, password, role="superadmin")
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=32, choices=USER_ROLE_CHOICES, default="simple_user")
    unit = models.CharField(max_length=64, null=True, blank=True)
    faculty = models.CharField(max_length=64, choices=FACULTY_CHOICES, default="نامشخص")  # دانشکده (اجباری)
    dormitory = models.CharField(max_length=64, choices=DORMITORY_CHOICES, null=True, blank=True, default="خوابگاهی نیستم")  # خوابگاه (می‌تواند null باشد)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    COUNCIL_MEMBER_CHOICES = [
        ('member', 'عضو'),
        ('observer', 'عضو بدون حق رای'),
        ('none', 'غیرعضو'),
    ]
    council_member_status = models.CharField(max_length=16, choices=COUNCIL_MEMBER_CHOICES, default='none', verbose_name='عضویت شورای عمومی')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        self.email = self.__class__.objects.normalize_email(self.email)
        super().save(*args, **kwargs)

class Campaign(models.Model):
    STATUS_CHOICES = [
        ('pending', 'در انتظار تایید'),
        ('approved', 'تایید شده'),
        ('rejected', 'رد شده'),
        ('closed', 'بسته شده'),
    ]
    CATEGORY_CHOICES = CAMPAIGN_CATEGORY_CHOICES
    title = models.CharField(max_length=255, verbose_name='عنوان')
    slug = models.SlugField(max_length=255, unique=True, blank=True, verbose_name='نامک')
    content = models.TextField(verbose_name='متن کامل')
    excerpt = models.TextField(max_length=500, blank=True, verbose_name='خلاصه')
    tags = models.TextField(blank=True, verbose_name='برچسب‌ها')
    category = models.CharField(max_length=64, choices=CATEGORY_CHOICES, default='مسائل دانشگاهی', verbose_name='دسته‌بندی')
    image_url = models.URLField(blank=True, null=True, verbose_name='آدرس تصویر')
    is_published = models.BooleanField(default=False, verbose_name='منتشر شده')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاریخ ایجاد')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='تاریخ بروزرسانی')
    published_at = models.DateTimeField(null=True, blank=True, verbose_name='تاریخ انتشار')
    deadline = models.DateTimeField(verbose_name='ددلاین')
    author = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='سازنده')
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='pending', verbose_name='وضعیت')
    anonymous_allowed = models.BooleanField(default=True, verbose_name='امضای ناشناس مجاز است؟')

    class Meta:
        verbose_name = 'کارزار'
        verbose_name_plural = 'کارزارها'
        ordering = ['-created_at']

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            from django.utils import timezone
            base_slug = slugify(self.title, allow_unicode=True)
            timestamp = str(int(timezone.now().timestamp()))
            self.slug = f"{base_slug}-{timestamp}"
        super().save(*args, **kwargs)

    def get_tags_list(self):
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',') if tag.strip()]
        return []

    def set_tags_list(self, tags_list):
        self.tags = ', '.join(tags_list)

    def signature_count(self):
        return self.campaignsignatures.count()

    def has_signed(self, user):
        return self.campaignsignatures.filter(user=user).exists()

class CampaignSignature(models.Model):
    campaign = models.ForeignKey(Campaign, on_delete=models.CASCADE, related_name='campaignsignatures')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user_email = models.EmailField()
    signed_at = models.DateTimeField(auto_now_add=True)
    is_anonymous = models.CharField(max_length=16, default="public")

    def __str__(self):
        return f"{self.user_email} signed {self.campaign}"  # campaign.__str__ returns title

class BlogPost(models.Model):
    CATEGORY_CHOICES = [
        ('اخبار', 'اخبار'),
        ('مقالات', 'مقالات'),
        ('گزارش‌ها', 'گزارش‌ها'),
        ('اطلاعیه‌ها', 'اطلاعیه‌ها'),
        ('داستان‌های دانشجویی', 'داستان‌های دانشجویی'),
        ('سایر', 'سایر'),
    ]
    
    title = models.CharField(max_length=255, verbose_name='عنوان')
    slug = models.SlugField(max_length=255, unique=True, blank=True, verbose_name='نامک')
    content = models.TextField(verbose_name='محتوای اصلی')
    excerpt = models.TextField(max_length=500, blank=True, verbose_name='خلاصه')
    tags = models.TextField(blank=True, verbose_name='برچسب‌ها')  # Stored as comma-separated values
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='سایر', verbose_name='دسته‌بندی')
    image_url = models.URLField(blank=True, null=True, verbose_name='آدرس تصویر')
    is_published = models.BooleanField(default=False, verbose_name='منتشر شده')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاریخ ایجاد')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='تاریخ بروزرسانی')
    published_at = models.DateTimeField(null=True, blank=True, verbose_name='تاریخ انتشار')
    reading_time = models.IntegerField(default=0, verbose_name='زمان مطالعه (دقیقه)')
    author = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='نویسنده')
    
    class Meta:
        verbose_name = 'مطلب بلاگ'
        verbose_name_plural = 'مطالب بلاگ'
        ordering = ['-created_at']
    
    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        # Auto-generate slug if not provided
        if not self.slug:
            import re
            from django.utils.text import slugify
            from django.utils import timezone
            
            # Create base slug from title
            base_slug = slugify(self.title, allow_unicode=True)
            
            # Add timestamp to make it unique
            timestamp = str(int(timezone.now().timestamp()))
            self.slug = f"{base_slug}-{timestamp}"
        
        # Calculate reading time (rough estimate: 200 words per minute)
        if self.content:
            word_count = len(self.content.split())
            self.reading_time = max(1, word_count // 200)
        
        super().save(*args, **kwargs)
    
    def get_tags_list(self):
        """Return tags as a list"""
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',') if tag.strip()]
        return []
    
    def set_tags_list(self, tags_list):
        """Set tags from a list"""
        self.tags = ', '.join(tags_list)

# --- Poll Models ---
class Poll(models.Model):
    STATUS_CHOICES = [
        ('pending', 'در انتظار تایید'),
        ('approved', 'تایید شده'),
        ('rejected', 'رد شده'),
        ('closed', 'بسته شده'),
    ]
    title = models.CharField(max_length=255, verbose_name='عنوان')
    slug = models.SlugField(max_length=255, unique=True, blank=True, verbose_name='نامک')
    description = models.TextField(verbose_name='توضیحات')
    is_anonymous = models.BooleanField(default=True, verbose_name='رأی مخفی')
    is_multiple_choice = models.BooleanField(default=False, verbose_name='چندگزینه‌ای')
    max_choices = models.IntegerField(null=True, blank=True, help_text='حداکثر تعداد انتخاب مجاز برای رأی‌دهنده (در حالت چندگزینه‌ای). اگر خالی باشد، نامحدود است.')
    category = models.CharField(max_length=64, choices=POLL_CATEGORY_CHOICES, default='مسائل دانشگاهی', verbose_name='دسته‌بندی')
    image_url = models.URLField(blank=True, null=True, verbose_name='آدرس تصویر')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='تاریخ ایجاد')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='تاریخ بروزرسانی')
    deadline = models.DateTimeField(verbose_name='ددلاین')
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='pending', verbose_name='وضعیت')
    author = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='سازنده')

    class Meta:
        verbose_name = 'نظرسنجی'
        verbose_name_plural = 'نظرسنجی‌ها'
        ordering = ['-created_at']

    def __str__(self):
        return self.title

    def is_expired(self):
        from django.utils import timezone
        return self.deadline < timezone.now()

    @property
    def total_votes(self):
        return self.votes.count()

    def save(self, *args, **kwargs):
        if not self.slug:
            from django.utils.text import slugify
            from django.utils import timezone
            base_slug = slugify(self.title, allow_unicode=True)
            timestamp = str(int(timezone.now().timestamp()))
            self.slug = f"{base_slug}-{timestamp}"
        super().save(*args, **kwargs)

class PollOption(models.Model):
    poll = models.ForeignKey(Poll, on_delete=models.CASCADE, related_name='options')
    text = models.CharField(max_length=255, verbose_name='متن گزینه')
    order = models.PositiveIntegerField(default=0, verbose_name='ترتیب')

    def __str__(self):
        return f"{self.text} ({self.poll.title})"

    @property
    def votes_count(self):
        return self.votes.count()

class PollParticipation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    poll = models.ForeignKey(Poll, on_delete=models.CASCADE, related_name='participations')
    participated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'poll')

    def __str__(self):
        return f"{self.user.email} participated in {self.poll.title}"

class PollVote(models.Model):
    poll = models.ForeignKey(Poll, on_delete=models.CASCADE, related_name='votes')
    option = models.ForeignKey(PollOption, on_delete=models.CASCADE, related_name='votes')
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, verbose_name='رأی‌دهنده')
    voted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.user:
            return f"{self.user.email} voted for {self.option.text} in {self.poll.title}"
        else:
            return f"Anonymous vote for {self.option.text} in {self.poll.title}"
