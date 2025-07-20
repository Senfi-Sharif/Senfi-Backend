from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import PendingCampaign, CampaignSignature, BlogPost

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'role', 'unit', 'faculty', 'dormitory']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        help_text='رمز عبور باید حداقل 8 کاراکتر باشد و شامل حروف بزرگ، کوچک، اعداد و کاراکترهای خاص باشد.'
    )
    
    class Meta:
        model = User
        fields = ['email', 'password']
    
    def validate_password(self, value):
        # Import here to avoid circular imports
        from .validators import PasswordComplexityValidator
        validator = PasswordComplexityValidator()
        validator.validate(value)
        return value
    
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class PendingCampaignSerializer(serializers.ModelSerializer):
    class Meta:
        model = PendingCampaign
        fields = ['id', 'title', 'description', 'email', 'created_at', 'status', 'is_anonymous', 'end_datetime', 'label']

class CampaignSignatureSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)
    class Meta:
        model = CampaignSignature
        fields = ['id', 'campaign', 'user', 'user_email', 'signed_at', 'is_anonymous']

class BlogPostSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source='author.email', read_only=True)
    author_name = serializers.CharField(source='author.email', read_only=True)
    tags = serializers.SerializerMethodField()
    
    def get_tags(self, obj):
        """Return tags as a list"""
        return obj.get_tags_list()
    
    def validate_slug(self, value):
        """Validate slug format"""
        import re
        if not re.match(r'^[a-z0-9_-]+$', value):
            raise serializers.ValidationError(
                'Slug must contain only lowercase letters, numbers, hyphens, and underscores.'
            )
        return value
    
    class Meta:
        model = BlogPost
        fields = [
            'id', 'title', 'slug', 'content', 'excerpt', 'tags', 'category',
            'image_url', 'is_published', 'created_at', 'updated_at', 
            'published_at', 'reading_time', 'author', 'author_email', 'author_name'
        ]
        read_only_fields = ['created_at', 'updated_at', 'author']

class BlogPostListSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source='author.email', read_only=True)
    tags = serializers.SerializerMethodField()
    
    def get_tags(self, obj):
        """Return tags as a list"""
        return obj.get_tags_list()
    
    class Meta:
        model = BlogPost
        fields = [
            'id', 'title', 'slug', 'excerpt', 'tags', 'category',
            'image_url', 'is_published', 'created_at', 'published_at', 
            'reading_time', 'author_email'
        ] 