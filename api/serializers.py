from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Campaign, CampaignSignature, BlogPost, Poll, PollOption, PollVote, PollParticipation

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'role', 'unit', 'faculty', 'dormitory', 'council_member_status']

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
        email = User.objects.normalize_email(validated_data['email'])
        user = User.objects.create_user(
            email=email,
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

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
    
    def create(self, validated_data):
        """Create blog post - slug will be auto-generated in model save method"""
        return super().create(validated_data)
    
    class Meta:
        model = BlogPost
        fields = [
            'id', 'title', 'slug', 'content', 'excerpt', 'tags', 'category',
            'image_url', 'is_published', 'created_at', 'updated_at', 
            'published_at', 'reading_time', 'author', 'author_email', 'author_name'
        ]
        read_only_fields = ['created_at', 'updated_at', 'author']
        extra_kwargs = {
            'slug': {'required': False, 'allow_blank': True}
        }

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

class CampaignSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source='author.email', read_only=True)
    author_faculty = serializers.CharField(source='author.faculty', read_only=True)
    author_dormitory = serializers.CharField(source='author.dormitory', read_only=True)
    tags = serializers.SerializerMethodField()
    signature_count = serializers.SerializerMethodField()
    has_signed = serializers.SerializerMethodField()

    def get_tags(self, obj):
        return obj.get_tags_list()
    def get_signature_count(self, obj):
        return obj.signature_count()
    def get_has_signed(self, obj):
        user = self.context.get('request').user if self.context.get('request') else None
        if user and user.is_authenticated:
            return obj.has_signed(user)
        return False

    class Meta:
        model = Campaign
        fields = [
            'id', 'title', 'slug', 'content', 'excerpt', 'tags', 'category',
            'image_url', 'is_published', 'created_at', 'updated_at', 'published_at',
            'deadline', 'author', 'author_email', 'author_faculty', 'author_dormitory', 'status', 'anonymous_allowed',
            'signature_count', 'has_signed'
        ]
        read_only_fields = ['created_at', 'updated_at', 'author', 'signature_count', 'has_signed']
        extra_kwargs = {
            'slug': {'required': False, 'allow_blank': True}
        }

class CampaignListSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source='author.email', read_only=True)
    author_faculty = serializers.CharField(source='author.faculty', read_only=True)
    author_dormitory = serializers.CharField(source='author.dormitory', read_only=True)
    tags = serializers.SerializerMethodField()
    signature_count = serializers.SerializerMethodField()

    def get_tags(self, obj):
        return obj.get_tags_list()
    def get_signature_count(self, obj):
        return obj.signature_count()

    class Meta:
        model = Campaign
        fields = [
            'id', 'title', 'slug', 'excerpt', 'tags', 'category',
            'image_url', 'is_published', 'created_at', 'published_at',
            'deadline', 'author_email', 'author_faculty', 'author_dormitory', 'status', 'anonymous_allowed',
            'signature_count'
        ]
        read_only_fields = ['created_at', 'author_email', 'signature_count'] 

class PollOptionSerializer(serializers.ModelSerializer):
    votes_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = PollOption
        fields = ['id', 'text', 'order', 'votes_count']

class PollVoteSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = PollVote
        fields = ['id', 'poll', 'option', 'user', 'user_email', 'voted_at']

class PollParticipationSerializer(serializers.ModelSerializer):
    class Meta:
        model = PollParticipation
        fields = ['id', 'user', 'poll', 'participated_at']

class PollSerializer(serializers.ModelSerializer):
    author_email = serializers.EmailField(source='author.email', read_only=True)
    options = PollOptionSerializer(many=True)
    total_votes = serializers.IntegerField(read_only=True)
    has_voted = serializers.SerializerMethodField()
    max_choices = serializers.IntegerField(required=False, allow_null=True)

    def get_has_voted(self, obj):
        user = self.context.get('request').user if self.context.get('request') else None
        if user and user.is_authenticated:
            result = obj.participations.filter(user=user).exists()
            return result
        return False

    def create(self, validated_data):
        options_data = validated_data.pop('options')
        max_choices = validated_data.pop('max_choices', None)
        poll = Poll.objects.create(max_choices=max_choices, **validated_data)
        for idx, option_data in enumerate(options_data):
            PollOption.objects.create(poll=poll, order=idx, **option_data)
        return poll

    def update(self, instance, validated_data):
        options_data = validated_data.pop('options', None)
        max_choices = validated_data.pop('max_choices', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if max_choices is not None:
            instance.max_choices = max_choices
        if 'category' in validated_data:
            instance.category = validated_data['category']
        instance.save()
        if options_data is not None:
            instance.options.all().delete()
            for idx, option_data in enumerate(options_data):
                PollOption.objects.create(poll=instance, order=idx, **option_data)
        return instance

    class Meta:
        model = Poll
        fields = [
            'id', 'title', 'slug', 'description', 'is_anonymous', 'is_multiple_choice',
            'max_choices',
            'category',
            'image_url', 'created_at', 'updated_at', 'deadline', 'author', 'author_email',
            'status', 'options', 'total_votes', 'has_voted'
        ]
        read_only_fields = ['created_at', 'updated_at', 'author', 'author_email', 'total_votes', 'has_voted']
        extra_kwargs = {
            'slug': {'required': False, 'allow_blank': True}
        } 