from django.contrib import admin
from .models import User, Campaign, CampaignSignature, BlogPost, Poll, PollOption, PollVote, PollParticipation

admin.site.register(User)
admin.site.register(Campaign)
admin.site.register(CampaignSignature)
admin.site.register(PollParticipation)

@admin.register(Poll)
class PollAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'is_anonymous', 'is_multiple_choice', 'status', 'author', 'created_at', 'deadline')
    list_filter = ('status', 'is_anonymous', 'is_multiple_choice', 'category', 'created_at')
    search_fields = ('title', 'description', 'author__email')
    prepopulated_fields = {'slug': ('title',)}
    readonly_fields = ('created_at', 'updated_at', 'total_votes')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('اطلاعات اصلی', {
            'fields': ('title', 'slug', 'description', 'category')
        }),
        ('تنظیمات رأی‌گیری', {
            'fields': ('is_anonymous', 'is_multiple_choice', 'max_choices')
        }),
        ('تنظیمات انتشار', {
            'fields': ('status', 'deadline', 'author')
        }),
        ('تنظیمات اضافی', {
            'fields': ('image_url',)
        }),
        ('آمار', {
            'fields': ('total_votes', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(PollOption)
class PollOptionAdmin(admin.ModelAdmin):
    list_display = ('text', 'poll', 'order', 'votes_count')
    list_filter = ('poll', 'order')
    search_fields = ('text', 'poll__title')
    ordering = ('poll', 'order')

@admin.register(PollVote)
class PollVoteAdmin(admin.ModelAdmin):
    list_display = ('poll', 'option', 'user', 'voted_at')
    list_filter = ('poll', 'voted_at')
    search_fields = ('poll__title', 'option__text', 'user__email')
    readonly_fields = ('voted_at',)
    ordering = ('-voted_at',)

@admin.register(BlogPost)
class BlogPostAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'category', 'is_published', 'created_at', 'published_at')
    list_filter = ('is_published', 'category', 'created_at', 'published_at')
    search_fields = ('title', 'content', 'excerpt')
    prepopulated_fields = {'slug': ('title',)}
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('اطلاعات اصلی', {
            'fields': ('title', 'slug', 'content', 'excerpt')
        }),
        ('دسته‌بندی و برچسب‌ها', {
            'fields': ('category', 'tags')
        }),
        ('تنظیمات انتشار', {
            'fields': ('is_published', 'published_at', 'author')
        }),
        ('تنظیمات اضافی', {
            'fields': ('image_url', 'reading_time')
        }),
        ('تاریخ‌ها', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
