from django.contrib import admin
from .models import User, PendingCampaign, CampaignSignature, BlogPost

admin.site.register(User)
admin.site.register(PendingCampaign)
admin.site.register(CampaignSignature)

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
