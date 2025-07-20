#!/usr/bin/env python3
"""
Script to fix blog post tags format
"""

import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'senfi_django_backend.settings')
django.setup()

from api.models import BlogPost

def fix_blog_post_tags():
    """Fix the format of blog post tags"""
    
    try:
        # Get all blog posts
        blog_posts = BlogPost.objects.all()
        
        for post in blog_posts:
            print(f"Processing post: {post.title}")
            print(f"Current tags: {post.tags}")
            
            # Get tags as list using the new method
            tags_list = post.get_tags_list()
            print(f"Parsed tags: {tags_list}")
            
            # Set tags back as comma-separated string
            if tags_list:
                post.tags = ', '.join(tags_list)
                post.save()
                print(f"Fixed tags: {post.tags}")
            else:
                print("No tags to fix")
            
            print("-" * 50)
        
        print("✅ All blog post tags have been fixed!")
        return True
        
    except Exception as e:
        print(f"❌ Error fixing blog post tags: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Fixing blog post tags...")
    success = fix_blog_post_tags()
    if success:
        print("✅ Done!")
    else:
        print("❌ Failed!")
        sys.exit(1) 