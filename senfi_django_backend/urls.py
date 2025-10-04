"""
URL configuration for senfi_django_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse, HttpResponseForbidden
from django.conf import settings
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

def api_root(request):
    return JsonResponse({
        "message": "Senfi Django Backend API",
        "version": "1.1.0",
        "endpoints": {
            "auth": "/auth/",
            "campaigns": "/campaigns/",
            "polls": "/polls/",
            "blog": "/blog/",
            "performance": "/performance/",
            "docs": "/docs/",
            "schema": "/schema/"
        }
    })

def admin_host_check(get_response):
    def middleware(request):
        if request.path.startswith('/admin/'):
            if not settings.DEBUG:
                allowed_host = getattr(settings, 'ADMIN_ALLOWED_HOST', None)
                if allowed_host and request.get_host() != allowed_host:
                    return HttpResponseForbidden("Access denied")
        return get_response(request)
    return middleware

urlpatterns = [
    path('', include([
        path('', api_root, name='api_root'),
        path('admin/', admin.site.urls),
        path('', include('api.urls')),
        path('schema/', SpectacularAPIView.as_view(), name='schema'),
        path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
        path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    ])),
]
