from django.contrib import admin
from .models import User, PendingCampaign, CampaignSignature

admin.site.register(User)
admin.site.register(PendingCampaign)
admin.site.register(CampaignSignature)
