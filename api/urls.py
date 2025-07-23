from django.urls import path
from .views import (
    RegisterView, LoginView, UserInfoView, RefreshTokenView, check_email, send_verification_code, verify_code, test_email_config,
    SubmitCampaignView, ApprovedCampaignsView, RejectedCampaignsView, PendingCampaignsAdminView, ApproveCampaignView, UpdateCampaignStatusView,
    SignCampaignView, CampaignSignaturesView, CheckUserSignatureView, UserSignedCampaignsView, UserIdSignedCampaignsView,
    UserListView, UserDetailView, UpdateUserRoleView, ValidateTokenView,
    PerformanceSummaryView, EndpointPerformanceView, SlowRequestsView, SystemMetricsView,
    BlogPostListView, BlogPostDetailView, BlogPostCreateView, BlogPostUpdateView, BlogPostDeleteView, 
    BlogPostAdminListView, BlogPostPublishView, CampaignDetailView, DeleteCampaignView,
    CampaignCategoryChoicesView,
    PollListCreateView, PollDetailView, PollVoteView, PollResultsView, PollVotersView, PollAdminListView, PollApproveRejectView, PollDeleteView,
    PollStatusUpdateView,
)

urlpatterns = [
    path('auth/register', RegisterView.as_view(), name='register'),
    path('auth/login', LoginView.as_view(), name='login'),
    path('auth/refresh', RefreshTokenView.as_view(), name='refresh-token'),
    path('auth/user', UserInfoView.as_view(), name='user-info'),
    path('auth/check-email', check_email, name='check-email'),
    path('auth/send-code', send_verification_code, name='send-code'),
    path('auth/verify-code', verify_code, name='verify-code'),
    path('auth/test-email', test_email_config, name='test-email-config'),
    path('auth/validate', ValidateTokenView.as_view(), name='validate-token'),

    path('campaigns/submit', SubmitCampaignView.as_view(), name='submit-campaign'),
    path('campaigns/approved', ApprovedCampaignsView.as_view(), name='approved-campaigns'),
    path('campaigns/rejected', RejectedCampaignsView.as_view(), name='rejected-campaigns'),
    path('admin/campaigns', PendingCampaignsAdminView.as_view(), name='pending-campaigns-admin'),
    path('admin/campaigns/approve', ApproveCampaignView.as_view(), name='approve-campaign'),
    path('campaigns/<int:campaign_id>/status', UpdateCampaignStatusView.as_view(), name='update-campaign-status'),
    path('campaigns/<int:campaign_id>', CampaignDetailView.as_view(), name='campaign-detail'),
    path('campaigns/<int:campaign_id>/delete', DeleteCampaignView.as_view(), name='delete-campaign'),
    path('campaigns/categories', CampaignCategoryChoicesView.as_view(), name='campaign-category-choices'),

    path('campaigns/<int:campaign_id>/sign', SignCampaignView.as_view(), name='sign-campaign'),
    path('campaigns/<int:campaign_id>/signatures', CampaignSignaturesView.as_view(), name='campaign-signatures'),
    path('campaigns/<int:campaign_id>/check-signature', CheckUserSignatureView.as_view(), name='check-user-signature'),
    path('user/signed-campaigns', UserSignedCampaignsView.as_view(), name='user-signed-campaigns'),
    path('user/<int:user_id>/signed-campaigns', UserIdSignedCampaignsView.as_view(), name='user-id-signed-campaigns'),

    path('auth/users', UserListView.as_view(), name='user-list'),
    path('auth/user/<int:user_id>', UserDetailView.as_view(), name='user-detail'),
    path('user/<int:user_id>/role', UpdateUserRoleView.as_view(), name='update-user-role'),
    
    # Performance monitoring endpoints
    path('performance/summary', PerformanceSummaryView.as_view(), name='performance-summary'),
    path('performance/endpoints', EndpointPerformanceView.as_view(), name='endpoint-performance'),
    path('performance/endpoints/<str:endpoint>', EndpointPerformanceView.as_view(), name='endpoint-performance-detail'),
    path('performance/slow-requests', SlowRequestsView.as_view(), name='slow-requests'),
    path('performance/system-metrics', SystemMetricsView.as_view(), name='system-metrics'),
    
    # Blog endpoints
    path('blog/posts', BlogPostListView.as_view(), name='blog-posts'),
    path('blog/posts/<str:slug>', BlogPostDetailView.as_view(), name='blog-post-detail'),
    path('admin/blog/posts', BlogPostAdminListView.as_view(), name='admin-blog-posts'),
    path('admin/blog/posts/create', BlogPostCreateView.as_view(), name='create-blog-post'),
    path('admin/blog/posts/<int:post_id>', BlogPostUpdateView.as_view(), name='update-blog-post'),
    path('admin/blog/posts/<int:post_id>/delete', BlogPostDeleteView.as_view(), name='delete-blog-post'),
    path('admin/blog/posts/<int:post_id>/publish', BlogPostPublishView.as_view(), name='publish-blog-post'),

    # Poll endpoints
    path('polls', PollListCreateView.as_view(), name='poll-list-create'),
    path('polls/<int:poll_id>', PollDetailView.as_view(), name='poll-detail'),
    path('polls/<int:poll_id>/vote', PollVoteView.as_view(), name='poll-vote'),
    path('polls/<int:poll_id>/results', PollResultsView.as_view(), name='poll-results'),
    path('polls/<int:poll_id>/voters', PollVotersView.as_view(), name='poll-voters'),
    path('admin/polls', PollAdminListView.as_view(), name='poll-admin-list'),
    path('admin/polls/approve', PollApproveRejectView.as_view(), name='poll-approve-reject'),
    path('polls/<int:poll_id>/delete', PollDeleteView.as_view(), name='poll-delete'),
    path('polls/<int:poll_id>/status', PollStatusUpdateView.as_view(), name='update-poll-status'),
] 