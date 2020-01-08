"""
Settings for OAUTH client by EDX
"""
from django.conf import settings


# Settings for OAuthRedirection middleware.
auth_process_urls = ('oauth2', 'auth', 'login_oauth_token', 'social-logout')
api_urls = (
    'certificates', 'api', 'user_api', 'notifier_api', 'update_example_certificate', 'update_certificate',
    'request_certificate',)

handle_local_urls = (
    'i18n', 'search', 'verify_student', 'certificates', 'jsi18n', 'course_modes', '404', '500', 'i18n.js',
    'wiki', 'notify', 'courses', 'xblock', 'change_setting', 'account', 'notification_prefs', 'admin',
    'survey', 'event', 'instructor_task_status', 'edinsights_service', 'openassessment', 'instructor_report',
    'logout', 'dashboard', 'course_run', 'change_enrollment', 'change_email_settings', 'sysadmin',
)

handle_local_urls += auth_process_urls + api_urls

if settings.DEBUG:
    debug_handle_local_urls = ('debug', settings.STATIC_URL, settings.MEDIA_URL)
    handle_local_urls += debug_handle_local_urls

CUSTOM_OAUTH_PARAMS = settings.CUSTOM_OAUTH_PARAMS if hasattr(settings, 'CUSTOM_OAUTH_PARAMS') else {}

LOCAL_URLS_DISABLED_FOR_REDIRECTION = tuple(CUSTOM_OAUTH_PARAMS.get("LOCAL_URLS_DISABLED_FOR_REDIRECTION", ()))
DISABLED_FOR_REDIRECTION_URLS = handle_local_urls + LOCAL_URLS_DISABLED_FOR_REDIRECTION

PROVIDER_URL = CUSTOM_OAUTH_PARAMS.get("PROVIDER_URL", "")
COURSES_LIST_URL_PATH = CUSTOM_OAUTH_PARAMS.get("COURSES_LIST_URL_PATH")
USER_ACCOUNT_URL_PATH = CUSTOM_OAUTH_PARAMS.get("USER_ACCOUNT_URL_PATH")
DASHBOARD_URL_PATH = CUSTOM_OAUTH_PARAMS.get("DASHBOARD_URL_PATH")
