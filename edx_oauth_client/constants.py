"""
Constants for the operation of the module.
Keep immutable values here so as not to clog the namespace of OAuth backend and middleware layer.
"""

OAUTH_PROCESS_URLS = ("oauth2", "auth", "login_oauth_token", "social-logout", "login_refresh")
API_URLS = (
    "certificates",
    "api",
    "v1",
    "user_api",
    "notifier_api",
    "update_example_certificate",
    "update_certificate",
    "request_certificate",
    "heartbeat",
    "admin",
)

LOCAL_URLS = (
    "i18n",
    "search",
    "verify_student",
    "certificates",
    "jsi18n",
    "course_modes",
    "404",
    "500",
    "i18n.js",
    "wiki",
    "notify",
    "courses",
    "xblock",
    "change_setting",
    "account",
    "notification_prefs",
    "survey",
    "event",
    "instructor_task_status",
    "edinsights_service",
    "openassessment",
    "instructor_report",
    "logout",
)
