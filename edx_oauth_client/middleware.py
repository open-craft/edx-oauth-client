import re
import os.path

from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME, logout
from django.shortcuts import redirect
from edx_oauth_client.backends.generic_oauth_client import GenericOAuthBackend

from social_django.views import auth, NAMESPACE

try:
    from opaque_keys.edx.keys import CourseKey
except ImportError:
    msg = "Oh, it's not edx"
    pass


class SeamlessAuthorization(object):

    cookie_name = GenericOAuthBackend.CUSTOM_OAUTH_PARAMS.get('COOKIE_NAME', 'authenticated')

    def process_request(self, request):
        """
        Checks cross-domain cookies and, if the user is authenticated with SSO,
        authorizes the user on edX.
        """
        backend = GenericOAuthBackend.name
        current_url = request.get_full_path()

        # SeamlessAuthorization doesn't work for Django administration
        if hasattr(settings, 'SOCIAL_AUTH_EXCLUDE_URL_PATTERN'):
            r = re.compile(settings.SOCIAL_AUTH_EXCLUDE_URL_PATTERN)
            if r.match(current_url):
                return None

        auth_cookie = request.COOKIES.get(self.cookie_name)
        auth_cookie_portal = request.session.get(self.cookie_name)
        continue_url = reverse('{0}:complete'.format(NAMESPACE),
                               args=(backend,))
        is_auth = request.user.is_authenticated()
        is_same_user = (auth_cookie == auth_cookie_portal)

        # Check for infinity redirection loop
        is_continue = (continue_url in current_url)

        request.session[self.cookie_name] = auth_cookie

        if not is_same_user and is_auth:
            logout(request)

        if (auth_cookie and not is_continue and (not is_auth or not is_same_user)) or \
                ('force_auth' in request.session and request.session.pop('force_auth')):
            query_dict = request.GET.copy()
            query_dict[REDIRECT_FIELD_NAME] = current_url
            query_dict['auth_entry'] = 'login'
            request.GET = query_dict
            logout(request)
            return auth(request, backend)
        elif not auth_cookie and is_auth:
            # Logout if user isn't logined on sso
            logout(request)

        return None


class OAuthRedirection(object):
    def process_request(self, request):
        """
        Redirect to PLP for pages that have duplicated functionality on PLP.
        """
        CUSTOM_OAUTH_PARAMS = settings.CUSTOM_OAUTH_PARAMS if hasattr(settings, 'CUSTOM_OAUTH_PARAMS') else {}
        PROVIDER_URL = CUSTOM_OAUTH_PARAMS.get("PROVIDER_URL", "")

        COURSES_LIST_URL_PATH = CUSTOM_OAUTH_PARAMS.get("COURSES_LIST_URL_PATH")
        USER_ACCOUNT_URL_PATH = CUSTOM_OAUTH_PARAMS.get("USER_ACCOUNT_URL_PATH")
        DASHBOARD_URL_PATH = CUSTOM_OAUTH_PARAMS.get("DASHBOARD_URL_PATH")

        current_url = request.get_full_path()
        if current_url:
            start_url = current_url.split('?')[0].split('/')[1]
        else:
            start_url = ''

        auth_process_urls = ('oauth2', 'auth', 'login_oauth_token', 'social-logout')
        api_urls = (
            'certificates', 'api', 'user_api', 'notifier_api', 'update_example_certificate', 'update_certificate',
            'request_certificate',)

        handle_local_urls = (
            'i18n', 'search', 'verify_student', 'certificates', 'jsi18n', 'course_modes', '404', '500', 'i18n.js',
            'wiki', 'notify', 'courses', 'xblock', 'change_setting', 'account', 'notification_prefs', 'admin',
            'survey', 'event', 'instructor_task_status', 'edinsights_service', 'openassessment', 'instructor_report',
            'logout'
        )

        handle_local_urls += auth_process_urls + api_urls
        is_auth = request.user.is_authenticated()

        if settings.DEBUG:
            debug_handle_local_urls = ('debug', settings.STATIC_URL, settings.MEDIA_URL)
            handle_local_urls += debug_handle_local_urls

        if request.path in ("/dashboard/", "/dashboard"):
            if is_auth and DASHBOARD_URL_PATH:
                return redirect(os.path.join(PROVIDER_URL, DASHBOARD_URL_PATH))
            else:
                return redirect(PROVIDER_URL)

        r_url = re.compile(r'^/courses/(.*)/about').match(current_url)
        if r_url:
            return redirect(
                os.path.join(os.path.join(PROVIDER_URL))
            )

        is_courses_list_or_about_page = False
        r = re.compile(r'^/courses/%s/about' % settings.COURSE_ID_PATTERN)

        if r.match(current_url):
            is_courses_list_or_about_page = True

        if COURSES_LIST_URL_PATH and request.path in ("/courses/", "/courses"):
            return redirect(os.path.join(PROVIDER_URL, COURSES_LIST_URL_PATH))

        if request.path.startswith('/u/') or request.path in ("/account/settings/", "/account/settings"):
            if is_auth and USER_ACCOUNT_URL_PATH:
                return redirect(os.path.join(PROVIDER_URL, USER_ACCOUNT_URL_PATH))
            else:
                return redirect(PROVIDER_URL)

        if start_url not in handle_local_urls or is_courses_list_or_about_page:
            if start_url.split('?')[0] not in handle_local_urls:
                provider_url = PROVIDER_URL.rstrip("/") + "/"
                return redirect("%s%s" % (provider_url, current_url))

        if not is_auth and start_url not in auth_process_urls and start_url not in api_urls:
            request.session['force_auth'] = True
