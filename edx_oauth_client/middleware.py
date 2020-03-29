import os.path
import re
from urlparse import urljoin

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, logout
from django.core.urlresolvers import reverse
from django.shortcuts import redirect

from social.apps.django_app.views import NAMESPACE, auth

try:
    from opaque_keys.edx.keys import CourseKey
except ImportError:
    msg = "Oh, it's not edx"
    pass


class SeamlessAuthorization(object):
    cookie_name = 'authenticated'

    def process_request(self, request):
        """
        Check multidomain cookie and if user is authenticated on sso, login it on edx.
        """
        backend = "edx-oauth2"
        current_url = request.get_full_path()

        # don't work for admin
        for attr in ['SOCIAL_AUTH_EXCLUDE_URL_PATTERN', 'AUTOCOMPLETE_EXCLUDE_URL_PATTERN']:
            if hasattr(settings, attr):
                r = re.compile(getattr(settings, attr))
                if r.match(current_url):
                    return None

        auth_cookie = request.COOKIES.get(self.cookie_name, '0').lower()
        auth_cookie_user = request.COOKIES.get('{}_user'.format(self.cookie_name))
        auth_cookie = (auth_cookie in ('1', 'true', 'ok'))
        continue_url = reverse('{0}:complete'.format(NAMESPACE),
                               args=(backend,))
        is_auth = request.user.is_authenticated()

        is_same_user = (request.user.username == auth_cookie_user)

        OAUTH_PROVIDER_URL = settings.FEATURES.get("OAUTH_PROVIDER_URL", "")

        if reverse("logout") == current_url:
            logout(request)
            return redirect(urljoin(OAUTH_PROVIDER_URL, '/logout'))

        # Check for infinity redirection loop
        is_continue = (continue_url in current_url)

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


class Redirection(object):
    def process_request(self, request):
        """
        Redirect to PLP for pages that have duplicated functionality on PLP
        """
        OAUTH_PROVIDER_URL = settings.FEATURES.get("OAUTH_PROVIDER_URL","")
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

        if request.path == "/dashboard/" or request.path == "/dashboard":
            if is_auth:
                return redirect(os.path.join(OAUTH_PROVIDER_URL, 'members', request.user.username))
            else:
                return redirect(OAUTH_PROVIDER_URL)

        r_url = re.compile(r'^/courses/(.*)/about').match(current_url)
        if r_url:
            return redirect(
                os.path.join(os.path.join(OAUTH_PROVIDER_URL))
            )

        is_courses_list_or_about_page = False
        r = re.compile(r'^/courses/%s/about' % settings.COURSE_ID_PATTERN)

        if r.match(current_url):
            is_courses_list_or_about_page = True

        if request.path == "/courses/" or request.path == "/courses":
            return redirect(os.path.join(OAUTH_PROVIDER_URL, 'courses'))

        if request.path.startswith(
                '/u/') or request.path == "/account/settings/" or request.path == "/account/settings":
            if is_auth:
                return redirect(os.path.join(OAUTH_PROVIDER_URL, 'members', request.user.username, 'profile'))
            else:
                return redirect(OAUTH_PROVIDER_URL)

        if start_url not in handle_local_urls or is_courses_list_or_about_page:
            if start_url.split('?')[0] not in handle_local_urls:
                oauth_url = OAUTH_PROVIDER_URL.rstrip("/") + "/"
                return redirect("%s%s" % (oauth_url, current_url))

        if not is_auth and start_url not in auth_process_urls and \
                        start_url not in api_urls:
            request.session['force_auth'] = True
