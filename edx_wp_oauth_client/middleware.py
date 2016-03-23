import re

from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME, logout

from social.apps.django_app.views import auth, NAMESPACE

try:
    from opaque_keys.edx.keys import CourseKey
except ImportError:
    msg = "Oh, it's not edx"
    pass


class SeamlessAuthorization(object):
    cookie_name = 'authenticated'

    def process_request(self, request):
        """
        Check multidomain cookie and if user is authenticated on sso, login it on edx
        """
        backend = "wp-oauth2"
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
