import re

from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME, logout

from social_django.views import auth, NAMESPACE


class SeamlessAuthorization(object):
    cookie_name = 'SpalahSSO'

    def process_request(self, request):
        """
        Checks cross-domain cookies and, if the user is authenticated with SSO,
        authorizes the user on edX.
        """
        backend = 'spalah-oauth2'
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
            # Logout if the user isn't authenticated with SSO
            logout(request)
