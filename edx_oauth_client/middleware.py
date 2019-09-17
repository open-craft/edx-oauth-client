import logging
import re

from urlparse import urljoin, urlparse

from django.conf import settings
from django.contrib.auth import logout, REDIRECT_FIELD_NAME
from django.shortcuts import redirect
from django.urls import reverse
from social_django.views import auth, NAMESPACE

from edx_oauth_client.backends.generic_oauth_client import GenericOAuthBackend
from edx_oauth_client.constants import API_URLS, LOCAL_URLS, OAUTH_PROCESS_URLS

log = logging.getLogger(__name__)

try:
    from opaque_keys.edx.keys import CourseKey
except ImportError:
    log.warn("Oh, it's not edx")


class SeamlessAuthorization(object):
    cookie_name = GenericOAuthBackend.CUSTOM_OAUTH_PARAMS.get("COOKIE_NAME", "authenticated")
    cookie_domain = GenericOAuthBackend.CUSTOM_OAUTH_PARAMS.get("COOKIE_DOMAIN")
    provider_url = GenericOAuthBackend.CUSTOM_OAUTH_PARAMS.get("PROVIDER_URL", "")
    provider_logout_url_path = GenericOAuthBackend.CUSTOM_OAUTH_PARAMS.get("LOGOUT_URL_PATH", "logout")

    def process_response(self, request, response):
        """
        Delete cross-domain cookie of SSO flow to accomplish logout.
        """
        if not request.session.get(self.cookie_name) and self.cookie_domain:
            response.set_cookie(
                self.cookie_name,
                domain=self.cookie_domain,
                max_age=0,
                expires="Thu, 01-Jan-1970 00:00:00 GMT",
            )

        return response

    def process_request(self, request):
        """
        Checks cross-domain cookies and, if the user is authenticated with SSO,
        authorizes the user on edX.
        """
        backend = GenericOAuthBackend.name
        current_url = request.get_full_path()

        # SeamlessAuthorization doesn't work for Django administration
        if hasattr(settings, "SOCIAL_AUTH_EXCLUDE_URL_PATTERN"):
            r = re.compile(settings.SOCIAL_AUTH_EXCLUDE_URL_PATTERN)
            if r.match(current_url):
                return None

        auth_cookie = request.COOKIES.get(self.cookie_name)
        auth_cookie_portal = request.session.get(self.cookie_name)
        continue_url = reverse("{0}:complete".format(NAMESPACE), args=(backend,))
        is_auth = request.user.is_authenticated()
        is_same_user = (auth_cookie == auth_cookie_portal)

        # Check for infinity redirection loop
        is_continue = (continue_url in current_url)

        request.session[self.cookie_name] = auth_cookie

        if reverse("logout") == current_url:
            del request.session[self.cookie_name]
            logout(request)
            # FIXME: redirect is dirty fix to be able logout external portal.
            # Please try to avoid and don't do it at edx side.
            return redirect(urljoin(self.provider_url, self.provider_logout_url_path))

        if not is_same_user and is_auth:
            logout(request)

        if (auth_cookie and not is_continue and (not is_auth or not is_same_user)) or (
            "force_auth" in request.session and request.session.pop("force_auth")
        ):
            query_dict = request.GET.copy()
            query_dict[REDIRECT_FIELD_NAME] = current_url
            query_dict["auth_entry"] = "login"
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
        CUSTOM_OAUTH_PARAMS = getattr(settings, "CUSTOM_OAUTH_PARAMS", {})

        provider_url = CUSTOM_OAUTH_PARAMS.get("PROVIDER_URL", "")
        dashboard_url_path = CUSTOM_OAUTH_PARAMS.get("DASHBOARD_URL_PATH")
        courses_list_url_path = CUSTOM_OAUTH_PARAMS.get("COURSES_LIST_URL_PATH")
        user_account_url_path = CUSTOM_OAUTH_PARAMS.get("USER_ACCOUNT_URL_PATH")

        current_url = request.get_full_path()
        start_url_path, _, _ = urlparse(current_url).path.strip("/").partition("/")

        available_urls = API_URLS + LOCAL_URLS + OAUTH_PROCESS_URLS
        if settings.DEBUG:
            debug_handle_local_urls = ("debug", settings.STATIC_URL, settings.MEDIA_URL)
            available_urls += debug_handle_local_urls

        if request.user.is_authenticated():
            if dashboard_url_path and request.path.strip("/") in reverse("dashboard"):
                return redirect(urljoin(provider_url, dashboard_url_path))

            if courses_list_url_path and request.path.strip("/") in reverse("courses"):
                return redirect(urljoin(provider_url, courses_list_url_path))

            if user_account_url_path and (
                request.path.startswith("/u/") or request.path.strip("/") in reverse("account_settings")
            ):
                return redirect(urljoin(provider_url, user_account_url_path))
        elif start_url_path not in (API_URLS + OAUTH_PROCESS_URLS):
            request.session["force_auth"] = True
