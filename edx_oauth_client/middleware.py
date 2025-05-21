import logging
from typing import Callable, Dict
from urllib.parse import urlparse

from common.djangoapps import third_party_auth
from django.conf import settings
from django.contrib.auth import logout, REDIRECT_FIELD_NAME
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse, NoReverseMatch
from social_django.views import auth, NAMESPACE

from edx_oauth_client.backends.edx_oauth_client import GenericOAuthBackend
from edx_oauth_client.constants import API_URLS, LOCAL_URLS, OAUTH_PROCESS_URLS

log = logging.getLogger(__name__)

try:
    from opaque_keys.edx.keys import CourseKey
except ImportError:
    log.warn("Oh, it's not edx")


def seamless_authorization(get_response: Callable[[HttpRequest], HttpResponse]):
    """A middleware for force authenticating users."""
    backend = getattr(settings, 'SEAMLESS_AUTHORIZATION_BACKEND', GenericOAuthBackend.name)

    def ignore_url(request: HttpRequest) -> bool:
        """Determine whether the request should bypass the forced authentication."""
        start_url_path, _, _ = urlparse(request.path).path.strip("/").partition("/")
        ignored_urls = OAUTH_PROCESS_URLS + API_URLS
        if settings.DEBUG:
            ignored_urls += LOCAL_URLS
        return start_url_path in ignored_urls or start_url_path.startswith("asset-v1:")

    def has_cookie(request: HttpRequest) -> bool:
        """
        Check if a cookie with a name specified in the `SEAMLESS_AUTHORIZATION_CHECK_COOKIE` is present in the request.

        Returns True if the cookie is present or the `SEAMLESS_AUTHORIZATION_CHECK_COOKIE` is not set.
        """
        if cookie_name := getattr(settings, 'SEAMLESS_AUTHORIZATION_CHECK_COOKIE', None):
            return cookie_name in request.COOKIES

        return True

    def prepare_redirection_query(request: HttpRequest) -> Dict[str, str]:
        """Prepare a redirection reference for the SSO."""
        query_dict = request.GET.copy()
        query_dict[REDIRECT_FIELD_NAME] = request.get_full_path()
        query_dict["auth_entry"] = "login"
        return query_dict

    def middleware(request: HttpRequest) -> HttpResponse:
        request.user: User  # type: ignore

        # Check for infinite redirection loop
        try:
            continue_url = reverse("{0}:complete".format(NAMESPACE), args=(backend,))
        except NoReverseMatch:
            # Not in the LMS.
            if not request.user.is_authenticated:
                return redirect(settings.FRONTEND_LOGIN_URL)
            continue_url = ''

        is_continue = continue_url in request.path

        if not (ignore_url(request) or request.user.is_authenticated or is_continue) and has_cookie(request):
            request.GET = prepare_redirection_query(request)
            logout(request)
            providers = [
                p
                for p in third_party_auth.provider.Registry.displayed_for_login()
                if p.backend_name.startswith(backend)
            ]
            try:
                response = auth(request, providers[0].backend_name)
            except IndexError:
                response = get_response(request)
        else:
            log.debug(f"Ignoring URL:{request.get_full_path()}")
            response = get_response(request)

        return response

    return middleware
