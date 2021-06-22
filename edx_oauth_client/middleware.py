import logging
from typing import Callable, Dict
from urllib.parse import urlparse

from common.djangoapps import third_party_auth
from django.conf import settings
from django.contrib.auth import logout, REDIRECT_FIELD_NAME
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.urls import reverse
from social_django.views import auth, NAMESPACE

from edx_oauth_client.backends.edx_oauth_client import GenericOAuthBackend
from edx_oauth_client.constants import API_URLS, LOCAL_URLS, OAUTH_PROCESS_URLS

log = logging.getLogger(__name__)

try:
    from opaque_keys.edx.keys import CourseKey
except ImportError:
    log.warn("Oh, it's not edx")


def seamless_authorization(get_response: Callable[[HttpRequest], HttpResponse]):
    backend = GenericOAuthBackend.name

    def ignore_url(request: HttpRequest) -> bool:
        """TODO"""
        start_url_path, _, _ = urlparse(request.path).path.strip("/").partition("/")
        ignored_urls = OAUTH_PROCESS_URLS + API_URLS
        if settings.DEBUG:
            ignored_urls += LOCAL_URLS
        return start_url_path in ignored_urls

    def prepare_redirection_query(request: HttpRequest) -> Dict[str, str]:
        """TODO"""
        query_dict = request.GET.copy()
        query_dict[REDIRECT_FIELD_NAME] = request.get_full_path()
        query_dict["auth_entry"] = "login"
        return query_dict

    def middleware(request: HttpRequest) -> HttpResponse:
        request.user: User  # type: ignore

        # Check for infinite redirection loop
        continue_url = reverse("{0}:complete".format(NAMESPACE), args=(backend,))
        is_continue = continue_url in request.path

        if not (ignore_url(request) or request.user.is_authenticated or is_continue):
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
            log.info(f"Ignoring URL:{request.get_full_path()}")

            response = get_response(request)
        return response

    return middleware
