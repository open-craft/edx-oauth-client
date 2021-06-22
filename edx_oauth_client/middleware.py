import logging
from typing import Callable
from urllib.parse import urlparse

import third_party_auth
from django.contrib.auth import logout
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
        start_url_path, _, _ = urlparse(request.path).path.strip("/").partition("/")
        return start_url_path in (OAUTH_PROCESS_URLS + LOCAL_URLS + API_URLS)

    def middleware(request: HttpRequest) -> HttpResponse:
        request.user: User  # type: ignore

        # Check for infinity redirection loop
        continue_url = reverse("{0}:complete".format(NAMESPACE), args=(backend,))
        is_continue = continue_url in request.path

        if not (ignore_url(request) or request.user.is_authenticated or is_continue):
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
            log.info(f"Ignoring URL:{request.path}")

            response = get_response(request)
        return response

    return middleware
