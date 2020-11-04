import logging

from django.contrib.sites.models import Site

from social.backends.oauth import BaseOAuth2
from social.strategies.django_strategy import DjangoStrategy
from social.utils import handle_http_errors

import third_party_auth
from openedx.core.djangoapps.theming.helpers import get_current_request

log = logging.getLogger(__name__)

DEFAULT_AUTH_PIPELINE = [
    'third_party_auth.pipeline.parse_query_params',
    'social.pipeline.social_auth.social_details',
    'social.pipeline.social_auth.social_uid',
    'social.pipeline.social_auth.auth_allowed',
    'social.pipeline.social_auth.social_user',
    'third_party_auth.pipeline.associate_by_email_if_login_api',
    'social.pipeline.user.get_username',
    'third_party_auth.pipeline.set_pipeline_timeout',
    'edx_oauth_client.pipeline.ensure_user_information',
    'social.pipeline.user.create_user',
    'social.pipeline.social_auth.associate_user',
    'social.pipeline.social_auth.load_extra_data',
    'social.pipeline.user.user_details',
    'third_party_auth.pipeline.login_analytics'
]


class GenericOAuthBackend(BaseOAuth2):
    """
    Backend for Edx OAuth Server Authorization.
    """
    name = "edx-oauth2"
    skip_email_verification = True

    PIPELINE = DEFAULT_AUTH_PIPELINE
    REDIRECT_STATE = False

    def authorization_url(self):
        return self.setting("AUTHORIZATION_URL")

    def access_token_url(self):
        return self.setting("ACCESS_TOKEN_URL")

    def setting(self, name, default=None, backend=None):
        """
        Load the setting from a ConfigurationModel if possible, or fall back to the normal Django settings lookup.
        """

        # Get the latest actual provider config.
        provider_config = third_party_auth.models.OAuth2ProviderConfig.objects.filter(
            backend_name=self.name,
            site=Site.objects.get_current(get_current_request()),
            enabled=True
        ).last()

        if provider_config and not provider_config.enabled_for_current_site:
            raise Exception("Can't fetch setting of a disabled backend/provider.")
        try:
            return provider_config.get_setting(name)
        except KeyError:
            pass

        return DjangoStrategy(self).setting(name, default, backend)

    def get_user_details(self, response):
        """
        Return user details from SSO account.
        """
        return response

    def user_data(self, access_token, *args, **kwargs):
        """
        Grab user profile information from SSO.
        """

        params, headers = None, None

        if self.setting("USER_DATA_REQUEST_METHOD", "GET") == "GET":
            headers = {"Authorization": "Bearer {}".format(access_token)}
        else:
            params = {"access_token": access_token}

        data = self.request_access_token(
            self.setting("USER_DATA_URL"),
            params=params,
            headers=headers,
            method=self.setting("USER_DATA_REQUEST_METHOD", "GET")
        )

        if isinstance(data, list):
            data = data[0]

        if data.get("success") and "user" in data:
            data = data["user"]
        elif "data" in data:
            data = data["data"]

        data["access_token"] = access_token
        data.pop("password", None)

        return data

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        """
        Set to session auth entry value.
        """
        self.strategy.session.setdefault("auth_entry", "register")
        return super(GenericOAuthBackend, self).pipeline(pipeline=self.PIPELINE, *args, **kwargs)

    def get_user_id(self, details, response):
        """
        Return a unique ID for the current user, by default from server response.
        """
        if "data" in response:
            return response["data"][0].get(self.setting("ID_KEY"))

        return response.get(self.setting("ID_KEY"))

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """
        Completes login process, must return user instance.
        """

        self.process_error(self.data)
        state = self.validate_state()

        data, params = None, None
        if self.setting("ACCESS_TOKEN_METHOD", "POST") == "GET":
            params = self.auth_complete_params(state)
        else:
            data = self.auth_complete_params(state)

        response = self.request_access_token(
            self.access_token_url(),
            data=data,
            params=params,
            headers=self.auth_headers(),
            auth=self.auth_complete_credentials(),
            method=self.setting("ACCESS_TOKEN_METHOD", "POST")
        )
        self.process_error(response)

        return self.do_auth(response["access_token"], response=response, *args, **kwargs)
