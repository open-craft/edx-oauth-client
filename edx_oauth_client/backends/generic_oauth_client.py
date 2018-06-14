import logging
import urlparse

from django.conf import settings
from social.backends.oauth import BaseOAuth2
from social.utils import handle_http_errors

import third_party_auth

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
    'third_party_auth.pipeline.set_logged_in_cookies',
    'third_party_auth.pipeline.login_analytics'
]


class GenericOAuthBackend(BaseOAuth2):
    """
    Backend for Generic OAuth Server Authorization.
    """
    name = 'custom-oauth2'

    CUSTOM_OAUTH_PARAMS = settings.CUSTOM_OAUTH_PARAMS

    if not all(CUSTOM_OAUTH_PARAMS.values()):
        log.error("Some of the CUSTOM_OAUTH_PARAMS are improperly configured. Custom oauth won't work correctly.")

    PROVIDER_URL = CUSTOM_OAUTH_PARAMS.get('PROVIDER_URL')
    AUTHORIZE_URL = CUSTOM_OAUTH_PARAMS.get('AUTHORIZE_URL')  # '/oauth2/authorize' usually is default value
    GET_TOKEN_URL = CUSTOM_OAUTH_PARAMS.get('GET_TOKEN_URL')  # '/oauth2/token' usually is default value
    ID_KEY = CUSTOM_OAUTH_PARAMS.get('PROVIDER_ID_KEY')  # unique marker which could be taken from the SSO response
    USER_DATA_URL = CUSTOM_OAUTH_PARAMS.get('USER_DATA_URL')  # '/api/current-user/' some url similar to the example

    AUTHORIZATION_URL = urlparse.urljoin(PROVIDER_URL, AUTHORIZE_URL)
    ACCESS_TOKEN_URL = urlparse.urljoin(PROVIDER_URL, GET_TOKEN_URL)
    DEFAULT_SCOPE = settings.FEATURES.get('SCOPE')  # extend the scope of the provided permissions.
    REDIRECT_STATE = False
    ACCESS_TOKEN_METHOD = 'POST'  # default method is 'GET'

    PIPELINE = DEFAULT_AUTH_PIPELINE

    skip_email_verification = True

    def setting(self, name, default=None):
        """
        Return setting value from strategy.
        """
        if third_party_auth.models.OAuth2ProviderConfig is not None:
            providers = [
                p for p in third_party_auth.provider.Registry.displayed_for_login() if p.backend_name == self.name
            ]
            if not providers:
                raise Exception("Can't fetch setting of a disabled backend.")
            provider_config = providers[0]
            try:
                return provider_config.get_setting(name)
            except KeyError:
                pass
        return super(GenericOAuthBackend, self).setting(name, default=default)

    def get_user_details(self, response):
        """
        Return user details from SSO account.
        """
        return response

    @handle_http_errors
    def do_auth(self, access_token, *args, **kwargs):
        """
        Finish the auth process once the access_token was retrieved.
        """
        data = self.user_data(access_token)
        if data is not None and 'access_token' not in data:
            data['access_token'] = access_token
        kwargs.update({'response': data, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """
        Complete loging process, must return user instance.
        """
        self.strategy.session_set('{}_state'.format(self.name), self.data.get('state'))
        next_url = '/'
        self.strategy.session.setdefault('next', next_url)
        return super(GenericOAuthBackend, self).auth_complete(*args, **kwargs)

    def user_data(self, access_token, *args, **kwargs):
        """
        Grab user profile information from SSO.
        """
        data = self.get_json(
            urlparse.urljoin(self.PROVIDER_URL, self.USER_DATA_URL),
            params={'access_token': access_token},
        )
        data['access_token'] = access_token
        return data

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        self.strategy.session.setdefault('auth_entry', 'register')
        return super(GenericOAuthBackend, self).pipeline(
            pipeline=self.PIPELINE, *args, **kwargs
        )

    def get_user_id(self, details, response):
        """
        Return a unique ID for the current user, by default from server response.
        """
        if 'data' in response:
            id_key = response['data'][0].get(self.ID_KEY)
        else:
            id_key = response.get('email')
        if not id_key:
            log.error("ID_KEY is not found in the User data response. SSO won't work correctly")
        return id_key
