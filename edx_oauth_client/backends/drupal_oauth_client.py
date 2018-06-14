import ssl
from django.conf import settings
from social_core.backends.oauth import BaseOAuth2
from social_core.utils import handle_http_errors


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


class DrupalOAuthBackend(BaseOAuth2):
    """
    Backend for Drupal OAuth Server Authorization
    """
    DRUPAL_PRIVIDER_URL = settings.FEATURES.get('DRUPAL_PRIVIDER_URL')
    DRUPAL_AUTHORIZE_URL = settings.FEATURES.get('DRUPAL_AUTHORIZE_URL', '/oauth2/authorize')
    DRUPAL_GET_TOKEN_URL = settings.FEATURES.get('DRUPAL_GET_TOKEN_URL', '/oauth2/token')
    name = 'drupal-oauth2'
    ID_KEY = settings.FEATURES.get('DRUPAL_ID_KEY', 'uid')
    AUTHORIZATION_URL = '{}{}'.format(DRUPAL_PRIVIDER_URL, DRUPAL_AUTHORIZE_URL)
    ACCESS_TOKEN_URL = '{}{}'.format(DRUPAL_PRIVIDER_URL, DRUPAL_GET_TOKEN_URL)
    # USER_DATA_URL = '{url}/oauth2/access_token/{access_token}/'
    DEFAULT_SCOPE = settings.FEATURES.get('DRUPAL_SCOPE', ['api'])
    REDIRECT_STATE = False
    ACCESS_TOKEN_METHOD = 'POST'

    PIPELINE = DEFAULT_AUTH_PIPELINE

    skip_email_verification = True

    def setting(self, name, default=None):
        """Return setting value from strategy"""
        try:
            import third_party_auth
        except ImportError:
            OAuth2ProviderConfig = None

        if third_party_auth.models.OAuth2ProviderConfig is not None:
            providers = [p for p in third_party_auth.provider.Registry.displayed_for_login() if p.backend_name == self.name]
            if not providers:
                raise Exception("Can't fetch setting of a disabled backend.")
            provider_config = providers[0]
            try:
                return provider_config.get_setting(name)
            except KeyError:
                pass
        return super(DrupalOAuthBackend, self).setting(name, default=default)

    def get_user_details(self, response):
        """ Return user details from SSO account. """
        return response

    @handle_http_errors
    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        data = self.user_data(access_token)
        if data is not None and 'access_token' not in data:
            data['access_token'] = access_token
        kwargs.update({'response': data, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        self.strategy.session_set(
            '{}_state'.format(self.name),
            self.data.get('state')
        )
        next_url = '/'
        self.strategy.session.setdefault('next', next_url)
        return super(DrupalOAuthBackend, self).auth_complete(*args, **kwargs)

    def user_data(self, access_token, *args, **kwargs):
        """ Grab user profile information from SSO. """
        data = self.get_json(
            '{}{}'.format(self.DRUPAL_PRIVIDER_URL, settings.FEATURES.get('DRUPAL_USER_DATA_URL', '/api/current-user/')),
            params={'access_token': access_token},
        )
        data['access_token'] = access_token
        return data

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        self.strategy.session.setdefault('auth_entry', 'register')
        return super(DrupalOAuthBackend, self).pipeline(
            pipeline=self.PIPELINE, *args, **kwargs
        )

    def get_user_id(self, details, response):
        """Return a unique ID for the current user, by default from server
        response."""
        if 'data' in response:
            return response['data'][0].get(self.ID_KEY)
        else:
            return response.get(self.ID_KEY)
