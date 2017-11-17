from django.conf import settings
from social.backends.oauth import BaseOAuth2
from social.utils import handle_http_errors

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


class EdxOAuthBackend(BaseOAuth2):
    """
    Backend for Edx OAuth Server Authorization
    """
    OAUTH_PROVIDER_URL = settings.FEATURES.get('OAUTH_PROVIDER_URL')
    name = 'edx-oauth2'
    ID_KEY = settings.FEATURES.get('OAUTH_ID_KEY', 'id')
    AUTHORIZATION_URL = '{}/oauth2/authorize'.format(OAUTH_PROVIDER_URL)
    ACCESS_TOKEN_URL = '{}/oauth2/token'.format(OAUTH_PROVIDER_URL)
    DEFAULT_SCOPE = settings.FEATURES.get('OAUTH_SCOPE', [])
    REDIRECT_STATE = False
    ACCESS_TOKEN_METHOD =  settings.FEATURES.get('OAUTH_ACCESS_TOKEN_METHOD', 'POST')

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
        return super(EdxOAuthBackend, self).setting(name, default=default)

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
        return super(EdxOAuthBackend, self).auth_complete(*args, **kwargs)

    def user_data(self, access_token, *args, **kwargs):
        """ Grab user profile information from SSO. """
        data = self.get_json(
            '{}{}'.format(self.OAUTH_PROVIDER_URL, settings.FEATURES.get('OAUTH_USER_DATA_URL', '/login')),
            params={'access_token': access_token}, method='POST'
        )
        if data.get('success') and 'user' in data:
            data = data['user']
        elif 'data' in data:
            data = data['data']
        data['access_token'] = access_token
        return data

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        self.strategy.session.setdefault('auth_entry', 'register')
        return super(EdxOAuthBackend, self).pipeline(
            pipeline=self.PIPELINE, *args, **kwargs
        )

    def get_user_id(self, details, response):
        """Return a unique ID for the current user, by default from server
        response."""
        if 'data' in response:
            return response['data'][0].get(self.ID_KEY)
        else:
            return response.get(self.ID_KEY)

    def auth_complete_params(self, state=None):
        client_id, client_secret = self.get_key_and_secret()
        return {
            'grant_type': 'authorization_code',  # request auth code
            'code': self.data.get('code', ''),  # server response code
            'id': client_id,
            'secret': client_secret,
            'redirect_uri': self.get_redirect_uri(state)
        }

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        state = self.validate_state()
        self.process_error(self.data)
        response = self.request_access_token(
            self.access_token_url(),
            data=self.auth_complete_params(state),
            headers=self.auth_headers(),
            method=self.ACCESS_TOKEN_METHOD
        )
        self.process_error(response)
        access_token = response['access_token']
        if type(access_token) not in (str, unicode) and 'value' in access_token:
            access_token = access_token['value']
        return self.do_auth(access_token, response=response,
                            *args, **kwargs)
