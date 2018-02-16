from django.conf import settings
from social_core.backends.oauth import BaseOAuth2

DEFAULT_AUTH_PIPELINE = [
    'third_party_auth.pipeline.parse_query_params',
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'third_party_auth.pipeline.associate_by_email_if_login_api',
    'social_core.pipeline.user.get_username',
    'third_party_auth.pipeline.set_pipeline_timeout',
    'edx_oauth_client.pipeline.ensure_user_information',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
    'third_party_auth.pipeline.set_logged_in_cookies',
    'third_party_auth.pipeline.login_analytics'
]


class SpalahOAuth2(BaseOAuth2):
    """
    Spalah OAuth authentication backend
    """
    name = 'spalah-oauth2'
    SPALAH_DOMAIN = settings.FEATURES.get('SPALAH_DOMAIN')
    AUTHORIZATION_URL = '{}/o/authorize/'.format(SPALAH_DOMAIN)
    ACCESS_TOKEN_URL = '{}/o/token/'.format(SPALAH_DOMAIN)
    ACCESS_TOKEN_METHOD = 'POST'
    USER_DATA_URL = '{}/user/current/'.format(SPALAH_DOMAIN)
    ID_KEY = 'email'
    REDIRECT_STATE = False

    PIPELINE = DEFAULT_AUTH_PIPELINE
    skip_email_verification = True

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        self.strategy.session.setdefault('auth_entry', 'register')
        return super(SpalahOAuth2, self).pipeline(
            pipeline=self.PIPELINE, pipeline_index=pipeline_index, *args, **kwargs
        )

    def get_user_details(self, response):
        """ Return user details from Spalah account. """
        return response

    def user_data(self, access_token, *args, **kwargs):
        return self.get_json(
            self.USER_DATA_URL,
            headers={'Authorization': 'Bearer {}'.format(access_token)}
        )
