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
    'third_party_auth.pipeline.set_logged_in_cookies',
    'third_party_auth.pipeline.login_analytics'
]


class GenericOAuthBackend(BaseOAuth2):
    """
    Backend for Edx OAuth Server Authorization.
    """
    name = 'edx-oauth2'
    skip_email_verification = True

    PIPELINE = DEFAULT_AUTH_PIPELINE
    REDIRECT_STATE = False

    def authorization_url(self):
        return self.setting("AUTHORIZATION_URL")

    def access_token_url(self):
        return self.setting("ACCESS_TOKEN_URL")

    def setting(self, name, default=None, backend=None):
        """
        Load the setting from a ConfigurationModel if possible, or fall back to the normal
        Django settings lookup.

        OAuthAuth subclasses will call this method for every setting they want to look up.
        SAMLAuthBackend subclasses will call this method only after first checking if the
            setting 'name' is configured via SAMLProviderConfig.
        LTIAuthBackend subclasses will call this method only after first checking if the
            setting 'name' is configured via LTIProviderConfig.
        """

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

        # Special case handling of login error URL if we're using a custom auth entry point:
        if name == 'LOGIN_ERROR_URL':
            auth_entry = self.request.session.get('auth_entry')
            if auth_entry and auth_entry in third_party_auth.pipeline.AUTH_ENTRY_CUSTOM:
                error_url = third_party_auth.pipeline.AUTH_ENTRY_CUSTOM[auth_entry].get('error_url')
                if error_url:
                    return error_url

        # Special case: we want to get this particular setting directly from the provider database
        # entry if possible; if we don't have the information, fall back to the default behavior.
        if name == 'MAX_SESSION_LENGTH':
            running_pipeline = third_party_auth.pipeline.get(self.request) if self.request else None
            if running_pipeline is not None:
                provider_config = third_party_auth.provider.Registry.get_from_pipeline(running_pipeline)
                if provider_config:
                    return provider_config.max_session_length

        # At this point, we know 'name' is not set in a [OAuth2|LTI|SAML]ProviderConfig row.
        # It's probably a global Django setting like 'FIELDS_STORED_IN_SESSION':
        return DjangoStrategy(self).setting(name, default, backend)

    def get_user_details(self, response):
        """ Return user details from SSO account. """
        return response

    def user_data(self, access_token, *args, **kwargs):
        """ Grab user profile information from SSO. """
        data = self.get_json(self.setting('USER_DATA_URL'), params={'access_token': access_token}, method='POST')

        if data.get('success') and 'user' in data:
            data = data['user']
        elif 'data' in data:
            data = data['data']

        data['access_token'] = access_token
        data.pop('password', None)

        return data

    def pipeline(self, pipeline, pipeline_index=0, *args, **kwargs):
        self.strategy.session.setdefault('auth_entry', 'register')
        return super(GenericOAuthBackend, self).pipeline(
            pipeline=self.PIPELINE, *args, **kwargs
        )

    def get_user_id(self, details, response):
        """Return a unique ID for the current user, by default from server
        response."""
        if 'data' in response:
            return response['data'][0].get(self.setting("ID_KEY"))

        return response.get(self.setting("ID_KEY"))

    # Method can be removed if SSO realization is simple.
    def auth_complete_params(self, state=None):
        res = super(GenericOAuthBackend, self).auth_complete_params(state)

        # CUSTOM FOR EFH, IN DEFAULT REALIZATION COULD BE OMITTED.
        res.update({
            'id': res.get('client_id'),
            'secret': res.get('client_secret'),
        })

        return res

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        state = self.validate_state()
        self.process_error(self.data)

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
            method=self.setting("ACCESS_TOKEN_METHOD", "POST")
        )
        self.process_error(response)
        access_token = response['access_token']

        # EFH RELATED PART CAN BE DELETED IN DEFAULT REALIZATION
        if type(access_token) not in (str, unicode) and 'value' in access_token:
            access_token = access_token['value']

        return self.do_auth(access_token, response=response, *args, **kwargs)
