from logging import getLogger

from django.contrib.auth.models import User

from student.views import create_account_with_params, reactivation_email_for_user
from third_party_auth.pipeline import (AuthEntryError, make_random_password)
from third_party_auth.provider import Registry

from edx_oauth_client.utils import get_user_data

log = getLogger(__name__)


def parse_user_information(
        strategy, auth_entry, backend=None, user=None, social=None, allow_inactive_user=False, *args, **kwargs
):
    """
    Parse user info from the provider response
    """
    data = {}
    if kwargs.get('request', {}).get('id_token'):
        user_data = get_user_data(kwargs['request']['id_token'])
        log.debug('SSO Provider data - %s', user_data)
        # username max_length was increased to be able to use the "sub" parameter as username.
        # https://github.com/raccoongang/edx-platform/pull/2365
        data['username'] = user_data.get('sub') # hash string
        data['first_name'] = user_data.get('given_name')
        data['last_name'] = user_data.get('family_name')
        data['email'] = user_data.get('email')
        data['name'] = user_data.get('email') # to avoid username with a suffix or hash string
        data['access_token'] = user_data.get('socialIdpUserId', '')
    if not user:
        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            pass

    return {'details': data, 'user': user}


def verify_user_email(user=None, *args, **kwargs):
    current_provider = Registry.get_from_pipeline({'backend': kwargs.get('backend'), 'kwargs': kwargs})
    if current_provider and current_provider.skip_email_verification:
        if user and not user.is_active:
            user.is_active = True
            user.save()

