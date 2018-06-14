from logging import getLogger

from django.contrib.auth.models import User
from social_core.pipeline.partial import partial
from student.views import create_account_with_params, reactivation_email_for_user
from third_party_auth.pipeline import (AuthEntryError, make_random_password)

log = getLogger(__name__)


@partial.partial
def ensure_user_information(
        strategy, auth_entry, backend=None, user=None, social=None, allow_inactive_user=False, *args, **kwargs
):
    """
    Ensure that we have the necessary information about a user to proceed with the pipeline.

    Either an existing account or registration data.
    """

    data = {}
    try:
        if 'data' in kwargs['response']:
            user_data = kwargs['response']['data'][0]
        else:
            user_data = kwargs['response']
        log.info('Get user data: %s', str(user_data))
        access_token = kwargs['response']['access_token']

        country = user_data.get('country')
        if not country:
            log.info('No country in response.')

        # Received fields could be pretty different from the expected, mandatory are only 'username' and 'email'
        data['username'] = user_data.get('username', user_data.get('name'))
        data['first_name'] = user_data.get('firstName', user_data.get('first_name'))
        data['last_name'] = user_data.get('lastName', user_data.get('last_name'))
        data['email'] = user_data.get('email')
        data['country'] = country
        data['access_token'] = access_token
        if any((data['first_name'], data['last_name'])):
            data['name'] = '{} {}'.format(['first_name'], data['last_name']).strip()
        else:
            data['name'] = user_data.get('username')
        if not all((data['username'], data['email'])):
            raise AuthEntryError(
                backend,
                "One of the required parameters (username or email) is not received with the user data."
            )
    except AuthEntryError as e:
        log.exception(e)
        raise
    except Exception as e:
        log.exception(e)
        raise AuthEntryError(backend, "Cannot receive user's data")

    if not user:
        request = strategy.request
        data['terms_of_service'] = "True"
        data['honor_code'] = 'True'
        data['password'] = make_random_password()

        data['provider'] = backend.name

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            create_account_with_params(request, data)
            user.is_active = True
            user.save()

    return {'user': user}
