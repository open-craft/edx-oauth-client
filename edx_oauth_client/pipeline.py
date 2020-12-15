# -*- coding: utf-8 -*-
import datetime
from logging import getLogger

from student.forms import AccountCreationForm
from django.contrib.auth.models import User
from django.shortcuts import render_to_response, redirect
from django.urls import reverse
from social_core.pipeline import partial
from openedx.core.djangoapps.user_api.accounts.utils import generate_password
from student.helpers import (
    do_create_account,
)
from third_party_auth.pipeline import AuthEntryError

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
        data['first_name'] = user_data.get('firstname', user_data.get('first_name'))
        data['last_name'] = user_data.get('lastname', user_data.get('last_name'))
        data['email'] = user_data.get('email')
        data['country'] = country
        data['access_token'] = access_token

        date_of_birth = user_data.get('date_of_birth')

        if date_of_birth is not None:
            data['year_of_birth'] = datetime.datetime.strptime(date_of_birth, '%d.%m.%Y').year

        # User API provide two possible variants "male" or "female", with are strings.
        # We need extract only first letter and save it to the user profile model.
        if user_data.get('gender'):
            data['gender'] = user_data.get('gender')[0]

        if any((data['first_name'], data['last_name'])):
            data['name'] = u'{} {}'.format(data['first_name'], data['last_name']).strip()
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
        data['terms_of_service'] = "True"
        data['honor_code'] = 'True'
        data['password'] = generate_password()
        data['provider'] = backend.name

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            form = AccountCreationForm(
                data=data,
                extra_fields={},
                extended_profile_fields={},
                tos_required=False,
            )

            (user, profile, registration) = do_create_account(form)
            user.is_active = True
            user.set_unusable_password()
            user.save()

    return {'user': user}


@partial.partial
def check_password_for_account_synchronization(
    strategy, auth_entry, backend=None, user=None, social=None, allow_inactive_user=False, *args, **kwargs
):
    """
    Provides additional validation for the users whose wants to synchronize their accounts in two systems.

    If the user try to authorize by the third party auth and has the same email in two systems asks
    the user to confirm synchronization by filling in the password of the account in Open edX.
    """

    request = kwargs.get('request')
    user = User.objects.filter(email=kwargs['response']['email']).last()

    if request.method == 'POST' and user:
        if user.check_password(request.POST.get('password')):
            request.session['is_valid'] = True

            return strategy.redirect(
                '{backend_url}?state={state}&code={code}'.format(
                    backend_url=reverse('social:complete', args=(backend.name,)),
                    state=request.POST.get('state'),
                    code=request.POST.get('code'),
                )
            )
        else:
            request.session['is_valid'] = False

    if social is None and user:
        if not request.session.get('is_valid'):
            return render_to_response(
                'check_password_for_account_synchronization.html',
                {
                    'path': request.path,
                    'state': request.GET.get('state'),
                    'code': request.GET.get('code'),
                    'user': user,
                    'error': request.session.get('is_valid') is False,
                }
            )
