"""
edx-oauth-client custom pipelines.
"""

import logging
import json

from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.urls import reverse
from edxmako.shortcuts import render_to_response
from social_core.pipeline import partial
from third_party_auth.pipeline import AuthEntryError, is_api, get_complete_url

from openedx.core.djangoapps.dark_lang import DARK_LANGUAGE_KEY
from openedx.core.djangoapps.user_authn import cookies as user_authn_cookies
from openedx.core.djangoapps.user_authn.views.registration_form import AccountCreationForm
from openedx.core.djangoapps.user_authn.utils import generate_password
from openedx.core.djangoapps.user_api.preferences.api import set_user_preference
from student.helpers import do_create_account


log = logging.getLogger(__name__)


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
        log.info('Get user data')

        data['access_token'] = kwargs['response']['access_token']

        data['country'] = user_data.get('country', 'UA')

        for key, value in backend.setting('USER_DATA_KEY_VALUES').items():
            data[key] = user_data.get(value)

        data['email'] = strategy.session_get('email', "")
        data['username'] = data['email']

        if not data['name']:
            data['name'] = ' '.join(
                [user_data.get('lastname', ''), user_data.get('givenname', ''), user_data.get('middlename', '')]
            )

        if kwargs.get('is_new') and not all((data['username'], data['email'])):
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
        data['terms_of_service'] = 'True'
        data['honor_code'] = 'True'
        data['password'] = generate_password()
        data['provider'] = backend.name

        try:
            user = User.objects.get(profile__meta__contains='"drfcode": {}'.format(user_data.get('drfocode')))
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
            user.profile.second_name = user_data.get('middlename')
            user.profile.meta = json.dumps({"drfcode": user_data.get('drfocode')})
            user.profile.save()
            user.save()

            set_user_preference(user, DARK_LANGUAGE_KEY, 'uk')

    return {'user': user}


@partial.partial
def fill_in_email(
        strategy, auth_entry, backend=None, user=None, social=None, allow_inactive_user=False, *args, **kwargs
):
    """
    Additional pipeline for checking user email from the provider on registration step.

    Checks if email is received from the provider and render the email form to the user if it is not.
    After successful adding the email, registration process continues.
    """
    if kwargs.get('is_new'):
        request = kwargs.get('request')
        email = strategy.session_get('email', None)

        if not email:
            return render_to_response(
                'register_email_form.html',
                {
                    'path': request.path,
                    'state': request.GET.get('state'),
                    'code': request.GET.get('code'),
                }
            )
        else:
            if request.method == 'POST':
                request.session['email'] = email
                return strategy.redirect(
                    '{backend_url}?state={state}&code={code}'.format(
                        backend_url=reverse('social:complete', args=(backend.name,)),
                        state=request.POST.get('state'),
                        code=request.POST.get('code'),
                    )
                )


@partial.partial
def set_logged_in_cookies(backend=None, user=None, strategy=None, auth_entry=None, current_partial=None,
                          *args, **kwargs):
    """
    This pipeline step sets the "logged in" cookie for authenticated users.

    Some installations have a marketing site front-end separate from
    edx-platform.  Those installations sometimes display different
    information for logged in versus anonymous users (e.g. a link
    to the student dashboard instead of the login page.)
    Since social auth uses Django's native `login()` method, it bypasses
    our usual login view that sets this cookie.  For this reason, we need
    to set the cookie ourselves within the pipeline.
    The procedure for doing this is a little strange.  On the one hand,
    we need to send a response to the user in order to set the cookie.
    On the other hand, we don't want to drop the user out of the pipeline.
    For this reason, we send a redirect back to the "complete" URL,
    so users immediately re-enter the pipeline.  The redirect response
    contains a header that sets the logged in cookie.
    If the user is not logged in, or the logged in cookie is already set,
    the function returns `None`, indicating that control should pass
    to the next pipeline step.
    """
    if not is_api(auth_entry) and user is not None and user.is_authenticated:
        request = strategy.request if strategy else None
        # n.b. for new users, user.is_active may be False at this point; set the cookie anyways.
        if request is not None:
            # Check that the cookie isn't already set.
            # This ensures that we allow the user to continue to the next
            # pipeline step once he/she has the cookie set by this step.
            has_cookie = user_authn_cookies.are_logged_in_cookies_set(request)
            if not has_cookie:
                try:
                    redirect_url = '{backend_url}?state={state}&code={code}'.format(
                        backend_url=reverse('social:complete', args=(backend.name,)),
                        state=kwargs['request'].GET.get('state'),
                        code=kwargs['request'].GET.get('code'),
                    )
                except ValueError:
                    # If for some reason we can't get the URL, just skip this step
                    # This may be overly paranoid, but it's far more important that
                    # the user log in successfully than that the cookie is set.
                    pass
                else:
                    response = redirect(redirect_url)
                    return user_authn_cookies.set_logged_in_cookies(request, response, user)
