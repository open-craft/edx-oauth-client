import string  # pylint: disable-msg=deprecated-module
import json
import logging

from cms.djangoapps.course_creators.models import CourseCreator
from django.http import HttpResponseBadRequest, HttpResponse
from django.contrib.auth.models import User

from social.pipeline import partial

from student.views import create_account_with_params, reactivation_email_for_user
from student.models import UserProfile, CourseAccessRole
from student.roles import (
    CourseInstructorRole, CourseStaffRole, GlobalStaff, OrgStaffRole,
    UserBasedRole, CourseCreatorRole, CourseBetaTesterRole, OrgInstructorRole,
    LibraryUserRole, OrgLibraryUserRole
)
from third_party_auth.pipeline import (
    make_random_password, AuthEntryError
)

from opaque_keys.edx.keys import CourseKey

# The following are various possible values for the AUTH_ENTRY_KEY.
AUTH_ENTRY_LOGIN = 'login'
AUTH_ENTRY_REGISTER = 'register'
AUTH_ENTRY_ACCOUNT_SETTINGS = 'account_settings'

AUTH_ENTRY_LOGIN_2 = 'account_login'
AUTH_ENTRY_REGISTER_2 = 'account_register'

# Entry modes into the authentication process by a remote API call (as opposed to a browser session).
AUTH_ENTRY_LOGIN_API = 'login_api'
AUTH_ENTRY_REGISTER_API = 'register_api'


@partial.partial
def ensure_user_information(
        strategy, auth_entry, backend=None, user=None, social=None,
        allow_inactive_user=False, *args, **kwargs):
    """
    Ensure that we have the necessary information about a user (either an
    existing account or registration data) to proceed with the pipeline.
    """

    response = {}
    data = {}
    try:
        user_data = kwargs['response']['data'][0]
        data['username'] = user_data['username']
        data['first_name'] = user_data['firstName']
        data['last_name'] = user_data['lastName']
        data['email'] = user_data['email']
        data['country'] = user_data.get('country')
        data['access_token'] = kwargs['response']['access_token']
        data['name'] = data['first_name'] + " " + data['last_name']
    except IndexError, KeyError:
        raise AuthEntryError(backend, 'can\' get user data.')

    def dispatch_to_register():
        """Force user creation on login or register"""

        request = strategy.request
        data['terms_of_service'] = "True"
        data['honor_code'] = 'True'
        data['password'] = make_random_password()

        data['provider'] = backend.name

        if request.session.get('ExternalAuthMap'):
            del request.session['ExternalAuthMap']

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            create_account_with_params(request, data)
            user = request.user
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.is_active = True
            user.save()
            CourseCreator.objects.get_or_create(user=user)
        return {'user': user}

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
            response = dispatch_to_register()
        elif auth_entry in [AUTH_ENTRY_REGISTER, AUTH_ENTRY_REGISTER_2]:
            response = dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(
                backend, 'auth_entry is wrong. Settings requires a user.')
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')
    else:
        if user.id != 1:
            user.email = data['email']
            user.username = data['username']
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.save()
            CourseCreator.objects.get_or_create(user=user)

        try:
            user_profile = UserProfile.objects.get(user=user)
        except User.DoesNotExist:
            user_profile = None
        except User.MultipleObjectsReturned:
            user_profile = UserProfile.objects.filter(user=user)[0]

        if user_profile:
            user_profile.name = user.get_full_name()
            user_profile.save()

    user = user or response.get('user')
    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            reactivation_email_for_user(user)
            raise AuthEntryError(backend, user.email)

    return {'user': user}
