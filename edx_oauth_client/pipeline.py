import requests
import urllib2

from cms.djangoapps.course_creators.models import CourseCreator
from django.http import HttpResponseBadRequest
from django.contrib.auth.models import User
from openedx.core.djangoapps.profile_images.images import create_profile_images
from openedx.core.djangoapps.profile_images.views import _make_upload_dt, LOG_MESSAGE_CREATE
from openedx.core.djangoapps.user_api.accounts.image_helpers import get_profile_image_names, set_has_profile_image

from social.pipeline import partial
from django_countries import countries

from student.views import create_account_with_params, reactivation_email_for_user
from student.models import UserProfile

from third_party_auth.pipeline import (
    make_random_password, AuthEntryError
)

from logging import getLogger

log = getLogger(__name__)

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
        log.info('Get user data: %s', str(user_data))
        access_token = kwargs['response']['access_token']

        country = user_data.get('country')
        if not country:
            log.info('No country in response.')
            api = user_data['self'].replace('current-', '')
            headers = {'Authorization': 'Bearer {}'.format(access_token)}
            resp = requests.get(api, headers=headers)
            country = resp.json()['data'][0]['country']
            log.info('Get country from API: %s', country)
        country = dict(map(lambda x: (x[1], x[0]), countries)).get(country, country)

        data['username'] = clean_username(user_data['username'])
        data['first_name'] = user_data['firstName']
        data['last_name'] = user_data['lastName']
        data['email'] = user_data['email']
        data['country'] = country
        data['access_token'] = access_token
        data['name'] = data['first_name'] + " " + data['last_name']
        profile_image = user_data.get('profileImage') or user_data.get('coverImage')
    except Exception as e:
        log.error('Exception %s', e)
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

    user = user or response.get('user')

    try:
        user_profile = UserProfile.objects.get(user=user)
    except User.DoesNotExist:
        user_profile = None
    except User.MultipleObjectsReturned:
        user_profile = UserProfile.objects.filter(user=user)[0]

    if user_profile:
        user_profile.name = user.get_full_name()

        if not user_profile.country:
            user_profile.country = data['country']

        user_profile.save()

    if profile_image and user_profile and not user_profile.has_profile_image:
        upload_profile_image(profile_image, user.username)

    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            reactivation_email_for_user(user)
            raise AuthEntryError(backend, user.email)

    return {'user': user}


def clean_username(username):
    username = username.replace(' ', '_')
    prefix = 1

    while True:
        if User.objects.filter(username=username).exists():
            username += str(prefix)
            prefix += 1
        else:
            break

    return username


def upload_profile_image(profile_image, username):
    uploaded_file = urllib2.urlopen(profile_image)
    # generate profile pic and thumbnails and store them
    profile_image_names = get_profile_image_names(username)
    create_profile_images(uploaded_file, profile_image_names)

    # update the user account to reflect that a profile image is available.
    set_has_profile_image(username, True, _make_upload_dt())

    log.info(
        LOG_MESSAGE_CREATE,
        {'image_names': profile_image_names.values(), 'user_id': username}
    )
