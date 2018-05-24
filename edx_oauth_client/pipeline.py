import string  # pylint: disable-msg=deprecated-module
import json
import logging
import requests

from cms.djangoapps.course_creators.models import CourseCreator
from django.http import HttpResponseBadRequest, HttpResponse
from django.contrib.auth.models import User
from django.conf import settings

from social.pipeline import partial
from django_countries import countries

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

    token_url = '{}/api/v1/user/token.json'.format(settings.FEATURES['DRUPAL_PRIVIDER_URL'])
    auth_url = '{}/api/v1/user/login.json'.format(settings.FEATURES['DRUPAL_PRIVIDER_URL'])
    user_info_url = '{}/api/v1/user/{{}}.json'.format(settings.FEATURES['DRUPAL_PRIVIDER_URL'])
    response = {}
    data = {}
    user_data = {}
    session = requests.session()
    session.headers['Content-type'] = 'application/json'

    try:
        if 'data' in kwargs['response']:
            user_data = kwargs['response']['data'][0]
        else:
            user_data = kwargs['response']
        log.info('Get user data: %s', str(user_data))
        access_token = kwargs['response']['access_token']

        country = user_data.get('country')
        if not country and 'self' in user_data:
            log.info('No country in response.')
            api = user_data['self'].replace('current-', '')
            headers = {'Authorization': 'Bearer {}'.format(access_token)}
            resp = requests.get(api, headers=headers)
            json_resp = resp.json()
            if 'data' in json_resp:
                country = json_resp['data'][0]['country']
                log.info('Get country from API: %s', country)
                country = dict(map(lambda x: (x[1], x[0]), countries)).get(country, country)

        gender = 'o'
        fname = ''
        lname = ''
        r = session.post(token_url)
        csrf_token = None
        if r.ok:
            log.info('Get the API token')
            csrf_token = r.json().get('token')

        if csrf_token:
            log.info('Post API auth data')
            session.headers['X-CSRF-Token'] = csrf_token
            r = session.post(auth_url, data=json.dumps({
                'username': settings.FEATURES['DRUPAL_API_USER'],
                'password': settings.FEATURES['DRUPAL_API_PASSWORD']
            }))

            if r.ok:
                r = session.get(user_info_url.format(user_data.get(settings.FEATURES['DRUPAL_ID_KEY'])))
                api_data = r.ok and r.json() or {}
                full_name =  (api_data.get('field_full_name', {}) or {}).get('und', [{}])[0].get('value', '')
                gender = (api_data.get('field_gender', {}) or {}).get('und', [{}])[0].get('value')
                log.info('Get gender %s for user %s', gender, user_data['email'])
                gender = gender and gender[0].lower() or 'o'
                full_name_list = full_name.split()
                fname, lname = full_name_list and (full_name_list[0], ' '.join(full_name_list[1:])) or ('', '')

        data['username'] = user_data.get('username', user_data.get('name'))
        data['first_name'] = user_data.get('firstName', fname)
        data['last_name'] = user_data.get('lastName', lname)
        data['email'] = user_data['email']
        data['country'] = country or '--'
        data['access_token'] = access_token
        if data['first_name'] or data['last_name']:
            data['name'] = data['first_name'] + " " + data['last_name']
        else:
            data['name'] = user_data.get('name', user_data.get('preferred_username'))
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
            user = User.objects.get(social_auth__uid=user_data.get(backend.ID_KEY))
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
        user_profile = UserProfile.objects.create(user=user)
    except User.MultipleObjectsReturned:
        user_profile = UserProfile.objects.filter(user=user)[0]

    if user_profile:
        user_profile.name = user.get_full_name()
        user_profile.gender = gender
        user_profile.name = data.get('name')
        user_profile.save()

    if user and not user.is_active:
        if allow_inactive_user:
            pass
        elif social is not None:
            reactivation_email_for_user(user)
            raise AuthEntryError(backend, user.email)

    return {'user': user}
