import logging
from hashlib import md5

from common.djangoapps.third_party_auth.pipeline import AuthEntryError
from django.contrib.auth.models import User
from django.template.defaultfilters import slugify
from openedx.core.djangoapps.user_authn.views.registration_form import AccountCreationForm
from social_core.pipeline import partial
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
        if "data" in kwargs["response"]:
            user_data = kwargs["response"]["data"][0]
        else:
            user_data = kwargs["response"]

        log.info("Get user data")

        data["access_token"] = kwargs["response"]["access_token"]

        for key, value in backend.get_setting("USER_DATA_KEY_VALUES", {}).items():
            data[key] = user_data.get(value)

        if 'username' not in data or not data['username']:
            data['username'] = data.get('name', slugify(data['email']))

        if any((data['first_name'], data['last_name'])):
            data['name'] = u'{} {}'.format(data['first_name'], data['last_name']).strip()
        else:
            data['name'] = user_data.get('preferred_username')

        if not all((data["username"], data["email"])):
            raise AuthEntryError(
                backend, "One of the required parameters (username or email) is not received with the user data."
            )
    except AuthEntryError as e:
        log.exception(e)
        raise
    except Exception as e:
        log.exception(e)
        raise AuthEntryError(backend, "Cannot receive user's data")

    if not user:
        data.update(
            {
                "terms_of_service": "True",
                "honor_code": "True",
                "provider": backend.name,
                "password": User.objects.make_random_password(),
            }
        )

        try:
            user = User.objects.get(email=user_data.get("email"))
        except User.DoesNotExist:
            # Generate a new username if the current one is taken.
            if User.objects.filter(username=data['username']).exists():
                data['username'] = '{}_{}'.format(data['username'], md5(data['email']).hexdigest()[:4])

            form = AccountCreationForm(
                data=data,
                extra_fields={},
                extended_profile_fields={},
                do_third_party_auth=True,
                tos_required=False,
            )

            (user, profile, registration) = do_create_account(form)
            user.is_active = True
            user.save()

    return {"user": user}
