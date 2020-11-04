import logging

from django.contrib.auth.models import User
from social_core.pipeline import partial
from third_party_auth.pipeline import AuthEntryError, is_api, get_complete_url

from openedx.core.djangoapps.user_authn.views.registration_form import AccountCreationForm
from openedx.core.djangoapps.user_authn.utils import generate_password
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

        for key, value in backend.setting("USER_DATA_KEY_VALUES").items():
            data[key] = user_data.get(value)

        if not all((data["username"], data["email"])):
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
        data["terms_of_service"] = "True"
        data["honor_code"] = "True"
        data["password"] = generate_password()
        data["provider"] = backend.name

        try:
            user = User.objects.get(email=user_data.get("email"))
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

    return {"user": user}
