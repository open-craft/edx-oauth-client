import re

from django.contrib.auth import get_user_model
from social_core.pipeline import partial

from student.forms import AccountCreationForm
from student.views import _do_create_account
from third_party_auth.pipeline import AuthEntryError, make_random_password

from logging import getLogger

log = getLogger(__name__)


@partial.partial
def ensure_user_information(
        strategy, auth_entry, backend=None, user=None, social=None,
        allow_inactive_user=False, *args, **kwargs):
    """
    Ensure that we have the necessary information about a user (either an
    existing account or registration data) to proceed with the pipeline.
    """

    if not user:
        UserModel = get_user_model()
        user_data = kwargs['response']
        user_data['username'] = re.sub('[\W]', '', user_data['email'])[:30]
        user_data['name'] = user_data['first_name'] + " " + user_data['last_name']
        user_data['password'] = make_random_password()
        log.info('Get user data from API: {}'.format(user_data))
        try:
            user = UserModel.objects.get(email=user_data['email'])
        except UserModel.DoesNotExist:
            form = AccountCreationForm(
                data=user_data,
                extra_fields={},
                extended_profile_fields={},
                enforce_username_neq_password=False,
                enforce_password_policy=False,
                tos_required=False,
            )

            (user, profile, registration) = _do_create_account(form)
            user.is_active = True
            user.set_unusable_password()
            user.save()

    return {'user': user}
