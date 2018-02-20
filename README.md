edx_oauth_client
SSO Client for Spalah project.

Install this client

pip install -e git+https://github.com/raccoongang/edx-oauth-client.git@spalah#egg=edx_oauth_client

In the edx/app/edxapp/lms.env.json file, edit the file so that it includes the following line in the features section. And add this backend.

...
"FEATURES" : {
    ...
    "ENABLE_COMBINED_LOGIN_REGISTRATION": true,
    "ENABLE_THIRD_PARTY_AUTH": true,
    "SSO_SPALAH_BACKEND_NAME": "http://spalahsite.domain"
}
...

"THIRD_PARTY_AUTH_BACKENDS":["edx_oauth_client.backends.spalah.SpalahOAuth2"]

Add provider config in edX admin panel /admin/third_party_auth/oauth2providerconfig/

Enabled - true
backend-name - spalah-oauth2
Skip registration form - true
Skip email verification - true
Client ID from Spalah Admin OAuth Tab
Client Secret from Spalah Admin OAuth Tab

If you're want seamless authorization add middleware classes for SeamlessAuthorization (cross-domain cookie support needed)

MIDDLEWARE_CLASSES += ("edx_oauth_client.middleware.SeamlessAuthorization",)

Also add

SOCIAL_AUTH_EXCLUDE_URL_PATTERN = 'r^/admin'
