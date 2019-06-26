# edx_oauth_client
SSO Generic Client for OAuth Identity Provider (ID).
### Installation guide
 - Setup your ID site as OAuth2 server. Add client for OpenEdx
Redirect uri must be **http://<edx_url>/auth/complete/custom-oauth2/**

 - Install this client
   ```
   pip install git+https://github.com/raccoongang/edx-oauth-client.git@hawthorn-master#egg=edx_oauth_client
   ```

 - Enable THIRD_PARTY_AUTH in edX

    In the edx/app/edxapp/lms.env.json file, edit the file so that it includes the following line in the features section.       And add  this backend.
    ```
    ...
    "FEATURES" : {
        ...
        "ENABLE_COMBINED_LOGIN_REGISTRATION": true,
        "ENABLE_THIRD_PARTY_AUTH": true,
        ...
    }
    ...
    "CUSTOM_OAUTH_PARAMS": {
        "PROVIDER_URL": "https://example.com",
        "AUTHORIZE_URL": "/oauth2/authorize",
        "GET_TOKEN_URL": "/oauth2/access_token",
        "PROVIDER_ID_KEY": "<unique identifier>",
        "PROVIDER_NAME": "custom-oauth2",
        "USER_DATA_URL": "/api/v0/users/me",
        "COOKIE_NAME": "cookie_name", # If you're want seamless authorization
        "COURSES_LIST_URL_PATH": "courses",  # write if course_list redirection is needed
        "USER_ACCOUNT_URL_PATH": "account",  # write if user account redirection is needed
        "DASHBOARD_URL_PATH": "user"  # write if dashboard redirection is needed
    },
    
    "THIRD_PARTY_AUTH_BACKENDS":["edx_oauth_client.backends.generic_oauth_client.GenericOAuthBackend"],
    ```

 - `CUSTOM_OAUTH_PARAMS` should be added to the `lms/envs/aws.py` if it is not supported by used OpenEdx.
    ```
    if FEATURES.get('ENABLE_THIRD_PARTY_AUTH'):
        CUSTOM_OAUTH_PARAMS = ENV_TOKENS.get('CUSTOM_OAUTH_PARAMS', {})
    ```

 - Add provider config in edX admin panel /admin/third_party_auth/oauth2providerconfig/
   - Enabled - **true**
   - backend-name - **custom-oauth2**
   - Skip registration form - **true**
   - Skip email verification - **true**
   - Client ID from Provider Admin OAuth Tab
   - Client Secret from Provider Admin OAuth Tab
   - Make it visible ? + link on Edx
   - name slug should be the same as provider name ? temp

 - If you're want seamless authorization add middleware classes for
 SeamlessAuthorization (crossdomain cookie support needed).
 In the `edx/app/edxapp/lms.env.json` file.
   ```
    "EXTRA_MIDDLEWARE_CLASSES": [
        "edx_oauth_client.middleware.SeamlessAuthorization",
        "edx_oauth_client.middleware.OAuthRedirection"
    ],
   ```

 - If SeamlessAuthorization shouldn't to work for Django administration add in `lms/envs/common.py`
   ```
   SOCIAL_AUTH_EXCLUDE_URL_PATTERN = r'^/admin'
   ```

   This feature requires to update you SSO Provider site's behaviour:

   Create multi-domain cookie `cookie_name` with the unique value for each user if user is logged in.
   And delete these cookie on logout.

   Also you should initiate user creation on edX after user creation on
   Provider. You need to send GET request to Edx API on url:
   ```
   https://<edx-url>/auth/complete/custom-oauth2/?state=<state>&code=<code>
   ```

   Where `state` is md5(time()) and `code` is code for authorization
   (create it if doesn't exist)

**Note.** If you work on local devstack. Inside your edx’s vagrant in
/etc/hosts add a row with your machine’s IP and provider’s vhost. For
example:
```192.168.0.197 sso.local```
