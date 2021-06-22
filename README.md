# Edx Oauth Client
SSO Client for Drupal.
### Installation guide
 - Setup your ID site as OAuth2 server. Add client for OpenEdx
Redirect uri must be **http://<edx_url>/auth/complete/custom-oauth2/**

 - Install this client
   ```
   pip install -e git+https://github.com/raccoongang/edx-oauth-client.git@juniper-master#egg=edx_oauth_client
   ```

 - Enable THIRD_PARTY_AUTH in edX
 
    In the `/edx/etc/lms.yml` file, edit the file so that it includes the following line in the features section. And add this backend.
    ```
    ...
    FEATURES:
        ENABLE_COMBINED_LOGIN_REGISTRATION: true
        ENABLE_THIRD_PARTY_AUTH: true
    ...
    THIRD_PARTY_AUTH_BACKENDS:
    - edx_oauth_client.backends.edx_oauth_client.GenericOAuthBackend
    ADDL_INSTALLED_APPS:
    - edx_oauth_client
    ```

 - Add provider config in edX admin panel `/admin/third_party_auth/oauth2providerconfig/`
   - Enabled - **true**
   - backend-name - **edx-oauth2**
   - Skip registration form - **true**
   - Skip email verification - **true**
   - Client ID from Provider Admin OAuth Tab
   - Client Secret from Provider Admin OAuth Tab
   - Other settings:
   ```json
   {
     "ACCESS_TOKEN_METHOD": "POST",
     "PROVIDER_URL": "<PROVIDER_URL>",
     "LOGIN_REDIRECT_URL": "<LOGIN_URL_ON_THE_PLATFORM>",
     "AUTHORIZATION_URL": "<AUTHORIZATION_URL>",
     "ID_KEY": "email",
     "USER_DATA_REQUEST_METHOD": "POST",
     "USER_DATA_KEY_VALUES": {
         "username": "<USERNAME_KEY_FROM_PROVIDER>",
         "name": "<NAME_KEY_FROM_PROVIDER>",
         "last_name": "<LAST_NAME_FROM_PROVIDER>",
         "email": "<EMAIL_FROM_PROVIDER>",
         "first_name": "FIRST_NAME_FROM_PROVIDER"
     },
    "ACCESS_TOKEN_URL": "<ACCESS_TOKEN_URL>",
    "USER_DATA_URL": "<USER_DATA_URL>"
   }
   ```

 - If you're want seamless authorization add middleware classes for SeamlessAuthorization (crossdomain cookie support needed)
   ```
   EXTRA_MIDDLEWARE_CLASSES: ["edx_oauth_client.middleware.SeamlessAuthorization",]
   ```
   
   This feature requires to update you provider site's behaviour:

   Create multi-domain cookies named `authenticated=1` and `authenticated_user=<username>` if user is logged in. And delete these cookies on logout
   
   Also you should initiate user creation on edX after user creation on Provider. You need to send GET request to Edx API on url:
   ```
   https://<edx-url>/auth/complete/edx-oauth2/?state=<state>&code=<code>
   ```
   
   Where `state` is md5(time()) and `code` is code for authorization (create it if doesn't exist)
 
**Note.** If you work on local devstack. Inside your edx’s vagrant in /etc/hosts add a row with your machine’s IP  and drupal’s vhost. For example:
```192.168.0.197 sso.local```
