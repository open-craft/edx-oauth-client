# Edx Oauth Client
SSO Client for Drupal.
### Installation guide
 - Setup your ID site as OAuth2 server. Add client for OpenEdx
Redirect uri must be **http://<edx_url>/auth/complete/custom-oauth2/**

 - Install this client
   ```bash
   pip install -e git+https://github.com/open-craft/edx-oauth-client.git@v2.0.0#egg=edx_oauth_client
   ```

 - Enable THIRD_PARTY_AUTH in edX
 
    In the `/edx/etc/lms.yml` file, edit the file so that it includes the following line in the features section. And add this backend.
    ```yaml
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

 - Add provider config
 
    In the `/edx/etc/lms.yml` file, edit the file so that it includes the following line in the features section. And add this backend.
    ```yaml
    ...
    FEATURES:
      CUSTOM_OAUTH_PARAMS:
        BACKEND_NAME: CUSTOM_NAME
        PROVIDER_URL: https://example.com
        ACCESS_TOKEN_URL: /oauth/token
        AUTHORIZATION_URL: /oauth/authorize
        USER_DATA_URL: /oauth/user
        ID_KEY: id
        DEFAULT_SCOPE:
          - profile
          - email
        USER_DATA_KEY_VALUES:
          username: username
          name: name
          first_name: first_name
          last_name: last_name
          email: email
    ...
    ```

 - (Experimental) Add provider config in edX admin panel `/admin/third_party_auth/oauth2providerconfig/`
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

 - If you want seamless authorization add the `seamless_authorization` middleware (crossdomain cookie support needed)
   ```
   EXTRA_MIDDLEWARE_CLASSES: ["edx_oauth_client.middleware.seamless_authorization",]
   ```
 - If you want to configure a backend (other than GenericOAuthBackend) used by the seamless authorization,
   set its name as the `SEAMLESS_AUTHORIZATION_BACKEND` variable in your settings.
 - If you want to use the seamless authorization only when a specific cookie is passed with the request,
   set its name as the `SEAMLESS_AUTHORIZATION_CHECK_COOKIE` variable in your settings.
