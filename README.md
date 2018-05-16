# edx_oauth_client
SSO Client for Drupal.
### Instalation guide
 - Setup your Drupal site as OAuth2 server. Add client for OpenEdx
Redirect uri must be **http://<edx_url>/auth/complete/drupal-oauth2/**

 - Install this client
   ```
   pip install -e git+https://github.com/raccoongang/edx-oauth-client.git@drupal#egg=edx_oauth_client
   ```

 - Enable THIRD_PARTY_AUTH in edX
 
    In the edx/app/edxapp/lms.env.json file, edit the file so that it includes the following line in the features section.       And add  this backend.
    ```
    ...
    "FEATURES" : {
        ...
        "ENABLE_COMBINED_LOGIN_REGISTRATION": true,
        "ENABLE_THIRD_PARTY_AUTH": true,
        "DRUPAL_PRIVIDER_URL": "http://drupalsite.domain",
        "DRUPAL_AUTHORIZE_URL":"/oauth2/authorize",
        "DRUPAL_GET_TOKEN_URL":"/oauth2/token",
    }
    ...
    "THIRD_PARTY_AUTH_BACKENDS":["edx_oauth_client.backends.drupal_oauth_client.DrupalOAuthBackend"]
    ```
   
 - Add in file **lms/envs/common.py**. It's preffered to place it somewhere at the top of the list
    ```
    INSTALLED_APPS = (
        ...
        'edx_oauth_client',
        ...
    )
    ```
    
 - Add provider config in edX admin panel /admin/third_party_auth/oauth2providerconfig/
   - Enabled - **true**
   - backend-name - **drupal-oauth2**
   - Skip registration form - **true**
   - Skip email verification - **true**
   - Client ID from Drupal Admin OAuth Tab
   - Client Secret from Drupal Admin OAuth Tab
    
 - If you're want seamless authorization add middleware classes for SeamlessAuthorization (crossdomain cookie support needed)
   ```
   MIDDLEWARE_CLASSES += ("edx_oauth_client.middleware.SeamlessAuthorization",)
   ```
   
   This feature requers to update you Drupal site's behaviour:

   Create multi-domain cookies named “authenticated”=1 and “authenticated_user”=”<username>” if user is logged in. And delete these cookies on logout
   
   Also you should initiate user creation on edX after user creation on Drupal. You need to send GET request to Edx API on url:
   ```
   https://<edx-url>/auth/complete/drupal-oauth2/?state=<state>&code=<code>
   ```
   
   Where `state` is md5(time()) and `code` is code for authorization (create it if doesn't exist)
 
**Note.** If you work on local devstack. Inside your edx’s vagrant in /etc/hosts add a row with your machine’s IP  and drupal’s vhost. For example:
```192.168.0.197 drupal.local```
