# edx_wp_oauth_client
SSO Client for [Wordpress OAuth plugin provider][wp_oauth_provider].

Install  WP plugin following instruction. In wp-admin OAuth Server tab add new client
Redirect uri must be **http://<edx_url>/auth/complete/wp-oauth2/**

 - Install this client
   ```
   pip install -e git+https://github.com/xahgmah/edx-wp-oauth-client.git#egg=edx_wp_oauth_client
   ```

 - Enable THIRD_PARTY_AUTH in edX
 
    In the edx/app/edxapp/lms.env.json file, edit the file so that it includes the following line in the features section.       And add  this backend.
    ```
    ...
    "FEATURES" : {
        ...
        "ENABLE_COMBINED_LOGIN_REGISTRATION": true,
        "ENABLE_THIRD_PARTY_AUTH": true
    }
    ...
    "THIRD_PARTY_AUTH_BACKENDS":["edx_wp_oauth_client.backends.wp_oauth_client.WPOAuthBackend"]
    ```
   
 - Add in file **lms/envs/common.py**. It's preffered to place it somewhere at the top of the list
    ```
    INSTALLED_APPS = (
        ...
        'sso_edx_ml',
        ...
    )
    ```
 - Add middleware classes for SeamlessAuthorization
   ```
   MIDDLEWARE_CLASSES += ("edx_wp_oauth_client.middleware.SeamlessAuthorization",)
   ```
 - Add provider config in edX admin panel /admin/third_party_auth/oauth2providerconfig/
   - Enabled - **true**
   - backend-name - **wp-oauth2**
   - Skip registration form - **true**
   - Skip email verification - **true**
   - Client ID from WP Admin OAuth Tab
   - Client Secret from WP Admin OAuth Tab
    

 
**Note.** If you work on local devstack. Inside your edx’s vagrant in /etc/hosts add a row with your machines’s IP  and wordpress’s >vhost. For example:
```192.168.0.197 wp.local```

[wp_oauth_provider]: <https://ru.wordpress.org/plugins/oauth2-provider/>
