# edx_oauth_client
SSO Generic Client for OAuth Identity Provider (ID) - [Wordpress OAuth Server](https://wordpress.org/plugins/oauth2-provider/).
### Installation guide
 - Install  WP OAuth Server following instruction. In wp-admin OAuth Server tab add new client.
Redirect uri must be **http://<edx_url>/auth/complete/custom-oauth2/**

 - Install this client
   ```
   pip install git+https://github.com/raccoongang/edx-oauth-client.git@letstudy-hawthorn-wordpress#egg=edx_oauth_client
   ```

 - Enable THIRD_PARTY_AUTH in edX

    In the `edx/app/edxapp/lms.env.json` file, edit the file so that it includes the following line in the features section.       And add  this backend.
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
        "AUTHORIZE_URL": "/oauth/authorize",
        "GET_TOKEN_URL": "/oauth/token",
        "USER_DATA_URL": "/oauth/me",
        "PROVIDER_NAME": "custom-oauth2",
        "PROVIDER_ID_KEY": "<unique identifier>", # For example: "user_email" or "user_login"
        "COOKIE_NAME": "authenticated", # If you're want seamless authorization
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
 - Add in file `lms/envs/common.py`. It's preffered to place it somewhere at the top of the list
     ```
    INSTALLED_APPS = (
    ...
    'edx_oauth_client',
    ...
				)
    ```

 - Add provider config in edX admin panel `/admin/third_party_auth/oauth2providerconfig/`
   - Enabled - **true**
   - backend-name - **custom-oauth2**
   - Skip registration form - **true**
   - Skip email verification - **true**
   - Client ID from Provider Admin OAuth Tab
   - Client Secret from Provider Admin OAuth Tab
   - Make it visible ? + link on Edx
   - name slug should be the same as provider name ? temp

 - If you're want seamless authorization, middleware classes for
 SeamlessAuthorization and OAuthRedirection (crossdomain cookie support needed).
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
   
 - And add this code in the end of **functions.php** for your Wordpress theme
   
   This feature create multi-domain cookie cookie_name with the unique value for each user if user is logged in. And delete these cookie on logout.
      ```
   $auth_cookie_name = "authenticated";
		 $domain_name = "<YOUR_DOMAIN>";
		 
		 add_action('wp_login', 'set_auth_cookie', 1, 2);
		 function set_auth_cookie($user_login, $user)
		 {
		     /**
		      * After login set multidomain cookies which gives to edx understanding that user have already registrated
		      */
		     global $auth_cookie_name, $domain_name;
		     setcookie($auth_cookie_name, 1, time() + 60 * 60 * 24 * 30, "/", ".{$domain_name}");
		     setcookie($auth_cookie_name . "_user", $user->nickname, time() + 60 * 60 * 24 * 30, "/", ".{$domain_name}");
		 }
		 
		 add_action('wp_logout', 'remove_custom_cookie_admin');
		 function remove_custom_cookie_admin()
		 {
		     /**
		      * After logout delete multidomain cookies which was added above
		      */
		     global $auth_cookie_name, $domain_name;
		     setcookie($auth_cookie_name, "", time() - 3600, "/", ".{$domain_name}");
		     setcookie($auth_cookie_name . "_user", "", time() - 3600, "/", ".{$domain_name}");
		 }
		 
		 add_action('user_register', 'create_edx_user_after_registration', 10, 1);
		 
		 function create_edx_user_after_registration($user_id)
		 {
		     /**
		      * Create edX user after user creation on Wordpress. This hack allows make API requests to edX before
		      * the user visit edX first time.
		      * Also this function allows update user data by wordpress initiative
		      */
		     global $wpdb, $domain_name;
		     # fix this url with your LMS address
		     $client_url = "https://courses.{$domain_name}/auth/complete/custom-oauth2/";
		     $query = "SELECT * FROM `wp_oauth_clients` WHERE `redirect_uri` = '{$client_url}'";
		     $client = $wpdb->get_row($query);
		     if ($client) {
		         require_once ABSPATH . '/wp-content/plugins/oauth2-provider/library/OAuth2/Autoloader.php';
		         OAuth2\Autoloader::register();
		         $storage = new OAuth2\Storage\Wordpressdb();
		         $authCode = new OAuth2\OpenID\ResponseType\AuthorizationCode($storage);
		         $code = $authCode->createAuthorizationCode($client->client_id, $user_id, $client->redirect_uri);
		         $params = http_build_query(array(
		             'state' => md5(time()),
		             'code' => $code
		         ));
		         file_get_contents($client->redirect_uri . "?" . $params);
		     }
		 }
   ```
**Note.** If you work on local devstack. Inside your edx’s vagrant in
/etc/hosts add a row with your machine’s IP and provider’s vhost. For
example:
```192.168.0.197 sso.local```
