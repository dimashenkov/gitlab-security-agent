<?php
















use WpOrg\Requests\Requests;














function yourls_http_get( $url, $headers = array(), $data = array(), $options = array() ) {
    return yourls_http_request( 'GET', $url, $headers, $data, $options );
}












function yourls_http_get_body( $url, $headers = array(), $data = array(), $options = array() ) {
    $return = yourls_http_get( $url, $headers, $data, $options );
    return isset( $return->body ) ? $return->body : null;
}














function yourls_http_post( $url, $headers = array(), $data = array(), $options = array() ) {
    return yourls_http_request( 'POST', $url, $headers, $data, $options );
}














function yourls_http_post_body( $url, $headers = array(), $data = array(), $options = array() ) {
    $return = yourls_http_post( $url, $headers, $data, $options );
    return isset( $return->body ) ? $return->body : null;
}







function yourls_http_get_proxy() {
    $proxy = false;

    if( defined( 'YOURLS_PROXY' ) ) {
        $proxy = YOURLS_PROXY;
        if( defined( 'YOURLS_PROXY_USERNAME' ) && defined( 'YOURLS_PROXY_PASSWORD' ) ) {
            $proxy = array( YOURLS_PROXY, YOURLS_PROXY_USERNAME, YOURLS_PROXY_PASSWORD );
        }
    }

    return yourls_apply_filter( 'http_get_proxy', $proxy );
}







function yourls_http_get_proxy_bypass_host() {
    $hosts = defined( 'YOURLS_PROXY_BYPASS_HOSTS' ) ? YOURLS_PROXY_BYPASS_HOSTS : false;

    return yourls_apply_filter( 'http_get_proxy_bypass_host', $hosts );
}









function yourls_http_default_options() {
    $options = array(
        'timeout'          => yourls_apply_filter( 'http_default_options_timeout', 3 ),
        'useragent'        => yourls_http_user_agent(),
        'follow_redirects' => true,
        'redirects'        => 3,
    );

    if( yourls_http_get_proxy() ) {
        $options['proxy'] = yourls_http_get_proxy();
    }

    return yourls_apply_filter( 'http_default_options', $options );
}











function yourls_send_through_proxy( $url ) {


    $pre = yourls_apply_filter( 'shunt_send_through_proxy', yourls_shunt_default(), $url );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $check = @parse_url( $url );

    if( !isset( $check['host'] ) ) {
        return false;
    }


    if ( $check === false )
        return true;


    $home = parse_url( yourls_get_yourls_site() );
    $local = array( 'localhost', '127.0.0.1', '127.1', '[::1]', ':', $home['host'] );

    if( in_array( $check['host'], $local ) )
        return false;

    $bypass = yourls_http_get_proxy_bypass_host();

    if( $bypass === false OR $bypass === '' ) {
        return true;
    }


    static $bypass_hosts;
    static $wildcard_regex = false;
    if ( null == $bypass_hosts ) {
        $bypass_hosts = preg_split( '|\s*,\s*|', $bypass );

        if ( false !== strpos( $bypass, '*' ) ) {
            $wildcard_regex = array();
            foreach ( $bypass_hosts as $host ) {
                $wildcard_regex[] = str_replace( '\*', '.+', preg_quote( $host, '/' ) );
                if ( false !== strpos( $host, '*' ) ) {
                    $wildcard_regex[] = str_replace( '\*\.', '', preg_quote( $host, '/' ) );
                }
            }
            $wildcard_regex = '/^(' . implode( '|', $wildcard_regex ) . ')$/i';
        }
    }

    if ( !empty( $wildcard_regex ) )
        return !preg_match( $wildcard_regex, $check['host'] );
    else
        return !in_array( $check['host'], $bypass_hosts );
}












function yourls_http_request( $type, $url, $headers, $data, $options ) {


    $pre = yourls_apply_filter( 'shunt_yourls_http_request', yourls_shunt_default(), $type, $url, $headers, $data, $options );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $options = array_merge( yourls_http_default_options(), $options );

    if( yourls_http_get_proxy() && !yourls_send_through_proxy( $url ) ) {
        unset( $options['proxy'] );
    }


    $type    = yourls_apply_filter('http_request_type', $type);
    $url     = yourls_apply_filter('http_request_url', $url);
    $headers = yourls_apply_filter('http_request_headers', $headers);
    $data    = yourls_apply_filter('http_request_data', $data);
    $options = yourls_apply_filter('http_request_options', $options);

    try {
        $result = Requests::request( $url, $headers, $data, $type, $options );
    } catch( \WpOrg\Requests\Exception $e ) {
        $result = yourls_debug_log( $e->getMessage() . ' (' . $type . ' on ' . $url . ')' );
    };

    return $result;
}







function yourls_http_user_agent() {
    return yourls_apply_filter( 'http_user_agent', 'YOURLS v'.YOURLS_VERSION.' +http://yourls.org/ (running on '.yourls_get_yourls_site().')' );
}
















function yourls_check_core_version() {

    global $yourls_user_passwords;

    $checks = yourls_get_option( 'core_version_checks' );


    if ( is_object( $checks ) && YOURLS_VERSION != $checks->version_checked ) {
        $checks = false;
    }

    if( !is_object( $checks ) ) {
        $checks = new stdClass;
        $checks->failed_attempts = 0;
        $checks->last_attempt    = 0;
        $checks->last_result     = '';
        $checks->version_checked = YOURLS_VERSION;
    }


    list( $total_urls, $total_clicks ) = array_values(yourls_get_db_stats());


    $stuff = array(


        'md5'                => md5( YOURLS_SITE . YOURLS_ABSPATH ),


        'failed_attempts'    => $checks->failed_attempts,
        'yourls_site'        => defined( 'YOURLS_SITE' ) ? yourls_get_yourls_site() : 'unknown',
        'yourls_version'     => defined( 'YOURLS_VERSION' ) ? YOURLS_VERSION : 'unknown',
        'php_version'        => PHP_VERSION,
        'mysql_version'      => yourls_get_db('read-check_core_version')->mysql_version(),
        'locale'             => yourls_get_locale(),


        'db_driver'          => defined( 'YOURLS_DB_DRIVER' ) ? YOURLS_DB_DRIVER : 'unset',
        'db_ext_pdo'         => extension_loaded( 'PDO' )     ? 1 : 0,
        'db_ext_mysql'       => extension_loaded( 'mysql' )   ? 1 : 0,
        'db_ext_mysqli'      => extension_loaded( 'mysqli' )  ? 1 : 0,
        'ext_curl'           => extension_loaded( 'curl' )    ? 1 : 0,


        'yourls_private'     => defined( 'YOURLS_PRIVATE' ) && YOURLS_PRIVATE ? 1 : 0,
        'yourls_unique'      => defined( 'YOURLS_UNIQUE_URLS' ) && YOURLS_UNIQUE_URLS ? 1 : 0,
        'yourls_url_convert' => defined( 'YOURLS_URL_CONVERT' ) ? YOURLS_URL_CONVERT : 'unknown',


        'num_users'          => count( $yourls_user_passwords ),
        'num_active_plugins' => yourls_has_active_plugins(),
        'num_pages'          => defined( 'YOURLS_PAGEDIR' ) ? count( (array) glob( YOURLS_PAGEDIR .'/*.php') ) : 0,
        'num_links'          => $total_urls,
        'num_clicks'         => $total_clicks,
    );

    $stuff = yourls_apply_filter( 'version_check_stuff', $stuff );


    $url = 'http://api.yourls.org/core/version/1.1/';
    if( yourls_can_http_over_ssl() ) {
        $url = yourls_set_url_scheme($url, 'https');
    }
    $req = yourls_http_post( $url, array(), $stuff );

    $checks->last_attempt = time();
    $checks->version_checked = YOURLS_VERSION;


    if( is_string( $req ) or !$req->success ) {
        $checks->failed_attempts = $checks->failed_attempts + 1;
        yourls_update_option( 'core_version_checks', $checks );
        if( is_string($req) ) {
            yourls_debug_log('Version check failed: ' . $req);
        }
        return false;
    }


    $json = json_decode( trim( $req->body ) );

    if( yourls_validate_core_version_response($json) ) {

        $checks->failed_attempts = 0;
        $checks->last_result     = $json;
        yourls_update_option( 'core_version_checks', $checks );

        return $json;
    }


    return false;
}














function yourls_validate_core_version_response($json) {
    return (
        yourls_validate_core_version_response_keys($json)
     && $json->latest === yourls_sanitize_version($json->latest)
     && $json->zipurl === yourls_sanitize_url($json->zipurl)
     && $json->latest === yourls_get_version_from_zipball_url($json->zipurl)
     && yourls_is_valid_github_repo_url($json->zipurl)
    );
}








function yourls_get_version_from_zipball_url($zipurl) {
    $version = '';
    $parts = explode('/', parse_url(yourls_sanitize_url($zipurl), PHP_URL_PATH) ?? '');

    if( count($parts) > 1 ) {
        $version = end($parts);
    }
    return $version;
}








function yourls_is_valid_github_repo_url($url) {
    $url = yourls_sanitize_url($url);
    return (
        join('.',array_slice(explode('.', parse_url($url, PHP_URL_HOST) ?? ''), -2, 2)) === 'github.com'



        && substr( parse_url($url, PHP_URL_PATH), 0, 21 ) === '/repos/YOURLS/YOURLS/'

    );
}








function yourls_validate_core_version_response_keys($json) {
    $keys = array('latest', 'zipurl');
    return (
        count(array_diff(array_keys((array)$json), $keys)) === 0
        && isset($json->latest)
        && isset($json->zipurl)
        && is_string($json->latest)
        && is_string($json->zipurl)
    );
}










function yourls_maybe_check_core_version() {

    $pre = yourls_apply_filter( 'shunt_maybe_check_core_version', yourls_shunt_default() );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    if (yourls_skip_version_check()) {
        return false;
    }

    if (!yourls_is_admin()) {
        return false;
    }

    $checks = yourls_get_option( 'core_version_checks' );







    if( !empty( $checks->last_result )
        AND
        (
            ( $checks->failed_attempts == 0 && ( ( time() - $checks->last_attempt ) < 24 * 3600 ) )
            OR
            ( $checks->failed_attempts > 0  && ( ( time() - $checks->last_attempt ) <  2 * 3600 ) )
        )
        AND ( $checks->version_checked == YOURLS_VERSION )
    )
        return false;


    $new_check = yourls_check_core_version();


    if( false == $new_check && !isset( $checks->last_result->latest ) )
        return false;

    return true;
}







function yourls_skip_version_check() {
    return yourls_apply_filter('skip_version_check', defined('YOURLS_NO_VERSION_CHECK') && YOURLS_NO_VERSION_CHECK);
}







function yourls_can_http_over_ssl() {
    $ssl_curl = $ssl_socket = false;

    if( function_exists( 'curl_exec' ) ) {
        $curl_version  = curl_version();
        $ssl_curl = ( $curl_version['features'] & CURL_VERSION_SSL );
    }

    if( function_exists( 'stream_socket_client' ) ) {
        $ssl_socket = extension_loaded( 'openssl' ) && function_exists( 'openssl_x509_parse' );
    }

    return ( $ssl_curl OR $ssl_socket );
}
