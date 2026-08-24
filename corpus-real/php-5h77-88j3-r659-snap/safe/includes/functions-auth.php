<?php










function yourls_maybe_require_auth() {
    if( yourls_is_private() ) {
        yourls_do_action( 'require_auth' );
        require_once( YOURLS_INC.'/auth.php' );
    } else {
        yourls_do_action( 'require_no_auth' );
    }
}






function yourls_is_valid_user() {

    $pre = yourls_apply_filter( 'shunt_is_valid_user', yourls_shunt_default() );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }


    $unfiltered_valid = false;


    if( isset( $_GET['action'] ) && $_GET['action'] == 'logout' && isset( $_REQUEST['nonce'] ) ) {

        yourls_verify_nonce('admin_logout', $_REQUEST['nonce'], 'logout');
        yourls_do_action( 'logout' );
        yourls_store_cookie( '' );
        return yourls__( 'Logged out successfully' );
    }



    yourls_do_action( 'pre_login' );


    if


        ( yourls_is_API() &&
          isset( $_REQUEST['timestamp'] ) && !empty($_REQUEST['timestamp'] ) &&
          isset( $_REQUEST['signature'] ) && !empty($_REQUEST['signature'] )
        )
        {
            yourls_do_action( 'pre_login_signature_timestamp' );
            $unfiltered_valid = yourls_check_signature_timestamp();
        }

    elseif


        ( yourls_is_API() &&
          !isset( $_REQUEST['timestamp'] ) &&
          isset( $_REQUEST['signature'] ) && !empty( $_REQUEST['signature'] )
        )
        {
            yourls_do_action( 'pre_login_signature' );
            $unfiltered_valid = yourls_check_signature();
        }

    elseif

        ( isset( $_REQUEST['username'] ) && isset( $_REQUEST['password'] )
          && !empty( $_REQUEST['username'] ) && !empty( $_REQUEST['password']  ) )
        {
            yourls_do_action( 'pre_login_username_password' );
            $unfiltered_valid = yourls_check_username_password();
        }

    elseif

        ( !yourls_is_API() &&
          isset( $_COOKIE[ yourls_cookie_name() ] ) )
        {
            yourls_do_action( 'pre_login_cookie' );
            $unfiltered_valid = yourls_check_auth_cookie();
        }


    $valid = yourls_apply_filter( 'is_valid_user', $unfiltered_valid );


    if ( $valid ) {
        yourls_do_action( 'login' );


        if ( !yourls_is_API() ) {
            yourls_store_cookie( YOURLS_USER );


            if( isset( $_REQUEST['username'] ) && isset( $_REQUEST['password'] ) && isset( $_SERVER['REQUEST_URI'] ) ) {


                return yourls_redirect( yourls_sanitize_url_safe($_SERVER['REQUEST_URI']) );
            }
        }


        return true;
    }


    yourls_do_action( 'login_failed' );

    if ( isset( $_REQUEST['username'] ) || isset( $_REQUEST['password'] ) ) {
        return yourls__( 'Invalid username or password' );
    } else {
        return yourls__( 'Please log in' );
    }
}






function yourls_check_username_password() {
    global $yourls_user_passwords;


    if(!yourls_is_API()) {
        yourls_verify_nonce('admin_login');
    }

    if( isset( $yourls_user_passwords[ $_REQUEST['username'] ] ) && yourls_check_password_hash( $_REQUEST['username'], $_REQUEST['password'] ) ) {
        yourls_set_user( $_REQUEST['username'] );
        return true;
    }
    return false;
}








function yourls_check_password_hash($user, $submitted_password ) {
    global $yourls_user_passwords;

    if( !isset( $yourls_user_passwords[ $user ] ) )
        return false;

    if ( yourls_has_phpass_password( $user ) ) {

        list( , $hash ) = explode( ':', $yourls_user_passwords[ $user ] );
        $hash = str_replace( '!', '$', $hash );
        return ( yourls_phpass_check( $submitted_password, $hash ) );
    } else if( yourls_has_md5_password( $user ) ) {

        list( , $salt, ) = explode( ':', $yourls_user_passwords[ $user ] );
        return( $yourls_user_passwords[ $user ] == 'md5:'.$salt.':'.md5( $salt . $submitted_password ) );
    } else {

        return( $yourls_user_passwords[ $user ] === $submitted_password );
    }
}








function yourls_hash_passwords_now( $config_file ) {
    if( !is_readable( $config_file ) ) {
        yourls_debug_log( 'Cannot hash passwords: cannot read file ' . $config_file );
        return 'cannot read file';
    }

    if( !is_writable( $config_file ) ) {
        yourls_debug_log( 'Cannot hash passwords: cannot write file ' . $config_file );
        return 'cannot write file';
    }

    $yourls_user_passwords = [];


    $errlevel = error_reporting();
    error_reporting( 0 );
    require $config_file;
    error_reporting( $errlevel );

    $configdata = file_get_contents( $config_file );

    if( $configdata == false ) {
        yourls_debug_log('Cannot hash passwords: file_get_contents() false with ' . $config_file);
        return 'could not read file';
    }

    $to_hash = 0;
    foreach ( $yourls_user_passwords as $user => $password ) {

        $password ??= '';
        if ( !yourls_has_phpass_password( $user ) && !yourls_has_md5_password( $user ) ) {
            $to_hash++;
            $hash = yourls_phpass_hash( $password );

            $hash = str_replace( '$', '!', $hash );
            $quotes = "'" . '"';
            $pattern = "/[$quotes]" . preg_quote( $user, '/' ) . "[$quotes]\s*=>\s*[$quotes]" . preg_quote( $password, '/' ) . "[$quotes]/";
            $replace = "'$user' => 'phpass:$hash' /* Password encrypted by YOURLS */ ";
            $count = 0;
            $configdata = preg_replace( $pattern, $replace, $configdata, -1, $count );

            if ( $count != 1 ) {
                yourls_debug_log( "Problem with preg_replace for password hash of user $user" );
                return 'preg_replace problem';
            }
        }
    }

    if( $to_hash == 0 ) {
        yourls_debug_log('Cannot hash passwords: no password found in ' . $config_file);
        return 'no password found';
    }

    $success = file_put_contents( $config_file, $configdata );
    if ( $success === FALSE ) {
        yourls_debug_log( 'Failed writing to ' . $config_file );
        return 'could not write file';
    }

    yourls_debug_log('Successfully encrypted passwords in ' . basename($config_file));
    return true;
}








function yourls_phpass_hash( $password ) {





    $algo    = yourls_apply_filter('hash_algo', PASSWORD_BCRYPT);









    $options = yourls_apply_filter('hash_options', [] );

    return password_hash($password, $algo, $options);
}









function yourls_phpass_check( $password, $hash ) {
    return password_verify($password, $hash);
}








function yourls_has_cleartext_passwords() {
    global $yourls_user_passwords;
    foreach ( $yourls_user_passwords as $user => $pwdata ) {
        if ( !yourls_has_md5_password( $user ) && !yourls_has_phpass_password( $user ) ) {
            return true;
        }
    }
    return false;
}











function yourls_has_md5_password( $user ) {
    global $yourls_user_passwords;
    return(    isset( $yourls_user_passwords[ $user ] )
            && substr( $yourls_user_passwords[ $user ], 0, 4 ) == 'md5:'
            && strlen( $yourls_user_passwords[ $user ] ) == 42
           );
}












function yourls_has_phpass_password( $user ) {
    global $yourls_user_passwords;
    return( isset( $yourls_user_passwords[ $user ] )
            && substr( $yourls_user_passwords[ $user ], 0, 7 ) == 'phpass:'
    );
}






function yourls_check_auth_cookie() {
    global $yourls_user_passwords;
    foreach( $yourls_user_passwords as $valid_user => $valid_password ) {
        if ( yourls_cookie_value( $valid_user ) === $_COOKIE[ yourls_cookie_name() ] ) {
            yourls_set_user( $valid_user );
            return true;
        }
    }
    return false;
}














function yourls_check_signature_timestamp() {
    if(   !isset( $_REQUEST['signature'] ) OR empty( $_REQUEST['signature'] )
       OR !isset( $_REQUEST['timestamp'] ) OR empty( $_REQUEST['timestamp'] )
    ) {
        return false;
    }


    if( !yourls_check_timestamp( $_REQUEST['timestamp'] )) {
        return false;
    }


    $hash_function = isset($_REQUEST['hash']) ? (string)$_REQUEST['hash'] : 'md5';
    if( !in_array($hash_function, hash_algos()) ) {
        return false;
    }


    global $yourls_user_passwords;
    foreach( $yourls_user_passwords as $valid_user => $valid_password ) {
        if (
            hash( $hash_function, $_REQUEST['timestamp'].yourls_auth_signature( $valid_user ) ) === $_REQUEST['signature']
            or
            hash( $hash_function, yourls_auth_signature( $valid_user ).$_REQUEST['timestamp'] ) === $_REQUEST['signature']
            ) {
            yourls_set_user( $valid_user );
            return true;
        }
    }


    return false;
}







function yourls_check_signature() {
    if( !isset( $_REQUEST['signature'] ) OR empty( $_REQUEST['signature'] ) )
        return false;


    global $yourls_user_passwords;
    foreach( $yourls_user_passwords as $valid_user => $valid_password ) {
        if ( yourls_auth_signature( $valid_user ) === $_REQUEST['signature'] ) {
            yourls_set_user( $valid_user );
            return true;
        }
    }


    return false;
}







function yourls_auth_signature( $username = false ) {
    if( !$username && defined('YOURLS_USER') ) {
        $username = YOURLS_USER;
    }
    return ( $username ? substr( yourls_salt( $username ), 0, 10 ) : 'Cannot generate auth signature: no username' );
}







function yourls_check_timestamp( $time ) {
    $now = time();

    return yourls_apply_filter( 'check_timestamp', abs( $now - (int)$time ) < yourls_get_nonce_life(), $time );
}







function yourls_store_cookie( $user = '' ) {


    if( !$user ) {
        $time = time() - 3600;
    } else {
        $time = time() + yourls_get_cookie_life();
    }

    $path     = yourls_apply_filter( 'setcookie_path',     '/' );
    $domain   = yourls_apply_filter( 'setcookie_domain',   parse_url( yourls_get_yourls_site(), PHP_URL_HOST ) );
    $secure   = yourls_apply_filter( 'setcookie_secure',   yourls_is_ssl() );
    $httponly = yourls_apply_filter( 'setcookie_httponly', true );


    if ( $domain == 'localhost' )
        $domain = '';

    yourls_do_action( 'pre_setcookie', $user, $time, $path, $domain, $secure, $httponly );

    if ( !headers_sent( $filename, $linenum ) ) {
        yourls_setcookie( yourls_cookie_name(), yourls_cookie_value( $user ), $time, $path, $domain, $secure, $httponly );
    } else {

        yourls_do_action( 'setcookie_failed', $user );
        yourls_debug_log( "Could not store cookie: headers already sent in $filename on line $linenum" );
    }
}


















function yourls_setcookie($name, $value, $expire, $path, $domain, $secure, $httponly) {
    $samesite = yourls_apply_filter('setcookie_samesite', 'Lax' );

    return(setcookie($name, $value, array(
        'expires'  => $expire,
        'path'     => $path,
        'domain'   => $domain,
        'samesite' => $samesite,
        'secure'   => $secure,
        'httponly' => $httponly,
    )));
}







function yourls_set_user( $user ) {
    if( !defined( 'YOURLS_USER' ) )
        define( 'YOURLS_USER', $user );
}











function yourls_get_cookie_life() {
    return yourls_apply_filter( 'get_cookie_life', YOURLS_COOKIE_LIFE );
}












function yourls_get_nonce_life() {
    return yourls_apply_filter( 'get_nonce_life', YOURLS_NONCE_LIFE );
}











function yourls_cookie_name() {
    return yourls_apply_filter( 'cookie_name', 'yourls_' . yourls_salt( yourls_get_yourls_site() ) );
}








function yourls_cookie_value( $user ) {
    return yourls_apply_filter( 'set_cookie_value', yourls_salt( $user ?? '' ), $user );
}








function yourls_tick() {
    return ceil( time() / yourls_get_nonce_life() );
}










function yourls_salt( $string ) {
    $salt = defined('YOURLS_COOKIEKEY') ? YOURLS_COOKIEKEY : md5(__FILE__) ;
    return yourls_apply_filter( 'yourls_salt', hash_hmac( yourls_hmac_algo(), $string,  $salt), $string );
}







function yourls_hmac_algo() {
    $algo = yourls_apply_filter( 'hmac_algo', 'sha256' );
    if( !in_array( $algo, hash_hmac_algos() ) ) {
        $algo = 'sha256';
    }
    return $algo;
}








function yourls_create_nonce($action, $user = false ) {
    if( false === $user ) {
        $user = defined('YOURLS_USER') ? YOURLS_USER : '-1';
    }
    $tick = yourls_tick();
    $nonce = substr( yourls_salt($tick . $action . $user), 0, 10 );

    return yourls_apply_filter( 'create_nonce', $nonce, $action, $user );
}










function yourls_nonce_field($action, $name = 'nonce', $user = false, $echo = true ) {
    $field = '<input type="hidden" id="'.$name.'" name="'.$name.'" value="'.yourls_create_nonce( $action, $user ).'" />';
    if( $echo )
        echo $field."\n";
    return $field;
}










function yourls_nonce_url($action, $url = false, $name = 'nonce', $user = false ) {
    $nonce = yourls_create_nonce( $action, $user );
    return yourls_add_query_arg( $name, $nonce, $url );
}













function yourls_verify_nonce($action, $nonce = false, $user = false, $return = '' ) {

    if( false === $user ) {
        $user = defined('YOURLS_USER') ? YOURLS_USER : '-1';
    }


    if( false === $nonce && isset( $_REQUEST['nonce'] ) ) {
        $nonce = $_REQUEST['nonce'];
    }


    if (yourls_apply_filter( 'verify_nonce', false, $action, $nonce, $user, $return ) === true) {
        return true;
    }


    $valid = yourls_create_nonce( $action, $user );

    if( $nonce === $valid ) {
        return true;
    } else {
        if( $return )
            die( $return );
        yourls_die( yourls__( 'Unauthorized action or expired link' ), yourls__( 'Error' ), 403 );
    }
}







function yourls_is_user_from_env() {
    return yourls_apply_filter('is_user_from_env', getenv('YOURLS_PASSWORD') || getenv('YOURLS_PASS') || getenv('YOURLS_PASS_FILE'));
}












function yourls_maybe_hash_passwords() {
    $hash = true;

    if ( !yourls_has_cleartext_passwords()
         OR (yourls_skip_password_hashing())
         OR (yourls_is_user_from_env())
    ) {
        $hash = false;
    }

    return yourls_apply_filter('maybe_hash_password', $hash );
}







function yourls_skip_password_hashing() {
    return yourls_apply_filter('skip_password_hashing', defined('YOURLS_NO_HASH_PASSWORD') && YOURLS_NO_HASH_PASSWORD);
}
