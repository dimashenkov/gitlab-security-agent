<?php

if( !defined( 'YOURLS_ABSPATH' ) ) die();

$auth = yourls_is_valid_user();

if( $auth !== true ) {


    if ( yourls_is_API() ) {
        $format = ( isset($_REQUEST['format']) ? $_REQUEST['format'] : 'xml' );
        $callback = ( isset($_REQUEST['callback']) ? $_REQUEST['callback'] : '' );
        yourls_api_output( $format, array(
            'simple' => $auth,
            'message' => $auth,
            'errorCode' => '403',
            'callback' => $callback,
        ) );


    } else {
        yourls_login_screen( $auth );
    }

    die();
}

yourls_do_action( 'auth_successful' );









if ( isset( $_GET['dismiss'] ) && $_GET['dismiss'] == 'hasherror' ) {
    yourls_update_option( 'defer_hashing_error', time() + 86400 * 7 );

} else {


    if ( yourls_maybe_hash_passwords() ) {
        $hash = yourls_hash_passwords_now( YOURLS_CONFIGFILE );
        if ( $hash === true ) {

            if( yourls_get_option( 'defer_hashing_error' ) )
                yourls_delete_option( 'defer_hashing_error' );
        } else {

            if ( time() > yourls_get_option( 'defer_hashing_error' ) or !yourls_get_option( 'defer_hashing_error' ) ) {
                $message  = yourls_s( 'Could not auto-encrypt passwords. Error was: "%s".', $hash );
                $message .= ' ';
                $message .= yourls_s( '<a href="%s">Get help</a>.', 'http://yourls.org/userpassword' );
                $message .= '</p><p>';
                $message .= yourls_s( '<a href="%s">Click here</a> to dismiss this message for one week.', '?dismiss=hasherror' );

                yourls_add_notice( $message );
            }
        }
    }
}
