<?php








function yourls_db_connect($context = '') {
    global $ydb;

    if ( !defined( 'YOURLS_DB_USER' )
         or !defined( 'YOURLS_DB_PASS' )
         or !defined( 'YOURLS_DB_NAME' )
         or !defined( 'YOURLS_DB_HOST' )
    ) {
        yourls_die( yourls__( 'Incorrect DB config, please refer to documentation' ), yourls__( 'Fatal error' ), 503 );
    }

    $dbhost = YOURLS_DB_HOST;
    $user = YOURLS_DB_USER;
    $pass = YOURLS_DB_PASS;
    $dbname = YOURLS_DB_NAME;


    yourls_do_action( 'set_DB_driver', 'deprecated' );


    if (str_contains($dbhost, ':')) {
        list( $dbhost, $dbport ) = explode( ':', $dbhost );
        $dbhost = sprintf( '%1$s;port=%2$d', $dbhost, $dbport );
    }

    $charset = yourls_apply_filter( 'db_connect_charset', 'utf8mb4', $context );









    $dsn = sprintf( 'mysql:host=%s;dbname=%s;charset=%s', $dbhost, $dbname, $charset );
    $dsn = yourls_apply_filter( 'db_connect_custom_dsn', $dsn, $context );









    $driver_options = yourls_apply_filter( 'db_connect_driver_option', [], $context );
    $attributes = yourls_apply_filter( 'db_connect_attributes', [], $context );

    $ydb = new \YOURLS\Database\YDB( $dsn, $user, $pass, $driver_options, $attributes );
    $ydb->init();


    yourls_debug_log( 'Connected to ' . $dsn );

    yourls_debug_mode( YOURLS_DEBUG );

    return $ydb;
}
























function yourls_get_db($context = '') {

    $pre = yourls_apply_filter( 'shunt_get_db', yourls_shunt_default(), $context );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }


    if ($context == '' || !preg_match('/^(read|write)-[a-z0-9_]+$/', $context)) {
        $db = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2);
        $file = $db[0]['file'];
        $line = $db[0]['line'];

        if ($context == '') {
            $msg = 'Undefined yourls_get_db() context';
        } else {
            $msg = 'Improperly formatted yourls_get_db() context ("' . $context . '")';
        }

        trigger_error( $msg . ' at <b>' . $file . ':' . $line .'</b>', E_USER_NOTICE );
    }

    yourls_do_action( 'get_db_action', $context );

    global $ydb;
    $ydb = ( isset( $ydb ) ) ? $ydb : yourls_db_connect($context);
    return yourls_apply_filter('get_db', $ydb, $context);
}















function yourls_set_db($db) {
    global $ydb;

    if (is_null($db)) {
        unset($ydb);
    } else {
        $ydb = $db;
    }
}
