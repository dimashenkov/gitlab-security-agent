<?php


























function yourls_activate_plugin_sandbox( $pluginfile ) {
    yourls_deprecated_function( __FUNCTION__, '1.9.1', 'yourls_include_file_sandbox');
    return yourls_include_file_sandbox($pluginfile);
}








function yourls_current_admin_page() {
    yourls_deprecated_function( __FUNCTION__, '1.9.1' );
    if( yourls_is_admin() ) {
        $current = substr( yourls_get_request(), 6 );
        if( $current === false )
            $current = 'index.php';

        return $current;
    }
    return null;
}









function yourls_encodeURI($url) {
    yourls_deprecated_function( __FUNCTION__, '1.9.1', '' );

    $result = yourls_rawurldecode_while_encoded( $url );

    $result = strtr( rawurlencode( $result ), array (
        '%3B' => ';', '%2C' => ',', '%2F' => '/', '%3F' => '?', '%3A' => ':', '%40' => '@',
        '%26' => '&', '%3D' => '=', '%2B' => '+', '%24' => '$', '%21' => '!', '%2A' => '*',
        '%27' => '\'', '%28' => '(', '%29' => ')', '%23' => '#',
    ) );



    return yourls_apply_filter( 'encodeURI', $result, $url );
}






function yourls_validate_plugin_file( $file ) {
    yourls_deprecated_function( __FUNCTION__, '1.8.3', 'yourls_is_a_plugin_file' );
    return yourls_is_a_plugin_file($file);
}






function yourls_string2htmlid( $string ) {
    yourls_deprecated_function( __FUNCTION__, '1.8.3', 'yourls_unique_element_id' );
    return yourls_apply_filter( 'string2htmlid', 'y'.abs( crc32( $string ) ) );
}













function yourls_get_search_text() {
    yourls_deprecated_function( __FUNCTION__, '1.8.2', 'YOURLS\Views\AdminParams::get_search' );
    $view_params = new YOURLS\Views\AdminParams();
    return $view_params->get_search();
}

















function yourls_current_time( $type, $gmt = 0 ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.10', 'yourls_get_timestamp' );
    switch ( $type ) {
        case 'mysql':
            return ( $gmt ) ? gmdate( 'Y-m-d H:i:s' ) : gmdate( 'Y-m-d H:i:s', yourls_get_timestamp( time() ));
        case 'timestamp':
            return ( $gmt ) ? time() : yourls_get_timestamp( time() );
    }
}










function yourls_lowercase_scheme_domain( $url ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.10', 'yourls_normalize_uri' );
    return yourls_normalize_uri( $url );
}







function yourls_sanitize_string( $string, $restrict_to_shorturl_charset = false ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.10', 'yourls_sanitize_keyword' );
    return yourls_sanitize_keyword( $string, $restrict_to_shorturl_charset );
}







function yourls_favicon( $echo = true ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.10', 'yourls_get_yourls_favicon_url' );
    return yourls_get_yourls_favicon_url( $echo );
}







function yourls_get_link_stats( $url ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.10', 'yourls_get_keyword_stats' );
    return yourls_get_keyword_stats( $url );
}








function yourls_url_exists( $url ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.10', 'yourls_long_url_exists' );
    return yourls_long_url_exists( $url );
}





function yourls_plural( $word, $count=1 ) {
    yourls_deprecated_function( __FUNCTION__, '1.6', 'yourls_n' );
    return $word . ($count > 1 ? 's' : '');
}





function yourls_get_duplicate_keywords( $longurl ) {
    yourls_deprecated_function( __FUNCTION__, '1.7', 'yourls_get_longurl_keywords' );
    if( !yourls_allow_duplicate_longurls() )
        return NULL;
    return yourls_apply_filter( 'get_duplicate_keywords', yourls_get_longurl_keywords ( $longurl ), $longurl );
}







function yourls_intval( $int ) {
    yourls_deprecated_function( __FUNCTION__, '1.7', 'yourls_sanitize_int' );
    return yourls_escape( $int );
}





function yourls_get_remote_content( $url,  $maxlen = 4096, $timeout = 5 ) {
    yourls_deprecated_function( __FUNCTION__, '1.7', 'yourls_http_get_body' );
    return yourls_http_get_body( $url );
}














function yourls_apply_filters( $hook, $value = '' ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.1', 'yourls_apply_filter' );
    return yourls_apply_filter( $hook, $value );
}





function yourls_has_interface() {
    yourls_deprecated_function( __FUNCTION__, '1.7.1' );
    if( yourls_is_API() or yourls_is_GO() )
        return false;
    return true;
}








function yourls_http_proxy_is_defined() {
    yourls_deprecated_function( __FUNCTION__, '1.7.1', 'yourls_http_get_proxy' );
    return yourls_apply_filter( 'http_proxy_is_defined', defined( 'YOURLS_PROXY' ) );
}















function yourls_ex( $text, $context, $domain = 'default' ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.1', 'yourls_xe' );
    echo yourls_xe( $text, $context, $domain );
}











function yourls_escape( $data ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.3', 'PDO' );
    if( is_array( $data ) ) {
        foreach( $data as $k => $v ) {
            if( is_array( $v ) ) {
                $data[ $k ] = yourls_escape( $v );
            } else {
                $data[ $k ] = yourls_escape_real( $v );
            }
        }
    } else {
        $data = yourls_escape_real( $data );
    }

    return $data;
}














function yourls_escape_real( $string ) {
    yourls_deprecated_function( __FUNCTION__, '1.7.3', 'PDO' );
    global $ydb;
    if( isset( $ydb ) && ( $ydb instanceof \YOURLS\Database\YDB ) )
        return $ydb->escape( $string );


    return yourls_apply_filter( 'custom_escape_real', addslashes( $string ), $string );
}


