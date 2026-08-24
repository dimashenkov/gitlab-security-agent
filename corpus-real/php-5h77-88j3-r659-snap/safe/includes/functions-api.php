<?php















function yourls_api_action_shorturl() {
    $url = ( isset( $_REQUEST['url'] ) ? $_REQUEST['url'] : '' );
    $keyword = ( isset( $_REQUEST['keyword'] ) ? $_REQUEST['keyword'] : '' );
    $title = ( isset( $_REQUEST['title'] ) ? $_REQUEST['title'] : '' );
    $return = yourls_add_new_link( $url, $keyword, $title );
    $return['simple'] = ( isset( $return['shorturl'] ) ? $return['shorturl'] : '' );
    unset( $return['html'] );
    return yourls_apply_filter( 'api_result_shorturl', $return );
}







function yourls_api_action_stats() {
    $filter = ( isset( $_REQUEST['filter'] ) ? $_REQUEST['filter'] : '' );
    $limit = ( isset( $_REQUEST['limit'] ) ? $_REQUEST['limit'] : '' );
    $start = ( isset( $_REQUEST['start'] ) ? $_REQUEST['start'] : '' );
    return yourls_apply_filter( 'api_result_stats', yourls_api_stats( $filter, $limit, $start ) );
}







function yourls_api_action_db_stats() {
    return yourls_apply_filter( 'api_result_db_stats', yourls_api_db_stats() );
}







function yourls_api_action_url_stats() {
    $shorturl = ( isset( $_REQUEST['shorturl'] ) ? $_REQUEST['shorturl'] : '' );
    return yourls_apply_filter( 'api_result_url_stats', yourls_api_url_stats( $shorturl ) );
}







function yourls_api_action_expand() {
    $shorturl = ( isset( $_REQUEST['shorturl'] ) ? $_REQUEST['shorturl'] : '' );
    return yourls_apply_filter( 'api_result_expand', yourls_api_expand( $shorturl ) );
}







function yourls_api_action_version() {
    $return['version'] = $return['simple'] = YOURLS_VERSION;
    if( isset( $_REQUEST['db'] ) && $_REQUEST['db'] == 1 )
        $return['db_version'] = YOURLS_DB_VERSION;
    return yourls_apply_filter( 'api_result_version', $return );
}

















function yourls_api_output( $mode, $output, $send_headers = true, $echo = true ) {
    if( isset( $output['simple'] ) ) {
        $simple = $output['simple'];
        unset( $output['simple'] );
    }

    yourls_do_action( 'pre_api_output', $mode, $output, $send_headers, $echo );

    if( $send_headers ) {
        if( isset( $output['statusCode'] ) ) {
            $code = $output['statusCode'];
        } elseif ( isset( $output['errorCode'] ) ) {
            $code = $output['errorCode'];
        } else {
            $code = 200;
        }
        yourls_status_header( $code );
    }

    $result = '';

    switch ( $mode ) {
        case 'jsonp':
            if( $send_headers )
                yourls_content_type_header( 'application/javascript' );

            $callback = isset( $output['callback'] ) ? yourls_validate_jsonp_callback($output['callback'] ) : '';
            if( $callback === false ) {
                yourls_status_header( 400 );
                $result = json_encode( ['errorCode' => '400', 'error' => 'Invalid callback parameter'] );
            } else {
                $result =  $callback . '(' . json_encode( $output ) . ')';
            }

            break;

        case 'json':
            if( $send_headers )
                yourls_content_type_header( 'application/json' );

            $result = json_encode( $output );
            break;

        case 'xml':
            if( $send_headers )
                yourls_content_type_header( 'application/xml' );

            $result = yourls_xml_encode( $output );
            break;

        case 'simple':
        default:
            if( $send_headers )
                yourls_content_type_header( 'text/plain' );

            $result = isset( $simple ) ? $simple : '';
            break;
    }

    if( $echo ) {
        echo $result;
    }

    yourls_do_action( 'api_output', $mode, $output, $send_headers, $echo );

    return $result;
}









function yourls_api_stats($filter = 'top', $limit = 10, $start = 0 ) {
    $return = yourls_get_stats( $filter, $limit, $start );
    $return['simple']  = 'Need either XML or JSON format for stats';
    $return['message'] = 'success';
    return yourls_apply_filter( 'api_stats', $return, $filter, $limit, $start );
}






function yourls_api_db_stats() {
    $return = array(
        'db-stats'   => yourls_get_db_stats(),
        'statusCode' => '200',
        'simple'     => 'Need either XML or JSON format for stats',
        'message'    => 'success',
    );

    return yourls_apply_filter( 'api_db_stats', $return );
}







function yourls_api_url_stats( $shorturl ) {
    $keyword = str_replace( yourls_get_yourls_site() . '/' , '', $shorturl );
    $keyword = yourls_sanitize_keyword( $keyword );

    $return = yourls_get_keyword_stats( $keyword );
    $return['simple']  = 'Need either XML or JSON format for stats';
    return yourls_apply_filter( 'api_url_stats', $return, $shorturl );
}







function yourls_api_expand( $shorturl ) {
    $keyword = str_replace( yourls_get_yourls_site() . '/' , '', $shorturl );
    $keyword = yourls_sanitize_keyword( $keyword );

    $longurl = yourls_get_keyword_longurl( $keyword );

    if( $longurl ) {
        $return = array(
            'keyword'   => $keyword,
            'shorturl'  => yourls_link($keyword),
            'longurl'   => $longurl,
            'title'     => yourls_get_keyword_title( $keyword ),
            'simple'    => $longurl,
            'message'   => 'success',
            'statusCode' => '200',
        );
    } else {
        $return = array(
            'keyword'   => $keyword,
            'simple'    => 'not found',
            'message'   => 'Error: short URL not found',
            'errorCode' => '404',
        );
    }

    return yourls_apply_filter( 'api_expand', $return, $shorturl );
}
