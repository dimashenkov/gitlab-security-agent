<?php











function yourls_make_regexp_pattern( $string ) {


    return preg_quote( $string, '@' );
}






function yourls_get_IP() {
    $ip = '';


    $headers = [ 'X-Forwarded-For', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP', 'HTTP_VIA', 'REMOTE_ADDR' ];
    foreach( $headers as $header ) {
        if ( !empty( $_SERVER[ $header ] ) ) {
            $ip = $_SERVER[ $header ];
            break;
        }
    }


    if ( strpos( $ip, ',' ) !== false )
        $ip = substr( $ip, 0, strpos( $ip, ',' ) );

    return (string)yourls_apply_filter( 'get_IP', yourls_sanitize_ip( $ip ) );
}







function yourls_get_next_decimal() {
    return (int)yourls_apply_filter( 'get_next_decimal', (int)yourls_get_option( 'next_id' ) );
}














function yourls_update_next_decimal( $int = 0 ) {
    $int = ( $int == 0 ) ? yourls_get_next_decimal() + 1 : (int)$int ;
    $update = yourls_update_option( 'next_id', $int );
    yourls_do_action( 'update_next_decimal', $int, $update );
    return $update;
}







function yourls_xml_encode( $array ) {
    return (\Spatie\ArrayToXml\ArrayToXml::convert($array, '', true, 'UTF-8'));
}








function yourls_update_clicks( $keyword, $clicks = false ) {

    $pre = yourls_apply_filter( 'shunt_update_clicks', yourls_shunt_default(), $keyword, $clicks );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $keyword = yourls_sanitize_keyword( $keyword );
    $table = YOURLS_DB_TABLE_URL;
    if ( $clicks !== false && is_int( $clicks ) && $clicks >= 0 ) {
        $update = "UPDATE `$table` SET `clicks` = :clicks WHERE `keyword` = :keyword";
        $values = [ 'clicks' => $clicks, 'keyword' => $keyword ];
        $update_type = 'set';
    } else {
        $update = "UPDATE `$table` SET `clicks` = clicks + 1 WHERE `keyword` = :keyword";
        $values = [ 'keyword' => $keyword ];
        $update_type = 'increment';
    }

    $ydb = yourls_get_db('write-update_clicks');


    try {
        $result = $ydb->fetchAffected($update, $values);
    } catch (Exception $e) {
        $result = 0;
    }

    if ( $result ) {
        if ( $ydb->has_infos($keyword) ) {
            if ( $update_type === 'increment' ) {
                $infos = $ydb->get_infos($keyword);
                if ( isset( $infos['clicks'] ) ) {
                    $infos['clicks']++;
                    $ydb->set_infos($keyword, $infos);
                } else {
                    $ydb->delete_infos($keyword);
                }
            } elseif ( $update_type === 'set' ) {
                $ydb->update_infos_if_exists($keyword, ['clicks' => $clicks]);
            }
        }
    }

    yourls_do_action( 'update_clicks', $keyword, $result, $clicks );

    return $result;
}










function yourls_get_stats($filter = 'top', $limit = 10, $start = 0) {
    switch( $filter ) {
        case 'bottom':
            $sort_by    = '`clicks`';
            $sort_order = 'asc';
            break;
        case 'last':
            $sort_by    = '`timestamp`';
            $sort_order = 'desc';
            break;
        case 'rand':
        case 'random':
            $sort_by    = 'RAND()';
            $sort_order = '';
            break;
        case 'top':
        default:
            $sort_by    = '`clicks`';
            $sort_order = 'desc';
            break;
    }


    $limit = intval( $limit );
    $start = intval( $start );
    if ( $limit > 0 ) {

        $table_url = YOURLS_DB_TABLE_URL;
        $results = yourls_get_db('read-get_stats')->fetchObjects( "SELECT * FROM `$table_url` WHERE 1=1 ORDER BY $sort_by $sort_order LIMIT $start, $limit;" );

        $return = [];
        $i = 1;

        foreach ( (array)$results as $res ) {
            $return['links']['link_'.$i++] = [
                'shorturl' => yourls_link($res->keyword),
                'url'      => $res->url,
                'title'    => $res->title,
                'timestamp'=> $res->timestamp,
                'ip'       => $res->ip,
                'clicks'   => $res->clicks,
            ];
        }
    }

    $return['stats'] = yourls_get_db_stats();

    $return['statusCode'] = '200';

    return yourls_apply_filter( 'get_stats', $return, $filter, $limit, $start );
}











function yourls_get_db_stats( $where = [ 'sql' => '', 'binds' => [] ] ) {
    $table_url = YOURLS_DB_TABLE_URL;

    $totals = yourls_get_db('read-get_db_stats')->fetchObject( "SELECT COUNT(keyword) as count, SUM(clicks) as sum FROM `$table_url` WHERE 1=1 " . $where['sql'] , $where['binds'] );
    $return = [ 'total_links' => (int)$totals->count, 'total_clicks' => (int)$totals->sum ];

    return yourls_apply_filter( 'get_db_stats', $return, $where );
}






function yourls_get_user_agent() {
    $ua = '-';

    if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
        $ua = strip_tags( html_entity_decode( $_SERVER['HTTP_USER_AGENT'] ));
        $ua = preg_replace('![^0-9a-zA-Z\':., /{}\(\)\[\]\+@&\!\?;_\-=~\*\#]!', '', $ua );
    }

    return yourls_apply_filter( 'get_user_agent', substr( $ua, 0, 255 ) );
}






function yourls_get_referrer() {
    $referrer = isset( $_SERVER['HTTP_REFERER'] ) ? yourls_sanitize_url_safe( $_SERVER['HTTP_REFERER'] ) : 'direct';

    return yourls_apply_filter( 'get_referrer', substr( $referrer, 0, 200 ) );
}
















function yourls_redirect( $location, $code = 301 ) {
    yourls_do_action( 'pre_redirect', $location, $code );
    $location = yourls_apply_filter( 'redirect_location', $location, $code );
    $code     = yourls_apply_filter( 'redirect_code', $code, $location );


    if( !headers_sent() ) {
        yourls_status_header( $code );
        header( "Location: $location" );
        return 1;
    }


    if( php_sapi_name() !== 'cli') {
        yourls_redirect_javascript( $location );
        return 2;
    }


    return 3;
}












function yourls_redirect_shorturl($url, $keyword) {
    yourls_do_action( 'redirect_shorturl', $url, $keyword );


    yourls_update_clicks( $keyword );


    yourls_log_redirect( $keyword );


    yourls_robots_tag_header();

    yourls_redirect( $url, 301 );
}







function yourls_robots_tag_header() {

    $pre = yourls_apply_filter( 'shunt_robots_tag_header', yourls_shunt_default() );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }


    $tag = yourls_apply_filter( 'robots_tag_header', 'noindex' );
    $replace = yourls_apply_filter( 'robots_tag_header_replace', true );
    if ( !headers_sent() ) {
        header( "X-Robots-Tag: $tag", $replace );
    }
}








function yourls_no_cache_headers() {
    if( !headers_sent() ) {
        header( 'Expires: Thu, 23 Mar 1972 07:00:00 GMT' );
        header( 'Last-Modified: ' . gmdate( 'D, d M Y H:i:s' ) . ' GMT' );
        header( 'Cache-Control: no-cache, must-revalidate, max-age=0' );
        header( 'Pragma: no-cache' );
    }
}












function yourls_no_frame_header() {

    $pre = yourls_apply_filter( 'shunt_no_frame_header', yourls_shunt_default() );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    if( !headers_sent() ) {
        header( 'X-Frame-Options: SAMEORIGIN' );
    }
}








function yourls_content_type_header( $type ) {
    yourls_do_action( 'content_type_header', $type );
    if( !headers_sent() ) {
        $charset = yourls_apply_filter( 'content_type_header_charset', 'utf-8' );
        header( "Content-Type: $type; charset=$charset" );
        return true;
    }
    return false;
}








function yourls_status_header( $code = 200 ) {
    yourls_do_action( 'status_header', $code );

    if( headers_sent() )
        return false;

    $protocol = $_SERVER['SERVER_PROTOCOL'];
    if ( 'HTTP/1.1' != $protocol && 'HTTP/1.0' != $protocol )
        $protocol = 'HTTP/1.0';

    $code = intval( $code );
    $desc = yourls_get_HTTP_status( $code );

    @header ("$protocol $code $desc");

    return true;
}









function yourls_redirect_javascript( $location, $dontwait = true ) {
    yourls_do_action( 'pre_redirect_javascript', $location, $dontwait );
    $location = yourls_apply_filter( 'redirect_javascript', $location, $dontwait );
    if ( $dontwait ) {
        $message = yourls_s( 'if you are not redirected after 10 seconds, please <a href="%s">click here</a>', $location );
        echo <<<REDIR
        <script type="text/javascript">
        window.location="$location";
        </script>
        <small>($message)</small>
REDIR;
    }
    else {
        echo '<p>'.yourls_s( 'Please <a href="%s">click here</a>', $location ).'</p>';
    }
    yourls_do_action( 'post_redirect_javascript', $location );
}







function yourls_get_HTTP_status( $code ) {
    $code = intval( $code );
    $headers_desc = [
        100 => 'Continue',
        101 => 'Switching Protocols',
        102 => 'Processing',

        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        207 => 'Multi-Status',
        226 => 'IM Used',

        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        306 => 'Reserved',
        307 => 'Temporary Redirect',

        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',
        422 => 'Unprocessable Entity',
        423 => 'Locked',
        424 => 'Failed Dependency',
        426 => 'Upgrade Required',

        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
        506 => 'Variant Also Negotiates',
        507 => 'Insufficient Storage',
        510 => 'Not Extended'
    ];

    return $headers_desc[$code] ?? '';
}











function yourls_log_redirect( $keyword ) {

    $pre = yourls_apply_filter( 'shunt_log_redirect', yourls_shunt_default(), $keyword );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    if (!yourls_do_log_redirect()) {
        return true;
    }

    $table = YOURLS_DB_TABLE_LOG;
    $ip = yourls_get_IP();
    $binds = [
        'now' => date( 'Y-m-d H:i:s' ),
        'keyword'  => yourls_sanitize_keyword($keyword),
        'referrer' => substr( yourls_get_referrer(), 0, 200 ),
        'ua'       => substr(yourls_get_user_agent(), 0, 255),
        'ip'       => $ip,
        'location' => yourls_geo_ip_to_countrycode($ip),
    ];


    try {
        $result = yourls_get_db('write-log_redirect')->fetchAffected("INSERT INTO `$table` (click_time, shorturl, referrer, user_agent, ip_address, country_code) VALUES (:now, :keyword, :referrer, :ua, :ip, :location)", $binds );
    } catch (Exception $e) {
        $result = 0;
    }

    return $result;
}






function yourls_do_log_redirect() {
    return ( !defined( 'YOURLS_NOSTATS' ) || YOURLS_NOSTATS != true );
}






function yourls_upgrade_is_needed() {

    list( $currentver, $currentsql ) = yourls_get_current_version_from_sql();
    if ( $currentsql < YOURLS_DB_VERSION ) {
        return true;
    }


    if ( $currentver < YOURLS_VERSION ) {
        yourls_update_option( 'version', YOURLS_VERSION );
    }

    return false;
}






function yourls_get_current_version_from_sql() {
    $currentver = yourls_get_option( 'version' );
    $currentsql = yourls_get_option( 'db_version' );


    if ( !$currentver ) {
        $currentver = '1.3';
    }
    if ( !$currentsql ) {
        $currentsql = '100';
    }

    return [ $currentver, $currentsql ];
}






function yourls_is_private() {
    $private = defined( 'YOURLS_PRIVATE' ) && YOURLS_PRIVATE;

    if ( $private ) {




        if ( yourls_is_API() && defined( 'YOURLS_PRIVATE_API' ) ) {
            $private = YOURLS_PRIVATE_API;
        }

        elseif ( yourls_is_infos() && defined( 'YOURLS_PRIVATE_INFOS' ) ) {
            $private = YOURLS_PRIVATE_INFOS;
        }

    }

    return yourls_apply_filter( 'is_private', $private );
}






function yourls_allow_duplicate_longurls() {

    if ( yourls_is_API() && isset( $_REQUEST[ 'source' ] ) && $_REQUEST[ 'source' ] == 'plugin' ) {
            return false;
    }

    return yourls_apply_filter('allow_duplicate_longurls', defined('YOURLS_UNIQUE_URLS') && !YOURLS_UNIQUE_URLS);
}







function yourls_check_IP_flood( $ip = '' ) {


    $pre = yourls_apply_filter( 'shunt_check_IP_flood', yourls_shunt_default(), $ip );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    yourls_do_action( 'pre_check_ip_flood', $ip );


    if(
        ( defined('YOURLS_FLOOD_DELAY_SECONDS') && YOURLS_FLOOD_DELAY_SECONDS === 0 ) ||
        !defined('YOURLS_FLOOD_DELAY_SECONDS') ||
        yourls_is_installing()
    )
        return true;


    if( yourls_is_private() ) {
         if( yourls_is_valid_user() === true )
            return true;
    }


    if( defined( 'YOURLS_FLOOD_IP_WHITELIST' ) && YOURLS_FLOOD_IP_WHITELIST ) {
        $whitelist_ips = explode( ',', YOURLS_FLOOD_IP_WHITELIST );
        foreach( (array)$whitelist_ips as $whitelist_ip ) {
            $whitelist_ip = trim( $whitelist_ip );
            if ( $whitelist_ip == $ip )
                return true;
        }
    }

    $ip = ( $ip ? yourls_sanitize_ip( $ip ) : yourls_get_IP() );

    yourls_do_action( 'check_ip_flood', $ip );

    $table = YOURLS_DB_TABLE_URL;
    $lasttime = yourls_get_db('read-check_ip_flood')->fetchValue( "SELECT `timestamp` FROM $table WHERE `ip` = :ip ORDER BY `timestamp` DESC LIMIT 1", [ 'ip' => $ip ] );
    if( $lasttime ) {
        $now = date( 'U' );
        $then = date( 'U', strtotime( $lasttime ) );
        if( ( $now - $then ) <= YOURLS_FLOOD_DELAY_SECONDS ) {

            yourls_do_action( 'ip_flood', $ip, $now - $then );
            yourls_die( yourls__( 'Too many URLs added too fast. Slow down please.' ), yourls__( 'Too Many Requests' ), 429 );
        }
    }

    return true;
}







function yourls_is_installing() {
    return (bool)yourls_apply_filter( 'is_installing', defined( 'YOURLS_INSTALLING' ) && YOURLS_INSTALLING );
}







function yourls_is_upgrading() {
    return (bool)yourls_apply_filter( 'is_upgrading', defined( 'YOURLS_UPGRADING' ) && YOURLS_UPGRADING );
}










function yourls_is_installed() {
    return (bool)yourls_apply_filter( 'is_installed', yourls_get_db('read-is_installed')->is_installed() );
}








function yourls_set_installed( $bool ) {
    yourls_get_db('read-set_installed')->set_installed( $bool );
}









function yourls_rnd_string ( $length = 5, $type = 0, $charlist = '' ) {
    $length = intval( $length );


    switch ( $type ) {


        case '1':
            $possible = "23456789bcdfghjkmnpqrstvwxyz";
            break;


        case '2':
            $possible = "23456789bcdfghjkmnpqrstvwxyzBCDFGHJKMNPQRSTVWXYZ";
            break;


        case '3':
            $possible = "abcdefghijklmnopqrstuvwxyz";
            break;


        case '4':
            $possible = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            break;


        case '5':
            $possible = "0123456789abcdefghijklmnopqrstuvwxyz";
            break;


        case '6':
            $possible = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            break;


        default:
        case '0':
            $possible = $charlist ? $charlist : yourls_get_shorturl_charset();
            break;
    }

    $str = substr( str_shuffle( $possible ), 0, $length );
    return yourls_apply_filter( 'rnd_string', $str, $length, $type, $charlist );
}






function yourls_is_API() {
    return (bool)yourls_apply_filter( 'is_API', defined( 'YOURLS_API' ) && YOURLS_API );
}






function yourls_is_Ajax() {
    return (bool)yourls_apply_filter( 'is_Ajax', defined( 'YOURLS_AJAX' ) && YOURLS_AJAX );
}






function yourls_is_GO() {
    return (bool)yourls_apply_filter( 'is_GO', defined( 'YOURLS_GO' ) && YOURLS_GO );
}






function yourls_is_infos() {
    return (bool)yourls_apply_filter( 'is_infos', defined( 'YOURLS_INFOS' ) && YOURLS_INFOS );
}






function yourls_is_admin() {
    return (bool)yourls_apply_filter( 'is_admin', defined( 'YOURLS_ADMIN' ) && YOURLS_ADMIN );
}






function yourls_is_windows() {
    return defined( 'DIRECTORY_SEPARATOR' ) && DIRECTORY_SEPARATOR == '\\';
}






function yourls_needs_ssl() {
    return (bool)yourls_apply_filter( 'needs_ssl', defined( 'YOURLS_ADMIN_SSL' ) && YOURLS_ADMIN_SSL );
}






function yourls_is_ssl() {
    $is_ssl = false;
    if ( isset( $_SERVER[ 'HTTPS' ] ) ) {
        if ( 'on' == strtolower( $_SERVER[ 'HTTPS' ] ) ) {
            $is_ssl = true;
        }
        if ( '1' == $_SERVER[ 'HTTPS' ] ) {
            $is_ssl = true;
        }
    }
    elseif ( isset( $_SERVER[ 'HTTP_X_FORWARDED_PROTO' ] ) ) {
        if ( 'https' == strtolower( $_SERVER[ 'HTTP_X_FORWARDED_PROTO' ] ) ) {
            $is_ssl = true;
        }
    }
    elseif ( isset( $_SERVER[ 'SERVER_PORT' ] ) && ( '443' == $_SERVER[ 'SERVER_PORT' ] ) ) {
        $is_ssl = true;
    }
    return (bool)yourls_apply_filter( 'is_ssl', $is_ssl );
}











function yourls_get_remote_title( $url ) {

    $pre = yourls_apply_filter( 'shunt_get_remote_title', yourls_shunt_default(), $url );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $url = yourls_sanitize_url( $url );


    if ( !in_array( yourls_get_protocol( $url ), [ 'http://', 'https://' ] ) ) {
        return $url;
    }

    $title = $charset = false;

    $max_bytes = yourls_apply_filter( 'get_remote_title_max_byte', 32768 );

    $response = yourls_http_get( $url, [], [], [ 'max_bytes' => $max_bytes ] );
    if ( is_string( $response ) ) {
        return $url;
    }


    $content = $response->body;
    if ( !$content ) {
        return $url;
    }


    if ( preg_match( '/<title>(.*?)<\/title>/is', $content, $found ) ) {
        $title = $found[ 1 ];
        unset( $found );
    }
    if ( !$title ) {
        return $url;
    }






    if ( preg_match( '/<meta[^>]*charset\s*=["\' ]*([a-zA-Z0-9\-_]+)/is', $content, $found ) ) {
        if ( yourls_is_valid_charset( $found[ 1 ] ) ) {
            $charset = $found[ 1 ];
        }
        unset( $found );
    }
    if ( empty( $charset ) ) {

        $_charset = current( $response->headers->getValues( 'content-type' ) );
        if ( preg_match( '/charset=(\S+)/', $_charset, $found ) ) {
            $_charset = trim( $found[ 1 ], ';' );
            if ( yourls_is_valid_charset( $_charset ) ) {
                $charset = $_charset;
            }
            unset( $found );
        }
    }


    if ( strtolower( $charset ) != 'utf-8' && function_exists( 'mb_convert_encoding' ) ) {

        if ( $charset ) {
            $title = @mb_convert_encoding( $title, 'UTF-8', $charset );
        }
        else {
            $title = @mb_convert_encoding( $title, 'UTF-8' );
        }
    }


    $title = html_entity_decode( $title, ENT_QUOTES, 'UTF-8' );


    $title = yourls_sanitize_title( $title, $url );

    return (string)yourls_apply_filter( 'get_remote_title', $title, $url );
}






function yourls_is_valid_charset( $charset ) {
    if ( ! function_exists( 'mb_list_encodings' ) ) {
        return false;
    }
    $charset = strtolower( $charset );
    $charsets = array_map( 'strtolower', mb_list_encodings() );

    return in_array( $charset, $charsets );
}






function yourls_is_mobile_device() {

    $mobiles = [
        'android', 'blackberry', 'blazer',
        'compal', 'elaine', 'fennec', 'hiptop',
        'iemobile', 'iphone', 'ipod', 'ipad',
        'iris', 'kindle', 'opera mobi', 'opera mini',
        'palm', 'phone', 'pocket', 'psp', 'symbian',
        'treo', 'wap', 'windows ce', 'windows phone'
    ];


    $current = strtolower( $_SERVER['HTTP_USER_AGENT'] );


    $is_mobile = ( str_replace( $mobiles, '', $current ) != $current );
    return (bool)yourls_apply_filter( 'is_mobile_device', $is_mobile );
}













function yourls_get_request($yourls_site = '', $uri = '') {

    $pre = yourls_apply_filter( 'shunt_get_request', yourls_shunt_default() );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    yourls_do_action( 'pre_get_request', $yourls_site, $uri );


    if ( '' === $yourls_site ) {
        $yourls_site = yourls_get_yourls_site();
    }
    if ( '' === $uri ) {
        $uri = $_SERVER[ 'REQUEST_URI' ];
    }


    $yourls_site = rtrim( $yourls_site, '/' );











    $yourls_site = parse_url( $yourls_site, PHP_URL_PATH ).'/';


    $request = $uri;
    if ( substr( $uri, 0, strlen( $yourls_site ) ) == $yourls_site ) {
        $request = ltrim( substr( $uri, strlen( $yourls_site ) ), '/' );
    }


    if ( !preg_match( "@^[a-zA-Z]+://.+@", $request ) ) {
        $request = current( explode( '?', $request ) );
    }

    $request = yourls_sanitize_url( $request );

    return (string)yourls_apply_filter( 'get_request', $request );
}










function yourls_fix_request_uri() {

    $default_server_values = [
        'SERVER_SOFTWARE' => '',
        'REQUEST_URI'     => '',
    ];
    $_SERVER = array_merge( $default_server_values, $_SERVER );


    $_REQUEST = array_merge( $_GET, $_POST );


    if ( empty( $_SERVER[ 'REQUEST_URI' ] ) || ( php_sapi_name() != 'cgi-fcgi' && preg_match( '/^Microsoft-IIS\//', $_SERVER[ 'SERVER_SOFTWARE' ] ) ) ) {


        if ( isset( $_SERVER[ 'HTTP_X_ORIGINAL_URL' ] ) ) {
            $_SERVER[ 'REQUEST_URI' ] = $_SERVER[ 'HTTP_X_ORIGINAL_URL' ];
        }

        elseif ( isset( $_SERVER[ 'HTTP_X_REWRITE_URL' ] ) ) {
            $_SERVER[ 'REQUEST_URI' ] = $_SERVER[ 'HTTP_X_REWRITE_URL' ];
        }
        else {

            if ( !isset( $_SERVER[ 'PATH_INFO' ] ) && isset( $_SERVER[ 'ORIG_PATH_INFO' ] ) ) {
                $_SERVER[ 'PATH_INFO' ] = $_SERVER[ 'ORIG_PATH_INFO' ];
            }


            if ( isset( $_SERVER[ 'PATH_INFO' ] ) ) {
                if ( $_SERVER[ 'PATH_INFO' ] == $_SERVER[ 'SCRIPT_NAME' ] ) {
                    $_SERVER[ 'REQUEST_URI' ] = $_SERVER[ 'PATH_INFO' ];
                }
                else {
                    $_SERVER[ 'REQUEST_URI' ] = $_SERVER[ 'SCRIPT_NAME' ].$_SERVER[ 'PATH_INFO' ];
                }
            }


            if ( !empty( $_SERVER[ 'QUERY_STRING' ] ) ) {
                $_SERVER[ 'REQUEST_URI' ] .= '?'.$_SERVER[ 'QUERY_STRING' ];
            }
        }
    }
}






function yourls_check_maintenance_mode() {
    $dot_file = YOURLS_ABSPATH . '/.maintenance' ;

    if ( !file_exists( $dot_file ) || yourls_is_upgrading() || yourls_is_installing() ) {
        return;
    }

    global $maintenance_start;
    yourls_include_file_sandbox( $dot_file );

    if ( ( time() - $maintenance_start ) >= 600 ) {
        return;
    }


    $file = YOURLS_USERDIR . '/maintenance.php';
    if(file_exists($file)) {
        if(yourls_include_file_sandbox( $file ) == true) {
            die();
        }
    }


    $title = yourls__('Service temporarily unavailable');
    $message = yourls__('Our service is currently undergoing scheduled maintenance.') . "</p>\n<p>" .
        yourls__('Things should not last very long, thank you for your patience and please excuse the inconvenience');
    yourls_die( $message, $title, 503 );
}















function yourls_is_allowed_protocol( $url, $protocols = [] ) {
    if ( empty( $protocols ) ) {
        global $yourls_allowedprotocols;
        $protocols = $yourls_allowedprotocols;
    }

    return yourls_apply_filter( 'is_allowed_protocol', in_array( yourls_get_protocol( $url ), $protocols ), $url, $protocols );
}
















function yourls_get_protocol( $url ) {







    preg_match( '!^[a-zA-Z][a-zA-Z0-9+.-]+:(//)?!', $url, $matches );
    return (string)yourls_apply_filter( 'get_protocol', isset( $matches[0] ) ? $matches[0] : '', $url );
}












function yourls_get_relative_url( $url, $strict = true ) {
    $url = yourls_sanitize_url( $url );


    $noproto_url = str_replace( 'https:', 'http:', $url );
    $noproto_site = str_replace( 'https:', 'http:', yourls_get_yourls_site() );


    $_url = str_replace( $noproto_site.'/', '', $noproto_url );
    if ( $_url == $noproto_url ) {
        $_url = ( $strict ? '' : $url );
    }
    return yourls_apply_filter( 'get_relative_url', $_url, $url );
}



















function yourls_deprecated_function( $function, $version, $replacement = null ) {

    yourls_do_action( 'deprecated_function', $function, $replacement, $version );


    if ( yourls_get_debug_mode() && yourls_apply_filter( 'deprecated_function_trigger_error', true ) ) {
        if ( ! is_null( $replacement ) )
            trigger_error( sprintf( yourls__('%1$s is <strong>deprecated</strong> since version %2$s! Use %3$s instead.'), $function, $version, $replacement ) );
        else
            trigger_error( sprintf( yourls__('%1$s is <strong>deprecated</strong> since version %2$s with no alternative available.'), $function, $version ) );
    }
}
























function yourls_get_protocol_slashes_and_rest( $url, $array = [ 'protocol', 'slashes', 'rest' ] ) {
    $proto = yourls_get_protocol( $url );

    if ( !$proto or count( $array ) != 3 ) {
        return false;
    }

    list( $null, $rest ) = explode( $proto, $url, 2 );

    list( $proto, $slashes ) = explode( ':', $proto );

    return [
        $array[ 0 ] => $proto.':',
        $array[ 1 ] => $slashes,
        $array[ 2 ] => $rest
    ];
}









function yourls_set_url_scheme( $url, $scheme = '' ) {
    if ( in_array( $scheme, [ 'http', 'https' ] ) ) {
        $url = preg_replace( '!^[a-zA-Z0-9+.-]+://!', $scheme.'://', $url );
    }
    return $url;
}










function yourls_tell_if_new_version() {
    yourls_debug_log( 'Check for new version: '.( yourls_maybe_check_core_version() ? 'yes' : 'no' ) );
    yourls_new_core_version_notice(YOURLS_VERSION);
}











function yourls_include_file_sandbox($file) {
    try {
        if (is_readable( $file )) {
            require_once $file;
            yourls_debug_log("loaded $file");
            return true;
        }
    } catch ( \Throwable $e ) {
        yourls_debug_log("could not load $file");
        return sprintf("%s (%s : %s)", $e->getMessage() , $e->getFile() , $e->getLine() );
    }
}
