<?php






























function yourls_add_new_link( $url, $keyword = '', $title = '', $row_id = 1 ) {

    $pre = yourls_apply_filter( 'shunt_add_new_link', yourls_shunt_default(), $url, $keyword, $title );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }




    $return = [

        'status' => '',
        'code'   => '',
        'message' => '',
        'errorCode' => '',
        'statusCode' => '',
    ];


    $url = yourls_sanitize_url( $url );
    if ( !$url || $url == 'http://' || $url == 'https://' ) {
        $return['status']    = 'fail';
        $return['code']      = 'error:nourl';
        $return['message']   = yourls__( 'Missing or malformed URL' );
        $return['errorCode'] = $return['statusCode'] = '400';

        return yourls_apply_filter( 'add_new_link_fail_nourl', $return, $url, $keyword, $title );
    }


    $ip = yourls_get_IP();
    yourls_check_IP_flood( $ip );


    if (yourls_is_shorturl($url)) {
        $return['status']    = 'fail';
        $return['code']      = 'error:noloop';
        $return['message']   = yourls__( 'URL is a short URL' );
        $return['errorCode'] = $return['statusCode'] = '400';
        return yourls_apply_filter( 'add_new_link_fail_noloop', $return, $url, $keyword, $title );
    }

    yourls_do_action( 'pre_add_new_link', $url, $keyword, $title );


    if ( !yourls_allow_duplicate_longurls() && ($url_exists = yourls_long_url_exists( $url )) ) {
        yourls_do_action( 'add_new_link_already_stored', $url, $keyword, $title );

        $return['status']   = 'fail';
        $return['code']     = 'error:url';
        $return['url']      = array( 'keyword' => $url_exists->keyword, 'url' => $url, 'title' => $url_exists->title, 'date' => $url_exists->timestamp, 'ip' => $url_exists->ip, 'clicks' => $url_exists->clicks );
        $return['message']  =  yourls_s('%s already exists in database (short URL: %s)',
            yourls_trim_long_string($url), preg_replace('!https?://!', '',  yourls_get_yourls_site()) . '/'. $url_exists->keyword );
        $return['title']    = $url_exists->title;
        $return['shorturl'] = yourls_link($url_exists->keyword);
        $return['errorCode'] = $return['statusCode'] = '400';

        return yourls_apply_filter( 'add_new_link_already_stored_filter', $return, $url, $keyword, $title );
    }


    if( isset( $title ) && !empty( $title ) ) {
        $title = yourls_sanitize_title( $title );
    } else {
        $title = yourls_get_remote_title( $url );
    }
    $title = yourls_apply_filter( 'add_new_title', $title, $url, $keyword );


    if ($keyword) {
        yourls_do_action( 'add_new_link_custom_keyword', $url, $keyword, $title );

        $keyword = yourls_sanitize_keyword( $keyword, true );
        $keyword = yourls_apply_filter( 'custom_keyword', $keyword, $url, $title );

        if ( !yourls_keyword_is_free( $keyword ) ) {

            $return['status']  = 'fail';
            $return['code']    = 'error:keyword';
            $return['message'] = yourls_s( 'Short URL %s already exists in database or is reserved', $keyword );
            $return['errorCode'] = $return['statusCode'] = '400';

            return yourls_apply_filter( 'add_new_link_keyword_exists', $return, $url, $keyword, $title );
        }


    } else {
        yourls_do_action( 'add_new_link_create_keyword', $url, $keyword, $title );

        $id = yourls_get_next_decimal();

        do {
            $keyword = yourls_int2string( $id );
            $keyword = yourls_apply_filter( 'random_keyword', $keyword, $url, $title );
            $id++;
        } while ( !yourls_keyword_is_free($keyword) );

        yourls_update_next_decimal($id);
    }



    $timestamp = date( 'Y-m-d H:i:s' );

    try {
        if (yourls_insert_link_in_db( $url, $keyword, $title )){

            $return['url']      = array('keyword' => $keyword, 'url' => $url, 'title' => $title, 'date' => $timestamp, 'ip' => $ip );
            $return['status']   = 'success';
            $return['message']  =  yourls_s( '%s added to database', yourls_trim_long_string( $url ) );
            $return['title']    = $title;
            $return['html']     = yourls_table_add_row( $keyword, $url, $title, $ip, 0, time(), $row_id );
            $return['shorturl'] = yourls_link($keyword);
            $return['statusCode'] = '200';
        } else {

            $return['status']   = 'fail';
            $return['code']     = 'error:db';
            $return['message']  = yourls_s( 'Error saving url to database' );
            $return['errorCode'] = $return['statusCode'] = '500';
        }
    } catch (Exception $e) {


        $return['status']  = 'fail';
        $return['code']    = 'error:concurrency';
        $return['message'] = $e->getMessage();
        $return['errorCode'] = $return['statusCode'] = '503';
    }

    yourls_do_action( 'post_add_new_link', $url, $keyword, $title, $return );

    return yourls_apply_filter( 'add_new_link', $return, $url, $keyword, $title );
}





function yourls_get_shorturl_charset() {
    if ( defined( 'YOURLS_URL_CONVERT' ) && in_array( YOURLS_URL_CONVERT, [ 62, 64 ] ) ) {
        $charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }
    else {

        $charset = '0123456789abcdefghijklmnopqrstuvwxyz';
    }

    return yourls_apply_filter( 'get_shorturl_charset', $charset );
}







function yourls_is_shorturl( $shorturl ) {


    $is_short = false;


    if( yourls_get_protocol( $shorturl ) ) {
        $keyword = yourls_get_relative_url( $shorturl );
    } else {
        $keyword = $shorturl;
    }


    if( $keyword && $keyword == yourls_sanitize_keyword( $keyword ) && yourls_keyword_is_taken( $keyword ) ) {
        $is_short = true;
    }

    return yourls_apply_filter( 'is_shorturl', $is_short, $shorturl );
}






function yourls_get_reserved_URL() {
    global $yourls_reserved_URL;
    if ( ! isset( $yourls_reserved_URL ) || ! is_array( $yourls_reserved_URL ) ) {
        return array();
    }

    return $yourls_reserved_URL;
}







function yourls_keyword_is_reserved( $keyword ) {
    $keyword = yourls_sanitize_keyword( $keyword );
    $reserved = false;

    if ( in_array( $keyword, yourls_get_reserved_URL() )
        or yourls_is_page($keyword)
        or is_dir( YOURLS_ABSPATH ."/$keyword" )
    )
        $reserved = true;

    return yourls_apply_filter( 'keyword_is_reserved', $reserved, $keyword );
}







function yourls_delete_link_by_keyword( $keyword ) {

    $pre = yourls_apply_filter( 'shunt_delete_link_by_keyword', yourls_shunt_default(), $keyword );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $table = YOURLS_DB_TABLE_URL;
    $keyword = yourls_sanitize_keyword($keyword);
    $ydb = yourls_get_db('write-delete_link_by_keyword');
    $delete = $ydb->fetchAffected("DELETE FROM `$table` WHERE `keyword` = :keyword", array('keyword' => $keyword));
    $ydb->delete_infos($keyword);
    yourls_do_action( 'delete_link', $keyword, $delete );
    return $delete;
}









function yourls_insert_link_in_db($url, $keyword, $title = '' ) {
    $url       = yourls_sanitize_url($url);
    $keyword   = yourls_sanitize_keyword($keyword);
    $title     = yourls_sanitize_title($title);
    $timestamp = date('Y-m-d H:i:s');
    $ip        = yourls_get_IP();

    $table = YOURLS_DB_TABLE_URL;
    $binds = array(
        'keyword'   => $keyword,
        'url'       => $url,
        'title'     => $title,
        'timestamp' => $timestamp,
        'ip'        => $ip,
    );
    $ydb = yourls_get_db('write-insert_link_in_db');
    $insert = $ydb->fetchAffected("INSERT INTO `$table` (`keyword`, `url`, `title`, `timestamp`, `ip`, `clicks`) VALUES(:keyword, :url, :title, :timestamp, :ip, 0);", $binds);

    if ( $insert ) {
        $infos = $binds;
        $infos['clicks'] = 0;
        $ydb->set_infos($keyword, $infos);
    }

    yourls_do_action( 'insert_link', (bool)$insert, $url, $keyword, $title, $timestamp, $ip );

    return (bool)$insert;
}










function yourls_long_url_exists( $url ) {

    $pre = yourls_apply_filter( 'shunt_url_exists', yourls_shunt_default(), $url );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $table = YOURLS_DB_TABLE_URL;
    $url   = yourls_sanitize_url($url);
    $url_exists = yourls_get_db('read-long_url_exists')->fetchObject("SELECT * FROM `$table` WHERE `url` = :url", array('url'=>$url));

    if ($url_exists === false) {
        $url_exists = NULL;
    }

    return yourls_apply_filter( 'url_exists', $url_exists, $url );
}










function yourls_edit_link($url, $keyword, $newkeyword='', $title='' ) {

    $pre = yourls_apply_filter( 'shunt_edit_link', yourls_shunt_default(), $keyword, $url, $keyword, $newkeyword, $title );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $ydb = yourls_get_db('write-edit_link');

    $table = YOURLS_DB_TABLE_URL;
    $url = yourls_sanitize_url($url);
    $keyword = yourls_sanitize_keyword($keyword);
    $title = yourls_sanitize_title($title);
    $newkeyword = yourls_sanitize_keyword($newkeyword, true);

    if(!$url OR !$newkeyword) {
        $return['status']  = 'fail';
        $return['message'] = yourls__( 'Long URL or Short URL cannot be blank' );
        return yourls_apply_filter( 'edit_link', $return, $url, $keyword, $newkeyword, $title );
    }

    $old_url = $ydb->fetchValue("SELECT `url` FROM `$table` WHERE `keyword` = :keyword", array('keyword' => $keyword));


    if ( $old_url != $url && !yourls_allow_duplicate_longurls() ) {
        $new_url_already_there = intval($ydb->fetchValue("SELECT COUNT(keyword) FROM `$table` WHERE `url` = :url;", array('url' => $url)));
    } else {
        $new_url_already_there = false;
    }


    if ( $newkeyword != $keyword ) {
        $keyword_is_ok = yourls_keyword_is_free( $newkeyword );
    } else {
        $keyword_is_ok = true;
    }

    yourls_do_action( 'pre_edit_link', $url, $keyword, $newkeyword, $new_url_already_there, $keyword_is_ok );


    if ( ( !$new_url_already_there || yourls_allow_duplicate_longurls() ) && $keyword_is_ok ) {
            $sql   = "UPDATE `$table` SET `url` = :url, `keyword` = :newkeyword, `title` = :title WHERE `keyword` = :keyword";
            $binds = array('url' => $url, 'newkeyword' => $newkeyword, 'title' => $title, 'keyword' => $keyword);
            $update_url = $ydb->fetchAffected($sql, $binds);
        if( $update_url ) {
            $return['url']     = array( 'keyword'       => $newkeyword,
                                        'shorturl'      => yourls_link($newkeyword),
                                        'url'           => yourls_esc_url($url),
                                        'display_url'   => yourls_esc_html(yourls_trim_long_string($url)),
                                        'title'         => yourls_esc_attr($title),
                                        'display_title' => yourls_esc_html(yourls_trim_long_string( $title ))
                                );
            $return['status']  = 'success';
            $return['message'] = yourls__( 'Link updated in database' );
            $ydb->update_infos_if_exists($newkeyword, array('url' => $url, 'title' => $title));
            if ($keyword != $newkeyword) {
                $ydb->delete_infos($keyword);
            }
        } else {
            $return['status']  = 'fail';
            $return['message'] =  yourls_s( 'Error updating %s (Short URL: %s)', yourls_esc_html(yourls_trim_long_string($url)), $keyword ) ;
        }


    } else {
        $return['status']  = 'fail';
        $return['message'] = yourls__( 'URL or keyword already exists in database' );
    }

    return yourls_apply_filter( 'edit_link', $return, $url, $keyword, $newkeyword, $title, $new_url_already_there, $keyword_is_ok );
}








function yourls_edit_link_title( $keyword, $title ) {

    $pre = yourls_apply_filter( 'shunt_edit_link_title', yourls_shunt_default(), $keyword, $title );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $keyword = yourls_sanitize_keyword( $keyword );
    $title = yourls_sanitize_title( $title );

    $table = YOURLS_DB_TABLE_URL;
    $ydb = yourls_get_db('write-edit_link_title');
    $update = $ydb->fetchAffected("UPDATE `$table` SET `title` = :title WHERE `keyword` = :keyword;", array('title' => $title, 'keyword' => $keyword));

    if ( $update ) {
        $ydb->update_infos_if_exists( $keyword, array('title' => $title) );
    }

    return $update;
}







function yourls_keyword_is_free( $keyword  ) {
    $free = true;
    if ( yourls_keyword_is_reserved( $keyword ) or yourls_keyword_is_taken( $keyword, false ) ) {
        $free = false;
    }

    return yourls_apply_filter( 'keyword_is_free', $free, $keyword );
}









function yourls_is_page($keyword) {
    return yourls_apply_filter( 'is_page', file_exists( YOURLS_PAGEDIR . "/$keyword.php" ) );
}












function yourls_keyword_is_taken( $keyword, $use_cache = true ) {

    $pre = yourls_apply_filter( 'shunt_keyword_is_taken', yourls_shunt_default(), $keyword );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $taken = false;


    if ( yourls_get_keyword_infos($keyword, $use_cache) ) {
        $taken = true;
    }

    return yourls_apply_filter( 'keyword_is_taken', $taken, $keyword );
}













function yourls_get_keyword_infos( $keyword, $use_cache = true ) {
    $ydb = yourls_get_db('read-get_keyword_infos');
    $keyword = yourls_sanitize_keyword( $keyword );

    yourls_do_action( 'pre_get_keyword', $keyword, $use_cache );

    if( $ydb->has_infos($keyword) && $use_cache === true ) {
        return yourls_apply_filter( 'get_keyword_infos', $ydb->get_infos($keyword), $keyword );
    }

    yourls_do_action( 'get_keyword_not_cached', $keyword );

    $table = YOURLS_DB_TABLE_URL;
    $infos = $ydb->fetchObject("SELECT * FROM `$table` WHERE `keyword` = :keyword", array('keyword' => $keyword));

    if( $infos ) {
        $infos = (array)$infos;
        $ydb->set_infos($keyword, $infos);
    } else {

        $infos = false;
        $ydb->set_infos($keyword, false);
    }

    return yourls_apply_filter( 'get_keyword_infos', $infos, $keyword );
}









function yourls_get_keyword_info($keyword, $field, $notfound = false ) {


    $pre = yourls_apply_filter( 'shunt_get_keyword_info', yourls_shunt_default(), $keyword, $field, $notfound );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $keyword = yourls_sanitize_keyword( $keyword );
    $infos = yourls_get_keyword_infos( $keyword );

    $return = $notfound;
    if ( isset( $infos[ $field ] ) && $infos[ $field ] !== false )
        $return = $infos[ $field ];

    return yourls_apply_filter( 'get_keyword_info', $return, $keyword, $field, $notfound );
}








function yourls_get_keyword_title( $keyword, $notfound = false ) {
    return yourls_get_keyword_info( $keyword, 'title', $notfound );
}








function yourls_get_keyword_longurl( $keyword, $notfound = false ) {
    return yourls_get_keyword_info( $keyword, 'url', $notfound );
}








function yourls_get_keyword_clicks( $keyword, $notfound = false ) {
    return yourls_get_keyword_info( $keyword, 'clicks', $notfound );
}








function yourls_get_keyword_IP( $keyword, $notfound = false ) {
    return yourls_get_keyword_info( $keyword, 'ip', $notfound );
}








function yourls_get_keyword_timestamp( $keyword, $notfound = false ) {
    return yourls_get_keyword_info( $keyword, 'timestamp', $notfound );
}










function yourls_get_keyword_stats( $shorturl ) {
    $table_url = YOURLS_DB_TABLE_URL;
    $shorturl  = yourls_sanitize_keyword( $shorturl );

    $res = yourls_get_db('read-get_keyword_stats')->fetchObject("SELECT * FROM `$table_url` WHERE `keyword` = :keyword", array('keyword' => $shorturl));

    if( !$res ) {

        $return = array(
            'statusCode' => '404',
            'message'    => 'Error: short URL not found',
        );
    } else {
        $return = array(
            'statusCode' => '200',
            'message'    => 'success',
            'link'       => array(
                'shorturl' => yourls_link($res->keyword),
                'url'      => $res->url,
                'title'    => $res->title,
                'timestamp'=> $res->timestamp,
                'ip'       => $res->ip,
                'clicks'   => $res->clicks,
            )
        );
    }

    return yourls_apply_filter( 'get_link_stats', $return, $shorturl );
}









function yourls_get_longurl_keywords( $longurl, $order = 'ASC' ) {
    $longurl = yourls_sanitize_url($longurl);
    $table   = YOURLS_DB_TABLE_URL;
    $sql     = "SELECT `keyword` FROM `$table` WHERE `url` = :url";

    if (in_array($order, array('ASC','DESC'))) {
        $sql .= " ORDER BY `keyword` ".$order;
    }

    return yourls_apply_filter( 'get_longurl_keywords', yourls_get_db('read-get_longurl_keywords')->fetchCol($sql, array('url'=>$longurl)), $longurl );
}
