<?php























function yourls_add_query_arg() {
    $ret = '';
    if ( is_array( func_get_arg(0) ) ) {
        if ( @func_num_args() < 2 || false === @func_get_arg( 1 ) )
            $uri = $_SERVER['REQUEST_URI'];
        else
            $uri = @func_get_arg( 1 );
    } else {
        if ( @func_num_args() < 3 || false === @func_get_arg( 2 ) )
            $uri = $_SERVER['REQUEST_URI'];
        else
            $uri = @func_get_arg( 2 );
    }

    $uri = str_replace( '&amp;', '&', $uri );


    if ( $frag = strstr( $uri, '#' ) )
        $uri = substr( $uri, 0, -strlen( $frag ) );
    else
        $frag = '';

    if ( preg_match( '|^https?://|i', $uri, $matches ) ) {
        $protocol = $matches[0];
        $uri = substr( $uri, strlen( $protocol ) );
    } else {
        $protocol = '';
    }

    if ( strpos( $uri, '?' ) !== false ) {
        $parts = explode( '?', $uri, 2 );
        if ( 1 == count( $parts ) ) {
            $base = '?';
            $query = $parts[0];
        } else {
            $base = $parts[0] . '?';
            $query = $parts[1];
        }
    } elseif ( !empty( $protocol ) || strpos( $uri, '=' ) === false ) {
        $base = $uri . '?';
        $query = '';
    } else {
        $base = '';
        $query = $uri;
    }

    parse_str( $query, $qs );
    $qs = yourls_urlencode_deep( $qs );
    if ( is_array( func_get_arg( 0 ) ) ) {
        $kayvees = func_get_arg( 0 );
        $qs = array_merge( $qs, $kayvees );
    } else {
        $qs[func_get_arg( 0 )] = func_get_arg( 1 );
    }

    foreach ( (array) $qs as $k => $v ) {
        if ( $v === false )
            unset( $qs[$k] );
    }

    $ret = http_build_query( $qs );
    $ret = trim( $ret, '?' );
    $ret = preg_replace( '#=(&|$)#', '$1', $ret );
    $ret = $protocol . $base . $ret . $frag;
    $ret = rtrim( $ret, '?' );
    return $ret;
}







function yourls_urlencode_deep( $value ) {
    $value = is_array( $value ) ? array_map( 'yourls_urlencode_deep', $value ) : urlencode( $value );
    return $value;
}











function yourls_remove_query_arg( $key, $query = false ) {
    if ( is_array( $key ) ) {
        foreach ( $key as $k )
            $query = yourls_add_query_arg( $k, false, $query );
        return $query;
    }
    return yourls_add_query_arg( $key, false, $query );
}











function yourls_link( $keyword = '', $stats = false ) {
    $keyword = yourls_sanitize_keyword($keyword);
    if( $stats  === true ) {
        $keyword = $keyword . '+';
    }
    $link    = yourls_normalize_uri( yourls_get_yourls_site() . '/' . $keyword );

    if( yourls_is_ssl() ) {
        $link = yourls_set_url_scheme( $link, 'https' );
    }

    return yourls_apply_filter( 'yourls_link', $link, $keyword );
}









function yourls_statlink( $keyword = '' ) {
    $link = yourls_link( $keyword, true );
    return yourls_apply_filter( 'yourls_statlink', $link, $keyword );
}







function yourls_admin_url( $page = '' ) {
    $admin = yourls_get_yourls_site() . '/admin/' . $page;
    if( yourls_is_ssl() or yourls_needs_ssl() ) {
        $admin = yourls_set_url_scheme( $admin, 'https' );
    }
    return yourls_apply_filter( 'admin_url', $admin, $page );
}








function yourls_site_url($echo = true, $url = '' ) {
    $url = yourls_get_relative_url( $url );
    $url = trim( yourls_get_yourls_site() . '/' . $url, '/' );


    if( yourls_is_ssl() ) {
        $url = yourls_set_url_scheme( $url, 'https' );
    }
    $url = yourls_apply_filter( 'site_url', $url );
    if( $echo ) {
        echo $url;
    }
    return $url;
}










function yourls_get_yourls_site() {
    return yourls_apply_filter('get_yourls_site', trim(YOURLS_SITE, '/'));
}


















function yourls_match_current_protocol( $url, $normal = 'http://', $ssl = 'https://' ) {

    if( yourls_is_ssl() && in_array( yourls_get_protocol($url), array('http://', 'https://') ) ) {
        $url = str_replace( $normal, $ssl, $url );
    }

    return yourls_apply_filter( 'match_current_protocol', $url );
}











function yourls_get_yourls_favicon_url( $echo = true ) {
    static $favicon = null;

    if( $favicon !== null ) {
        if( $echo ) {
            echo $favicon;
        }
        return $favicon;
    }

    $custom = null;

    foreach( array( 'gif', 'ico', 'png', 'jpg', 'svg' ) as $ext ) {
        if( file_exists( YOURLS_USERDIR. '/favicon.' . $ext ) ) {
            $custom = 'favicon.' . $ext;
            break;
        }
    }

    if( $custom ) {
        $favicon = yourls_site_url( false, YOURLS_USERURL . '/' . $custom );
    } else {
        $favicon = yourls_site_url( false ) . '/images/favicon.svg';
    }

    $favicon = yourls_apply_filter('get_favicon_url', $favicon);

    if( $echo ) {
        echo $favicon;
    }
    return $favicon;
}
