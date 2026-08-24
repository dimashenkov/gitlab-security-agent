<?php












function yourls_int2string($num, $chars = null) {
    if( $chars == null )
        $chars = yourls_get_shorturl_charset();
    $string = '';
    $len = strlen( $chars );
    while( $num >= $len ) {
        $mod = bcmod( (string)$num, (string)$len );
        $num = bcdiv( (string)$num, (string)$len );
        $string = $chars[ $mod ] . $string;
    }
    $string = $chars[ intval( $num ) ] . $string;

    return yourls_apply_filter( 'int2string', $string, $num, $chars );
}








function yourls_string2int($string, $chars = null) {
    if( $chars == null )
        $chars = yourls_get_shorturl_charset();
    $integer = 0;
    $string = strrev( $string  );
    $baselen = strlen( $chars );
    $inputlen = strlen( $string );
    for ($i = 0; $i < $inputlen; $i++) {
        $index = strpos( $chars, $string[$i] );
        $integer = bcadd( (string)$integer, bcmul( (string)$index, bcpow( (string)$baselen, (string)$i ) ) );
    }

    return yourls_apply_filter( 'string2int', $integer, $string, $chars );
}









function yourls_unique_element_id($prefix = 'yid', $initial_val = 1) {
    static $id_counter = 1;
    if ($initial_val > 1) {
        $id_counter = (int) $initial_val;
    }
    return yourls_apply_filter( 'unique_element_id', $prefix . (string) $id_counter++ );
}














function yourls_sanitize_keyword( $keyword, $restrict_to_shorturl_charset = false ) {
    if( $restrict_to_shorturl_charset === true ) {

        $pattern = yourls_make_regexp_pattern( yourls_get_shorturl_charset() );
        $valid = (string) substr( preg_replace( '![^'.$pattern.']!', '', $keyword ), 0, 199 );
    } else {
        $valid = yourls_sanitize_url( $keyword );
    }

    return yourls_apply_filter( 'sanitize_string', $valid, $keyword, $restrict_to_shorturl_charset );
}










function yourls_sanitize_title( $unsafe_title, $fallback = '' ) {
    $title = $unsafe_title;
    $title = strip_tags( $title );
    $title = preg_replace( "/\s+/", ' ', trim( $title ) );

    if ( '' === $title || false === $title ) {
        $title = $fallback;
    }

    return yourls_apply_filter( 'sanitize_title', $title, $unsafe_title, $fallback );
}










function yourls_sanitize_url( $unsafe_url, $protocols = array() ) {
    $url = yourls_esc_url( $unsafe_url, 'redirection', $protocols );
    return yourls_apply_filter( 'sanitize_url', $url, $unsafe_url );
}















function yourls_sanitize_url_safe( $unsafe_url, $protocols = array() ) {
    $url = yourls_esc_url( $unsafe_url, 'safe', $protocols );
    return yourls_apply_filter( 'sanitize_url_safe', $url, $unsafe_url );
}










function yourls_deep_replace($search, $subject ){
    $found = true;
    while($found) {
        $found = false;
        foreach( (array) $search as $val ) {
            while( strpos( $subject, $val ) !== false ) {
                $found = true;
                $subject = str_replace( $val, '', $subject );
            }
        }
    }

    return $subject;
}







function yourls_sanitize_int($int ) {
    return ( substr( preg_replace( '/[^0-9]/', '', strval( $int ) ), 0, 20 ) );
}








function yourls_sanitize_ip($ip ) {
    return preg_replace( '/[^0-9a-fA-F:., ]/', '', $ip );
}







function yourls_sanitize_date($date ) {
    if( !preg_match( '!^\d{1,2}/\d{1,2}/\d{4}$!' , $date ) ) {
        return false;
    }
    return $date;
}







function yourls_sanitize_date_for_sql($date) {
    if( !yourls_sanitize_date( $date ) )
        return false;
    return date( 'Y-m-d', strtotime( $date ) );
}









function yourls_trim_long_string($string, $length = 60, $append = '[...]') {
    $newstring = $string;
    if ( mb_strlen( $newstring ) > $length ) {
        $newstring = mb_substr( $newstring, 0, $length - mb_strlen( $append ), 'UTF-8' ) . $append;
    }
    return yourls_apply_filter( 'trim_long_string', $newstring, $string, $length, $append );
}

















function yourls_sanitize_version( $version ) {
    preg_match( '/([0-9]+\.[0-9.]+).*$/', $version, $matches );
    $version = isset($matches[1]) ? trim($matches[1], '.') : '';

    return $version;
}







function yourls_sanitize_filename($file) {
    $file = str_replace( '\\', '/', $file );
    $file = preg_replace( '|/+|' ,'/', $file );
    return $file;
}
















function yourls_validate_jsonp_callback($callback ) {
    $callback = (string) $callback;



    if ( preg_match( '/\\\\?u[0-9a-fA-F]{4}/', $callback ) ) {
        return yourls_apply_filter( 'validate_jsonp_callback_error', false, $callback );
    }


    if ( !preg_match( '/^[a-zA-Z0-9_$.]+$/', $callback ) ) {
        return yourls_apply_filter( 'validate_jsonp_callback_error', false, $callback );
    }


    return yourls_apply_filter( 'validate_jsonp_callback', $callback );
}







function yourls_seems_utf8($str) {
    $length = strlen( $str );
    for ( $i=0; $i < $length; $i++ ) {
        $c = ord( $str[ $i ] );
        if ( $c < 0x80 ) $n = 0;
        elseif (($c & 0xE0) == 0xC0) $n=1;
        elseif (($c & 0xF0) == 0xE0) $n=2;
        elseif (($c & 0xF8) == 0xF0) $n=3;
        elseif (($c & 0xFC) == 0xF8) $n=4;
        elseif (($c & 0xFE) == 0xFC) $n=5;
        else return false;
        for ($j=0; $j<$n; $j++) {
            if ((++$i == $length) || ((ord($str[$i]) & 0xC0) != 0x80))
                return false;
        }
    }
    return true;
}












function yourls_supports_pcre_u() {
    static $utf8_pcre;
    if( !isset( $utf8_pcre ) ) {
        $utf8_pcre = (bool) @preg_match( '/^./u', 'a' );
    }
    return $utf8_pcre;
}










function yourls_check_invalid_utf8( $string, $strip = false ) {
    $string = (string) $string;

    if ( 0 === strlen( $string ) ) {
        return '';
    }


    if ( ! yourls_supports_pcre_u() ) {
        return $string;
    }


    if ( 1 === @preg_match( '/^./us', $string ) ) {
        return $string;
    }


    if ( $strip && function_exists( 'iconv' ) ) {
        return iconv( 'utf-8', 'utf-8', $string );
    }

    return '';
}
















function yourls_specialchars( $string, $quote_style = ENT_NOQUOTES, $double_encode = false ) {
    $string = (string) $string;

    if ( 0 === strlen( $string ) )
        return '';


    if ( ! preg_match( '/[&<>"\']/', $string ) )
        return $string;


    if ( empty( $quote_style ) )
        $quote_style = ENT_NOQUOTES;
    elseif ( ! in_array( $quote_style, array( 0, 2, 3, 'single', 'double' ), true ) )
        $quote_style = ENT_QUOTES;

    $charset = 'UTF-8';

    $_quote_style = $quote_style;

    if ( $quote_style === 'double' ) {
        $quote_style = ENT_COMPAT;
        $_quote_style = ENT_COMPAT;
    } elseif ( $quote_style === 'single' ) {
        $quote_style = ENT_NOQUOTES;
    }


    if ( $double_encode ) {
        $string = @htmlspecialchars( $string, $quote_style, $charset );
    } else {

        $string = yourls_specialchars_decode( $string, $_quote_style );


        $string = yourls_kses_normalize_entities( $string );


        $string = preg_split( '/(&#?x?[0-9a-z]+;)/i', $string, -1, PREG_SPLIT_DELIM_CAPTURE );

        for ( $i = 0; $i < count( $string ); $i += 2 )
            $string[$i] = @htmlspecialchars( $string[$i], $quote_style, $charset );

        $string = implode( '', $string );
    }


    if ( 'single' === $_quote_style )
        $string = str_replace( "'", '&#039;', $string );

    return $string;
}















function yourls_specialchars_decode( $string, $quote_style = ENT_NOQUOTES ) {
    $string = (string) $string;

    if ( 0 === strlen( $string ) ) {
        return '';
    }


    if ( strpos( $string, '&' ) === false ) {
        return $string;
    }


    if ( empty( $quote_style ) ) {
        $quote_style = ENT_NOQUOTES;
    } elseif ( !in_array( $quote_style, array( 0, 2, 3, 'single', 'double' ), true ) ) {
        $quote_style = ENT_QUOTES;
    }


    $single = array( '&#039;'  => '\'', '&#x27;' => '\'' );
    $single_preg = array( '/&#0*39;/'  => '&#039;', '/&#x0*27;/i' => '&#x27;' );
    $double = array( '&quot;' => '"', '&#034;'  => '"', '&#x22;' => '"' );
    $double_preg = array( '/&#0*34;/'  => '&#034;', '/&#x0*22;/i' => '&#x22;' );
    $others = array( '&lt;'   => '<', '&#060;'  => '<', '&gt;'   => '>', '&#062;'  => '>', '&amp;'  => '&', '&#038;'  => '&', '&#x26;' => '&' );
    $others_preg = array( '/&#0*60;/'  => '&#060;', '/&#0*62;/'  => '&#062;', '/&#0*38;/'  => '&#038;', '/&#x0*26;/i' => '&#x26;' );

    $translation = $translation_preg = [];

    if ( $quote_style === ENT_QUOTES ) {
        $translation = array_merge( $single, $double, $others );
        $translation_preg = array_merge( $single_preg, $double_preg, $others_preg );
    } elseif ( $quote_style === ENT_COMPAT || $quote_style === 'double' ) {
        $translation = array_merge( $double, $others );
        $translation_preg = array_merge( $double_preg, $others_preg );
    } elseif ( $quote_style === 'single' ) {
        $translation = array_merge( $single, $others );
        $translation_preg = array_merge( $single_preg, $others_preg );
    } elseif ( $quote_style === ENT_NOQUOTES ) {
        $translation = $others;
        $translation_preg = $others_preg;
    }


    $string = preg_replace( array_keys( $translation_preg ), array_values( $translation_preg ), $string );


    return strtr( $string, $translation );
}










function yourls_esc_html( $text ) {
    $safe_text = yourls_check_invalid_utf8( $text );
    $safe_text = yourls_specialchars( $safe_text, ENT_QUOTES );
    return yourls_apply_filter( 'esc_html', $safe_text, $text );
}









function yourls_esc_attr( $text ) {
    $safe_text = yourls_check_invalid_utf8( $text );
    $safe_text = yourls_specialchars( $safe_text, ENT_QUOTES );
    return yourls_apply_filter( 'esc_attr', $safe_text, $text );
}

















function yourls_esc_url( $url, $context = 'display', $protocols = array() ) {

    $url = trim( $url );


    $url = str_replace(
        array( 'http://http://', 'http://https://' ),
        array( 'http://',        'https://'        ),
        $url
    );

    if ( '' == $url )
        return $url;

    $original_url = $url;


    $url = yourls_normalize_uri( $url );

    $url = preg_replace( '|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\[\]\\\\\x80-\\xff]|i', '', $url );

    $url = yourls_remove_backslashes_before_query_fragment($url);






    if ( 'safe' == $context ) {
        $strip = array( '%0d', '%0a', '%0D', '%0A' );
        $url = yourls_deep_replace( $strip, $url );
    }


    if ( 'display' == $context ) {
        $url = yourls_kses_normalize_entities( $url );
        $url = str_replace( '&amp;', '&#038;', $url );
        $url = str_replace( "'", '&#039;', $url );
    }


    if( yourls_get_protocol($url) !== '' ) {
        if ( ! is_array( $protocols ) or ! $protocols ) {
            global $yourls_allowedprotocols;
            $protocols = yourls_apply_filter( 'esc_url_protocols', $yourls_allowedprotocols );

        }

        if ( !yourls_is_allowed_protocol( $url, $protocols ) )
            return '';


    }

    return yourls_apply_filter( 'esc_url', $url, $original_url, $context );
}












function yourls_remove_backslashes_before_query_fragment(string $url): string {
    $posQ = strpos($url, '?');
    $posH = strpos($url, '#');

    if ($posQ === false && $posH === false) {

        return str_replace('\\', '', $url);
    }


    if ($posQ === false) {
        $pos = $posH;
    } elseif ($posH === false) {
        $pos = $posQ;
    } else {
        $pos = min($posQ, $posH);
    }

    $before = substr($url, 0, $pos);
    $after  = substr($url, $pos);

    $before = str_replace('\\', '', $before);

    return $before . $after;
}

































function yourls_normalize_uri( $url ) {
    $scheme = yourls_get_protocol( $url );

    if ('' == $scheme) {

        return $url;
    }






    if (substr($scheme, -2, 2) != '//') {
        $url = str_replace( $scheme, strtolower( $scheme ), $url );
        return $url;
    }





    $parts = parse_url($url);


    if (false == $parts) {
        $url = str_replace( $scheme, strtolower( $scheme ), $url );
        return $url;
    }


    $lower = array();
    $lower['scheme'] = strtolower( $parts['scheme'] );
    if( isset( $parts['host'] ) ) {

        $lower['host'] = mb_strtolower($parts['host']);





         $lower['host'] = idn_to_utf8($lower['host'], IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    }

    $url = http_build_url($url, $lower);

    return $url;
}














function yourls_esc_js( $text ) {
    $safe_text = yourls_check_invalid_utf8( $text );
    $safe_text = yourls_specialchars( $safe_text, ENT_COMPAT );
    $safe_text = preg_replace( '/&#(x)?0*(?(1)27|39);?/i', "'", stripslashes( $safe_text ) );
    $safe_text = str_replace( "\r", '', $safe_text );
    $safe_text = str_replace( "\n", '\\n', addslashes( $safe_text ) );
    return yourls_apply_filter( 'esc_js', $safe_text, $text );
}









function yourls_esc_textarea( $text ) {
    $safe_text = htmlspecialchars( $text, ENT_QUOTES );
    return yourls_apply_filter( 'esc_textarea', $safe_text, $text );
}








function yourls_backslashit($string) {
    $string = preg_replace('/^([0-9])/', '\\\\\\\\\1', (string)$string);
    $string = preg_replace('/([a-z])/i', '\\\\\1', (string)$string);
    return $string;
}










function yourls_is_rawurlencoded( $string ) {
    return rawurldecode( $string ) != $string;
}











function yourls_rawurldecode_while_encoded( $string ) {
    $string = rawurldecode( $string );
    if( yourls_is_rawurlencoded( $string ) ) {
        $string = yourls_rawurldecode_while_encoded( $string );
    }
    return $string;
}










function yourls_make_bookmarklet( $code ) {
    $book = new \Ozh\Bookmarkletgen\Bookmarkletgen;
    return $book->crunch( $code );
}








function yourls_get_timestamp( $timestamp ) {
    $offset = yourls_get_time_offset();
    $timestamp_offset = (int)$timestamp + ($offset * 3600);

    return yourls_apply_filter( 'get_timestamp', $timestamp_offset, $timestamp, $offset );
}







function yourls_get_time_offset() {
    $offset = defined('YOURLS_HOURS_OFFSET') ? (int)YOURLS_HOURS_OFFSET : 0;
    return yourls_apply_filter( 'get_time_offset', $offset );
}








function yourls_get_datetime_format( $format ) {
    return yourls_apply_filter( 'get_datetime_format', (string)$format );
}








function yourls_get_date_format( $format ) {
    return yourls_apply_filter( 'get_date_format', (string)$format );
}








function yourls_get_time_format( $format ) {
    return yourls_apply_filter( 'get_time_format', (string)$format );
}
