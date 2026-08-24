<?php















function yourls_get_option( $option_name, $default = false ) {

    $pre = yourls_apply_filter( 'shunt_option_'.$option_name, yourls_shunt_default() );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $option = new \YOURLS\Database\Options(yourls_get_db('read-get_option'));
    $value  = $option->get($option_name, $default);

    return yourls_apply_filter( 'get_option_'.$option_name, $value );
}












function yourls_get_all_options() {

    $pre = yourls_apply_filter( 'shunt_all_options', yourls_shunt_default() );
    if ( yourls_shunt_default() !== $pre ) {
        return $pre;
    }

    $options = new \YOURLS\Database\Options(yourls_get_db('read-get_all_options'));

    if ($options->get_all_options() === false) {

        yourls_set_installed(false);
        return;
    }

    yourls_set_installed(true);
}











function yourls_update_option( $option_name, $newvalue ) {
    $option = new \YOURLS\Database\Options(yourls_get_db('write-update_option'));
    $update = $option->update($option_name, $newvalue);

    return $update;
}











function yourls_add_option( $name, $value = '' ) {
    $option = new \YOURLS\Database\Options(yourls_get_db('write-add_option'));
    $add    = $option->add($name, $value);

    return $add;
}










function yourls_delete_option( $name ) {
    $option = new \YOURLS\Database\Options(yourls_get_db('write-delete_option'));
    $delete = $option->delete($name);

    return $delete;
}








function yourls_maybe_serialize( $data ) {
    if ( is_array( $data ) || is_object( $data ) )
        return serialize( $data );

    if ( yourls_is_serialized( $data, false ) )
        return serialize( $data );

    return $data;
}








function yourls_maybe_unserialize( $original ) {
    if ( yourls_is_serialized( $original ) )
        return @unserialize( $original );
    return $original;
}









function yourls_is_serialized( $data, $strict = true ) {

    if ( ! is_string( $data ) )
        return false;
    $data = trim( $data );
     if ( 'N;' == $data )
        return true;
    $length = strlen( $data );
    if ( $length < 4 )
        return false;
    if ( ':' !== $data[1] )
        return false;
    if ( $strict ) {
        $lastc = $data[ $length - 1 ];
        if ( ';' !== $lastc && '}' !== $lastc )
            return false;
    } else {
        $semicolon = strpos( $data, ';' );
        $brace     = strpos( $data, '}' );

        if ( false === $semicolon && false === $brace )
            return false;

        if ( false !== $semicolon && $semicolon < 3 )
            return false;
        if ( false !== $brace && $brace < 4 )
            return false;
    }
    $token = $data[0];
    switch ( $token ) {
        case 's' :
            if ( $strict ) {
                if ( '"' !== $data[ $length - 2 ] )
                    return false;
            } elseif ( false === strpos( $data, '"' ) ) {
                return false;
            }

        case 'a' :
        case 'O' :
            return (bool) preg_match( "/^{$token}:[0-9]+:/s", $data );
        case 'b' :
        case 'i' :
        case 'd' :
            $end = $strict ? '$' : '';
            return (bool) preg_match( "/^{$token}:[0-9.E-]+;$end/", $data );
    }
    return false;
}
