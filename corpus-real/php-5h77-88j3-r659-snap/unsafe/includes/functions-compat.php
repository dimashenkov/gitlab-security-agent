<?php











if( !function_exists( 'json_encode' ) ) {
    function json_encode( $array ) {
        return yourls_array_to_json( $array );
    }
}









function yourls_array_to_json( $array ){

    if( !is_array( $array ) ){
        return false;
    }

    $associative = count( array_diff( array_keys($array), array_keys( array_keys( $array )) ));
    if( $associative ){

        $construct = array();
        foreach( $array as $key => $value ){





            if( is_numeric( $key ) ){
                $key = "key_$key";
            }
            $key = '"'.addslashes( $key ).'"';


            if( is_array( $value )){
                $value = yourls_array_to_json( $value );
            } else if( !is_numeric( $value ) || is_string( $value ) ){
                $value = '"'.addslashes( $value ).'"';
            }


            $construct[] = "$key: $value";
        }


        $result = "{ " . implode( ", ", $construct ) . " }";

    } else {

        $construct = array();
        foreach( $array as $value ){


            if( is_array( $value )){
                $value = yourls_array_to_json( $value );
            } else if( !is_numeric( $value ) || is_string( $value ) ){
                $value = '"'.addslashes($value).'"';
            }


            $construct[] = $value;
        }


        $result = "[ " . implode( ", ", $construct ) . " ]";
    }

    return $result;
}






if ( !function_exists( 'bcdiv' ) ) {
    function bcdiv( $dividend, $divisor ) {
        $quotient = floor( $dividend/$divisor );
        return $quotient;
    }
    function bcmod( $dividend, $modulo ) {
        $remainder = $dividend%$modulo;
        return $remainder;
    }
    function bcmul( $left, $right ) {
        return $left * $right;
    }
    function bcadd( $left, $right ) {
        return $left + $right;
    }
    function bcpow( $base, $power ) {
        return pow( $base, $power );
    }
}


