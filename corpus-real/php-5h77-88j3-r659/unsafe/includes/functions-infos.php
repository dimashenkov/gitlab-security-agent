<?php








function yourls_stats_countries_map($countries, $id = null) {

    yourls_do_action( 'pre_stats_countries_map' );


    if( $id === null )
        $id = uniqid ( 'yourls_stats_map_' );

    $data = array_merge( array( 'Country' => 'Hits' ), $countries );
    $data = yourls_google_array_to_data_table( $data );

    $options = array(
        'backgroundColor' => "white",
        'colorAxis'       => "{colors:['A8D0ED','99C4E4','8AB8DB','7BACD2','6BA1C9','5C95C0','4D89B7','3E7DAE','2E72A5','1F669C']}",
        'width'           => "550",
        'height'          => "340",
        'theme'           => 'maximized'
    );
    $options = yourls_apply_filter( 'stats_countries_map_options', $options );

    $map = yourls_google_viz_code( 'GeoChart', $data, $options, $id );

    echo yourls_apply_filter( 'stats_countries_map', $map, $countries, $options, $id );
}











function yourls_stats_pie($data, $limit = 10, $size = '340x220', $id = null) {

    yourls_do_action( 'pre_stats_pie' );


    if( $id === null )
        $id = uniqid ( 'yourls_stats_pie_' );


    if ( count( $data ) > $limit ) {
        $i= 0;
        $trim_data = array( 'Others' => 0 );
        foreach( $data as $item=>$value ) {
            $i++;
            if( $i <= $limit ) {
                $trim_data[$item] = $value;
            } else {
                $trim_data['Others'] += $value;
            }
        }
        $data = $trim_data;
    }


    $_data = yourls_scale_data( $data );

    list($width, $height) = explode( 'x', $size );

    $options = array(
        'theme'  => 'maximized',
        'width'   => $width,
        'height'   => $height,
        'colors'    => "['A8D0ED','99C4E4','8AB8DB','7BACD2','6BA1C9','5C95C0','4D89B7','3E7DAE','2E72A5','1F669C']",
        'legend'     => 'none',
        'chartArea'   => '{top: "5%", height: "90%"}',
        'pieSliceText' => 'label',
    );
    $options = yourls_apply_filter( 'stats_pie_options', $options );

    $script_data = array_merge( array( 'Country' => 'Value' ), $_data );
    $script_data = yourls_google_array_to_data_table( $script_data );

    $pie = yourls_google_viz_code( 'PieChart', $script_data, $options, $id );

    echo yourls_apply_filter( 'stats_pie', $pie, $data, $limit, $size, $options, $id );
}








function yourls_build_list_of_days($dates) {

















    if( !$dates )
        return array();


    $first_year = key( $dates );
    $_keys      = array_keys( $dates );
    $last_year  = end( $_keys );
    reset( $dates );


    $first_month = key( $dates[ $first_year ] );
    $_keys       = array_keys( $dates[ $last_year ] );
    $last_month  = end( $_keys );
    reset( $dates );


    $first_day = key( $dates[ $first_year ][ $first_month ] );
    $_keys     = array_keys( $dates[ $last_year ][ $last_month ] );
    $last_day  = end( $_keys );

    unset( $_keys );


    $today = new DateTime();
    $today->setTime( 0, 0, 0 );
    $today_year = $today->format( 'Y' );
    $today_month = $today->format( 'm' );
    $today_day = $today->format( 'd' );


    $list_of_years  = array();
    $list_of_months = array();
    $list_of_days   = array();
    for ( $year = $first_year; $year <= $today_year; $year++ ) {
        $_year = sprintf( '%04d', $year );
        $list_of_years[ $_year ] = $_year;
        $current_first_month = ( $year == $first_year ? $first_month : '01' );
        $current_last_month = ( $year == $today_year ? $today_month : '12' );
        for ( $month = $current_first_month; $month <= $current_last_month; $month++ ) {
            $_month = sprintf( '%02d', $month );
            $list_of_months[ $_month ] = $_month;
            $current_first_day = ( $year == $first_year && $month == $first_month ? $first_day : '01' );
            $current_last_day = ( $year == $today_year && $month == $today_month ? $today_day : yourls_days_in_month( $month, $year ) );
            for ( $day = $current_first_day; $day <= $current_last_day; $day++ ) {
                $day = sprintf( '%02d', $day );
                $key = date( 'M d, Y', mktime( 0, 0, 0, $_month, $day, $_year ) );
                $list_of_days[ $key ] = isset( $dates[$_year][$_month][$day] ) ? $dates[$_year][$_month][$day] : 0;
            }
        }
    }

    return array(
        'list_of_days'   => $list_of_days,
        'list_of_months' => $list_of_months,
        'list_of_years'  => $list_of_years,
    );
}











function yourls_stats_line($values, $id = null) {

    yourls_do_action( 'pre_stats_line' );


    if( $id === null )
        $id = uniqid ( 'yourls_stats_line_' );


    if ( count( $values ) == 1 )
        array_unshift( $values, 0 );


    $values = yourls_array_granularity( $values, 30 );

    $data = array_merge( array( 'Time' => 'Hits' ), $values );
    $data = yourls_google_array_to_data_table( $data );

    $options = array(
        "legend"      => "none",
        "pointSize"   => "3",
        "theme"       => "maximized",
        "curveType"   => "function",
        "width"       => 430,
        "height"      => 220,
        "hAxis"       => "{minTextSpacing: 80, maxTextLines: 1, maxAlternation: 1}",
        "vAxis"       => "{minValue: 0, format: '#'}",
        "colors"      => "['#2a85b3']",
    );
    $options = yourls_apply_filter( 'stats_line_options', $options );

    $lineChart = yourls_google_viz_code( 'LineChart', $data, $options, $id );

    echo yourls_apply_filter( 'stats_line', $lineChart, $values, $options, $id );
}









function yourls_days_in_month($month, $year) {

    return $month == 2 ? ( $year % 4 ? 28 : ( $year % 100 ? 29 : ( $year % 400 ? 28 : 29 ) ) ) : ( ( $month - 1 ) % 7 % 2 ? 30 : 31 );
}








function yourls_stats_get_best_day($list_of_days) {
    $max = max( $list_of_days );
    foreach( $list_of_days as $k=>$v ) {
        if ( $v == $max )
            return array( 'day' => $k, 'max' => $max );
    }
}








function yourls_get_domain(string $url, bool $include_scheme = false): string {
    $parse = parse_url($url);


    if ($parse === false) {
        return '';
    }


    $host = $parse['host'] ?? '';
    $scheme = $parse['scheme'] ?? '';
    $path = $parse['path'] ?? '';
    if (!$host) {
        $host = $path;
    }



    if ($host && !preg_match('/^(\[[\da-fA-F:]+\]|[a-zA-Z0-9._-]+)$/', $host)) {

        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($ascii === false || !preg_match('/^[a-zA-Z0-9._-]+$/', $ascii)) {
                return '';
            }
            $host = $ascii;
        } else {

            if (!preg_match('/^[\pL\pN._-]+$/u', $host)) {
                return '';
            }
        }
    }

    if ($include_scheme && $scheme) {
        $host = $scheme . '://' . $host;
    }

    return $host;
}








function yourls_get_favicon_url(string $url): string {
    return yourls_match_current_protocol( '//www.google.com/s2/favicons?domain=' . yourls_esc_url(yourls_get_domain( $url, false ) ) );
}







function yourls_scale_data($data ) {
    $max = max( $data );
    if( $max > 100 ) {
        foreach( $data as $k=>$v ) {
            $data[$k] = intval( $v / $max * 100 );
        }
    }
    return $data;
}













function yourls_array_granularity($array, $grain = 100, $preserve_max = true) {
    if ( count( $array ) > $grain ) {
        $max = max( $array );
        $step = intval( count( $array ) / $grain );
        $i = 0;

        foreach( $array as $k=>$v ) {
            $i++;
            if ( $i % $step != 0 ) {
                if ( $preserve_max == false ) {
                    unset( $array[$k] );
                } else {
                    if ( $v < $max )
                        unset( $array[$k] );
                }
            }
        }
    }
    return $array;
}







function yourls_google_array_to_data_table(array $data): string {
    $str  = "var data = google.visualization.arrayToDataTable([\n";
    foreach( $data as $label => $values ){
        if( !is_array( $values ) ) {
            $values = array( $values );
        }
        $str .= "\t['" . yourls_esc_js($label) . "',";
        foreach( $values as $value ){
            $value = yourls_esc_url( $value );
            if( !is_numeric( $value ) && !str_starts_with($value, '[') && !str_starts_with($value, '{')) {
                $value = "'" . yourls_esc_js($value) . "'";
            }
            $str .= "$value";
        }
        $str .= "],\n";
    }
    $str = substr( $str, 0, -2 ) . "\n";
    $str .= "]);\n";
    return $str;
}










function yourls_google_viz_code($graph_type, $data, $options, $id ) {
    $function_name = 'yourls_graph' . $id;
    $code  = "\n<script id=\"$function_name\" type=\"text/javascript\">\n";
    $code .= "function $function_name() { \n";

    $code .= "$data\n";

    $code .= "var options = {\n";
    foreach( $options as $field => $value ) {
        if( !is_numeric( $value ) && strpos( $value, '[' ) !== 0 && strpos( $value, '{' ) !== 0 ) {
            $value = "\"$value\"";
        }
        $code .= "\t'$field': $value,\n";
    }
    $code  = substr( $code, 0, -2 ) . "\n";
    $code .= "\t}\n";

    $code .= "new google.visualization.$graph_type( document.getElementById('visualization_$id') ).draw( data, options );";
    $code .= "}\n";
    $code .= "google.setOnLoadCallback( $function_name );\n";
    $code .= "</script>\n";
    $code .= "<div id=\"visualization_$id\"></div>\n";

    return $code;
}
