<?php













use POMO\MO;
use POMO\Translations\NOOPTranslations;


















function yourls_get_locale() {
    global $yourls_locale;

    if ( !isset( $yourls_locale ) ) {

        if ( defined( 'YOURLS_LANG' ) )
            $yourls_locale = YOURLS_LANG;
    }

    if ( !$yourls_locale )
        $yourls_locale = '';

    return yourls_apply_filter( 'get_locale', $yourls_locale );
}












function yourls_translate( $text, $domain = 'default' ) {
    $translations = yourls_get_translations_for_domain( $domain );
    return yourls_apply_filter( 'translate', $translations->translate( $text ), $text, $domain );
}

















function yourls_translate_with_context( $text, $context, $domain = 'default' ) {
    $translations = yourls_get_translations_for_domain( $domain );
    return yourls_apply_filter( 'translate_with_context', $translations->translate( $text, $context ), $text, $context, $domain );
}












function yourls__( $text, $domain = 'default' ) {
    return yourls_translate( $text, $domain );
}

















function yourls_s( $pattern ) {

    $args = func_get_args();

    if( count( $args ) == 1 && is_array( $args[0] ) ) {
        $args = $args[0];
    }
    $pattern = $args[0];


    $num_of_tokens = substr_count( $pattern, '%' ) - 2 * substr_count( $pattern, '%%' );

    $domain = 'default';

    if( $num_of_tokens < ( count( $args ) - 1 ) ) {
        $domain = array_pop( $args );
    }


    $args[0] = yourls__( $pattern, $domain );

    return call_user_func_array( 'sprintf', $args );
}


















function yourls_se( $pattern ) {
    echo yourls_s( func_get_args() );
}














function yourls_esc_attr__( $text, $domain = 'default' ) {
    return yourls_esc_attr( yourls_translate( $text, $domain ) );
}













function yourls_esc_html__( $text, $domain = 'default' ) {
    return yourls_esc_html( yourls_translate( $text, $domain ) );
}











function yourls_e( $text, $domain = 'default' ) {
    echo yourls_translate( $text, $domain );
}












function yourls_esc_attr_e( $text, $domain = 'default' ) {
    echo yourls_esc_attr( yourls_translate( $text, $domain ) );
}












function yourls_esc_html_e( $text, $domain = 'default' ) {
    echo yourls_esc_html( yourls_translate( $text, $domain ) );
}

















function yourls_x( $text, $context, $domain = 'default' ) {
    return yourls_translate_with_context( $text, $context, $domain );
}












function yourls_xe( $text, $context, $domain = 'default' ) {
    echo yourls_x( $text, $context, $domain );
}















function yourls_esc_attr_x( $single, $context, $domain = 'default' ) {
    return yourls_esc_attr( yourls_translate_with_context( $single, $context, $domain ) );
}














function yourls_esc_html_x( $single, $context, $domain = 'default' ) {
    return yourls_esc_html( yourls_translate_with_context( $single, $context, $domain ) );
}




















function yourls_n( $single, $plural, $number, $domain = 'default' ) {
    $translations = yourls_get_translations_for_domain( $domain );
    $translation = $translations->translate_plural( $single, $plural, $number );
    return yourls_apply_filter( 'translate_n', $translation, $single, $plural, $number, $domain );
}















function yourls_nx($single, $plural, $number, $context, $domain = 'default') {
    $translations = yourls_get_translations_for_domain( $domain );
    $translation = $translations->translate_plural( $single, $plural, $number, $context );
    return yourls_apply_filter( 'translate_nx', $translation, $single, $plural, $number, $context, $domain );
}






















function yourls_n_noop( $singular, $plural, $domain = null ) {
    return array(
        0 => $singular,
        1 => $plural,
        'singular' => $singular,
        'plural' => $plural,
        'context' => null,
        'domain' => $domain
    );
}













function yourls_nx_noop( $singular, $plural, $context, $domain = null ) {
    return array(
        0 => $singular,
        1 => $plural,
        2 => $context,
        'singular' => $singular,
        'plural' => $plural,
        'context' => $context,
        'domain' => $domain
    );
}











function yourls_translate_nooped_plural( $nooped_plural, $count, $domain = 'default' ) {
    if ( $nooped_plural['domain'] )
        $domain = $nooped_plural['domain'];

    if ( $nooped_plural['context'] )
        return yourls_nx( $nooped_plural['singular'], $nooped_plural['plural'], $count, $nooped_plural['context'], $domain );
    else
        return yourls_n( $nooped_plural['singular'], $nooped_plural['plural'], $count, $domain );
}
















function yourls_load_textdomain( $domain, $mofile ) {
    global $yourls_l10n;

    $plugin_override = yourls_apply_filter( 'override_load_textdomain', false, $domain, $mofile );

    if ( true == $plugin_override ) {
        return true;
    }

    yourls_do_action( 'load_textdomain', $domain, $mofile );

    $mofile = yourls_apply_filter( 'load_textdomain_mofile', $mofile, $domain );

    if ( !is_readable( $mofile ) ) {
        trigger_error( 'Cannot read file ' . str_replace( YOURLS_ABSPATH.'/', '', $mofile ) . '.'
                    . ' Make sure there is a language file installed. More info: http://yourls.org/translations' );
        return false;
    }

    $mo = new MO();
    if ( !$mo->import_from_file( $mofile ) )
        return false;

    if ( isset( $yourls_l10n[$domain] ) )
        $mo->merge_with( $yourls_l10n[$domain] );

    $yourls_l10n[$domain] = &$mo;

    return true;
}








function yourls_unload_textdomain( $domain ) {
    global $yourls_l10n;

    $plugin_override = yourls_apply_filter( 'override_unload_textdomain', false, $domain );

    if ( $plugin_override )
        return true;

    yourls_do_action( 'unload_textdomain', $domain );

    if ( isset( $yourls_l10n[$domain] ) ) {
        unset( $yourls_l10n[$domain] );
        return true;
    }

    return false;
}










function yourls_load_default_textdomain() {
    $yourls_locale = yourls_get_locale();

    if( !empty( $yourls_locale ) )
        return yourls_load_textdomain( 'default', YOURLS_LANG_DIR . "/$yourls_locale.mo" );

    return false;
}








function yourls_get_translations_for_domain( $domain ) {
    global $yourls_l10n;
    if ( !isset( $yourls_l10n[$domain] ) ) {
        $yourls_l10n[$domain] = new NOOPTranslations;
    }
    return $yourls_l10n[$domain];
}








function yourls_is_textdomain_loaded( $domain ) {
    global $yourls_l10n;
    return isset( $yourls_l10n[$domain] );
}













function yourls_translate_user_role( $name ) {
    return yourls_translate_with_context( $name, 'User role' );
}









function yourls_get_available_languages( $dir = null ) {
    $languages = array();

    $dir = is_null( $dir) ? YOURLS_LANG_DIR : $dir;

    foreach( (array) glob( $dir . '/*.mo' ) as $lang_file ) {
        $languages[] = basename( $lang_file, '.mo' );
    }

    return yourls_apply_filter( 'get_available_languages', $languages );
}










function yourls_number_format_i18n( $number, $decimals = 0 ) {
    global $yourls_locale_formats;
    if( !isset( $yourls_locale_formats ) )
        $yourls_locale_formats = new YOURLS_Locale_Formats();

    $formatted = number_format( $number, abs( intval( $decimals ) ), $yourls_locale_formats->number_format['decimal_point'], $yourls_locale_formats->number_format['thousands_sep'] );
    return yourls_apply_filter( 'number_format_i18n', $formatted );
}














function yourls_date_i18n( $dateformatstring, $timestamp = false ) {



    global $yourls_locale_formats;
    if( !isset( $yourls_locale_formats ) )
        $yourls_locale_formats = new YOURLS_Locale_Formats();

    if ( false === $timestamp ) {
        $timestamp = yourls_get_timestamp( time() );
    }


    $req_format = $dateformatstring;







    if ( ( !empty( $yourls_locale_formats->month ) ) && ( !empty( $yourls_locale_formats->weekday ) ) ) {
        $datemonth            = $yourls_locale_formats->get_month( date( 'm', $timestamp ) );
        $datemonth_abbrev     = $yourls_locale_formats->get_month_abbrev( $datemonth );
        $dateweekday          = $yourls_locale_formats->get_weekday( date( 'w', $timestamp ) );
        $dateweekday_abbrev   = $yourls_locale_formats->get_weekday_abbrev( $dateweekday );
        $datemeridiem         = $yourls_locale_formats->get_meridiem( date( 'a', $timestamp ) );
        $datemeridiem_capital = $yourls_locale_formats->get_meridiem( date( 'A', $timestamp ) );

        $dateformatstring = ' '.$dateformatstring;
        $dateformatstring = preg_replace( "/([^\\\])D/", "\\1" . yourls_backslashit( $dateweekday_abbrev ), $dateformatstring );
        $dateformatstring = preg_replace( "/([^\\\])F/", "\\1" . yourls_backslashit( $datemonth ), $dateformatstring );
        $dateformatstring = preg_replace( "/([^\\\])l/", "\\1" . yourls_backslashit( $dateweekday ), $dateformatstring );
        $dateformatstring = preg_replace( "/([^\\\])M/", "\\1" . yourls_backslashit( $datemonth_abbrev ), $dateformatstring );
        $dateformatstring = preg_replace( "/([^\\\])a/", "\\1" . yourls_backslashit( $datemeridiem ), $dateformatstring );
        $dateformatstring = preg_replace( "/([^\\\])A/", "\\1" . yourls_backslashit( $datemeridiem_capital ), $dateformatstring );

        $dateformatstring = substr( $dateformatstring, 1, strlen( $dateformatstring ) -1 );
    }

    $date = date( $dateformatstring, $timestamp );


    return yourls_apply_filter('date_i18n', $date, $req_format, $timestamp);
}






class YOURLS_Locale_Formats {







    var $weekday;













    var $weekday_initial;








    var $weekday_abbrev;








    var $month;








    var $month_abbrev;










    var $meridiem;








    var $number_format;










    var $text_direction = 'ltr';












    function init() {

        $this->weekday[0] =  yourls__( 'Sunday' );
        $this->weekday[1] =  yourls__( 'Monday' );
        $this->weekday[2] =  yourls__( 'Tuesday' );
        $this->weekday[3] =  yourls__( 'Wednesday' );
        $this->weekday[4] =  yourls__( 'Thursday' );
        $this->weekday[5] =  yourls__( 'Friday' );
        $this->weekday[6] =  yourls__( 'Saturday' );



        $this->weekday_initial[yourls__( 'Sunday' )]    =  yourls__( 'S_Sunday_initial' );
        $this->weekday_initial[yourls__( 'Monday' )]    =  yourls__( 'M_Monday_initial' );
        $this->weekday_initial[yourls__( 'Tuesday' )]   =  yourls__( 'T_Tuesday_initial' );
        $this->weekday_initial[yourls__( 'Wednesday' )] =  yourls__( 'W_Wednesday_initial' );
        $this->weekday_initial[yourls__( 'Thursday' )]  =  yourls__( 'T_Thursday_initial' );
        $this->weekday_initial[yourls__( 'Friday' )]    =  yourls__( 'F_Friday_initial' );
        $this->weekday_initial[yourls__( 'Saturday' )]  =  yourls__( 'S_Saturday_initial' );

        foreach ($this->weekday_initial as $weekday_ => $weekday_initial_) {
            $this->weekday_initial[$weekday_] = preg_replace('/_.+_initial$/', '', $weekday_initial_);
        }


        $this->weekday_abbrev[ yourls__( 'Sunday' ) ]    =  yourls__( 'Sun' );
        $this->weekday_abbrev[ yourls__( 'Monday' ) ]    =  yourls__( 'Mon' );
        $this->weekday_abbrev[ yourls__( 'Tuesday' ) ]   =  yourls__( 'Tue' );
        $this->weekday_abbrev[ yourls__( 'Wednesday' ) ] =  yourls__( 'Wed' );
        $this->weekday_abbrev[ yourls__( 'Thursday' ) ]  =  yourls__( 'Thu' );
        $this->weekday_abbrev[ yourls__( 'Friday' ) ]    =  yourls__( 'Fri' );
        $this->weekday_abbrev[ yourls__( 'Saturday' ) ]  =  yourls__( 'Sat' );


        $this->month['01'] =  yourls__( 'January' );
        $this->month['02'] =  yourls__( 'February' );
        $this->month['03'] =  yourls__( 'March' );
        $this->month['04'] =  yourls__( 'April' );
        $this->month['05'] =  yourls__( 'May' );
        $this->month['06'] =  yourls__( 'June' );
        $this->month['07'] =  yourls__( 'July' );
        $this->month['08'] =  yourls__( 'August' );
        $this->month['09'] =  yourls__( 'September' );
        $this->month['10'] =  yourls__( 'October' );
        $this->month['11'] =  yourls__( 'November' );
        $this->month['12'] =  yourls__( 'December' );



        $this->month_abbrev[ yourls__( 'January' ) ]   =  yourls__( 'Jan_January_abbreviation' );
        $this->month_abbrev[ yourls__( 'February' ) ]  =  yourls__( 'Feb_February_abbreviation' );
        $this->month_abbrev[ yourls__( 'March' ) ]     =  yourls__( 'Mar_March_abbreviation' );
        $this->month_abbrev[ yourls__( 'April' ) ]     =  yourls__( 'Apr_April_abbreviation' );
        $this->month_abbrev[ yourls__( 'May' ) ]       =  yourls__( 'May_May_abbreviation' );
        $this->month_abbrev[ yourls__( 'June' ) ]      =  yourls__( 'Jun_June_abbreviation' );
        $this->month_abbrev[ yourls__( 'July' ) ]      =  yourls__( 'Jul_July_abbreviation' );
        $this->month_abbrev[ yourls__( 'August' ) ]    =  yourls__( 'Aug_August_abbreviation' );
        $this->month_abbrev[ yourls__( 'September' ) ] =  yourls__( 'Sep_September_abbreviation' );
        $this->month_abbrev[ yourls__( 'October' ) ]   =  yourls__( 'Oct_October_abbreviation' );
        $this->month_abbrev[ yourls__( 'November' ) ]  =  yourls__( 'Nov_November_abbreviation' );
        $this->month_abbrev[ yourls__( 'December' ) ]  =  yourls__( 'Dec_December_abbreviation' );

        foreach ($this->month_abbrev as $month_ => $month_abbrev_) {
            $this->month_abbrev[$month_] = preg_replace('/_.+_abbreviation$/', '', $month_abbrev_);
        }


        $this->meridiem['am'] = yourls__( 'am' );
        $this->meridiem['pm'] = yourls__( 'pm' );
        $this->meridiem['AM'] = yourls__( 'AM' );
        $this->meridiem['PM'] = yourls__( 'PM' );





        $trans = yourls__( 'number_format_thousands_sep' );
        $this->number_format['thousands_sep'] = ('number_format_thousands_sep' == $trans) ? ',' : $trans;


        $trans = yourls__( 'number_format_decimal_point' );
        $this->number_format['decimal_point'] = ('number_format_decimal_point' == $trans) ? '.' : $trans;


        if ( isset( $GLOBALS['text_direction'] ) )
            $this->text_direction = $GLOBALS['text_direction'];

        elseif ( 'rtl' == yourls_x( 'ltr', 'text direction' ) )
            $this->text_direction = 'rtl';
    }














    function get_weekday( $weekday_number ) {
        return $this->weekday[ $weekday_number ];
    }















    function get_weekday_initial( $weekday_name ) {
        return $this->weekday_initial[ $weekday_name ];
    }













    function get_weekday_abbrev( $weekday_name ) {
        return $this->weekday_abbrev[ $weekday_name ];
    }


















    function get_month( $month_number ) {
        return $this->month[ sprintf( '%02s', $month_number ) ];
    }













    function get_month_abbrev( $month_name ) {
        return $this->month_abbrev[ $month_name ];
    }












    function get_meridiem( $meridiem ) {
        return $this->meridiem[ $meridiem ];
    }










    function register_globals() {
        $GLOBALS['weekday']         = $this->weekday;
        $GLOBALS['weekday_initial'] = $this->weekday_initial;
        $GLOBALS['weekday_abbrev']  = $this->weekday_abbrev;
        $GLOBALS['month']           = $this->month;
        $GLOBALS['month_abbrev']    = $this->month_abbrev;
    }






    function __construct() {
        $this->init();
        $this->register_globals();
    }







    function is_rtl() {
        return 'rtl' == $this->text_direction;
    }
}













function yourls_load_custom_textdomain( $domain, $path ) {
    $locale = yourls_apply_filter( 'load_custom_textdomain', yourls_get_locale(), $domain );
    if( !empty( $locale ) ) {
        $mofile = rtrim( $path, '/' ) . '/'. $domain . '-' . $locale . '.mo';
        return yourls_load_textdomain( $domain, $mofile );
    }
}







function yourls_is_rtl() {
    global $yourls_locale_formats;
    if( !isset( $yourls_locale_formats ) )
        $yourls_locale_formats = new YOURLS_Locale_Formats();

    return $yourls_locale_formats->is_rtl();
}











function yourls_l10n_weekday_abbrev( $weekday = '' ){
    global $yourls_locale_formats;
    if( !isset( $yourls_locale_formats ) )
        $yourls_locale_formats = new YOURLS_Locale_Formats();

    if( $weekday === '' )
        return $yourls_locale_formats->weekday_abbrev;

    if( is_int( $weekday ) ) {
        $day = $yourls_locale_formats->weekday[ $weekday ];
        return $yourls_locale_formats->weekday_abbrev[ $day ];
    } else {
        return $yourls_locale_formats->weekday_abbrev[ yourls__( $weekday ) ];
    }
}











function yourls_l10n_weekday_initial( $weekday = '' ){
    global $yourls_locale_formats;
    if( !isset( $yourls_locale_formats ) )
        $yourls_locale_formats = new YOURLS_Locale_Formats();

    if( $weekday === '' )
        return $yourls_locale_formats->weekday_initial;

    if( is_int( $weekday ) ) {
        $weekday = $yourls_locale_formats->weekday[ $weekday ];
        return $yourls_locale_formats->weekday_initial[ $weekday ];
    } else {
        return $yourls_locale_formats->weekday_initial[ yourls__( $weekday ) ];
    }
}











function yourls_l10n_month_abbrev( $month = '' ){
    global $yourls_locale_formats;
    if( !isset( $yourls_locale_formats ) )
        $yourls_locale_formats = new YOURLS_Locale_Formats();

    if( $month === '' )
        return $yourls_locale_formats->month_abbrev;

    if( intval( $month ) > 0 ) {
        $month = sprintf('%02d', intval( $month ) );
        $month = $yourls_locale_formats->month[ $month ];
        return $yourls_locale_formats->month_abbrev[ $month ];
    } else {
        return $yourls_locale_formats->month_abbrev[ yourls__( $month ) ];
    }
}







function yourls_l10n_months(){
    global $yourls_locale_formats;
    if( !isset( $yourls_locale_formats ) )
        $yourls_locale_formats = new YOURLS_Locale_Formats();

    return $yourls_locale_formats->month;
}
