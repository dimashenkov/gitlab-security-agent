<?php


























































if ( !isset( $yourls_filters ) ) {
    $yourls_filters = [];
}







if ( !isset( $yourls_actions ) ) {
    $yourls_actions = [];
}



















function yourls_add_filter( $hook, $function_name, $priority = 10, $accepted_args = NULL, $type = 'filter' ) {
    global $yourls_filters;

    $id = yourls_filter_unique_id($function_name);

    $yourls_filters[ $hook ][ $priority ][ $id ] = [
        'function'      => $function_name,
        'accepted_args' => $accepted_args,
        'type'          => $type,
    ];
}





















function yourls_add_action( $hook, $function_name, $priority = 10, $accepted_args = 1 ) {
    yourls_add_filter( $hook, $function_name, $priority, $accepted_args, 'action' );
}






















function yourls_filter_unique_id($function) {

    if ( is_string( $function ) ) {
        return $function;
    }

    if ( is_object( $function ) ) {

        $function = [ $function, '' ];
    }
    else {
        $function = (array)$function;
    }


    if ( is_object( $function[0] ) ) {
        return spl_object_hash( $function[0] ).$function[1];
    }


    return $function[0].'::'.$function[1];
}





















function yourls_apply_filter( $hook, $value = '', $is_action = false ) {
    global $yourls_filters;

    $args = func_get_args();


    if ( !$is_action && isset($yourls_filters['all']) ) {
        yourls_call_all_hooks('filter', $hook, $args);
    }


    if ( !isset( $yourls_filters[ $hook ] ) ) {
        return $value;
    }


    ksort( $yourls_filters[ $hook ] );


    reset( $yourls_filters[ $hook ] );
    do {
        foreach ( (array)current( $yourls_filters[ $hook ] ) as $the_ ) {
            $_value = '';
            if ( !is_null($the_[ 'function' ]) ) {
                $args[ 1 ] = $value;
                $count = $the_[ 'accepted_args' ];
                if ( is_null( $count ) ) {
                    $_value = call_user_func_array( $the_[ 'function' ], array_slice( $args, 1 ) );
                }
                else {
                    $_value = call_user_func_array( $the_[ 'function' ], array_slice( $args, 1, (int)$count ) );
                }
            }
            if ( $the_[ 'type' ] == 'filter' ) {
                $value = $_value;
            }
        }
    } while ( next( $yourls_filters[ $hook ] ) !== false );


    return $value;
}








function yourls_do_action( $hook, $arg = '' ) {
    global $yourls_actions, $yourls_filters;


    if ( !isset( $yourls_actions ) ) {
        $yourls_actions = [];
    }
    if ( !isset( $yourls_actions[ $hook ] ) ) {
        $yourls_actions[ $hook ] = 1;
    }
    else {
        ++$yourls_actions[ $hook ];
    }

    $args = [];
    if ( is_array( $arg ) && 1 == count( $arg ) && isset( $arg[ 0 ] ) && is_object( $arg[ 0 ] ) ) {
        $args[] =& $arg[ 0 ];
    }
    else {
        $args[] = $arg;
    }

    for ( $a = 2 ; $a < func_num_args() ; $a++ ) {
        $args[] = func_get_arg( $a );
    }


    if ( isset($yourls_filters['all']) ) {
        yourls_call_all_hooks('action', $hook, $args);
    }

    yourls_apply_filter( $hook, $args, true );
}







function yourls_did_action( $hook ) {
    global $yourls_actions;
    return empty( $yourls_actions[ $hook ] ) ? 0 : $yourls_actions[ $hook ];
}
















function yourls_call_all_hooks($type, $hook, ...$args) {
    global $yourls_filters;


    reset( $yourls_filters['all'] );
    do {
        foreach ( (array) current($yourls_filters['all']) as $the_ )

            if ( $the_['type'] == $type && !is_null($the_['function']) ) {
                call_user_func_array( $the_['function'], array($type, $hook, $args) );





            }

    } while ( next($yourls_filters['all']) !== false );

}
















function yourls_remove_filter( $hook, $function_to_remove, $priority = 10 ) {
    global $yourls_filters;

    $function_to_remove = yourls_filter_unique_id($function_to_remove);

    $remove = isset( $yourls_filters[ $hook ][ $priority ][ $function_to_remove ] );

    if ( $remove === true ) {
        unset ( $yourls_filters[ $hook ][ $priority ][ $function_to_remove ] );
        if ( empty( $yourls_filters[ $hook ][ $priority ] ) ) {
            unset( $yourls_filters[ $hook ] );
        }
    }
    return $remove;
}











function yourls_remove_action( $hook, $function_to_remove, $priority = 10 ) {
    return yourls_remove_filter( $hook, $function_to_remove, $priority );
}










function yourls_remove_all_actions( $hook, $priority = false ) {
    return yourls_remove_all_filters( $hook, $priority );
}









function yourls_remove_all_filters( $hook, $priority = false ) {
    global $yourls_filters;

    if ( isset( $yourls_filters[ $hook ] ) ) {
        if ( $priority === false ) {
            unset( $yourls_filters[ $hook ] );
        }
        elseif ( isset( $yourls_filters[ $hook ][ $priority ] ) ) {
            unset( $yourls_filters[ $hook ][ $priority ] );
        }
    }

    return true;
}











function yourls_get_filters($hook) {
    global $yourls_filters;
    return $yourls_filters[$hook] ?? array();
}








function yourls_get_actions($hook) {
    return yourls_get_filters($hook);
}








function yourls_has_filter( $hook, $function_to_check = false ) {
    global $yourls_filters;

    $has = !empty( $yourls_filters[ $hook ] );
    if ( false === $function_to_check || false === $has ) {
        return $has;
    }

    if ( !$idx = yourls_filter_unique_id($function_to_check) ) {
        return false;
    }

    foreach ( array_keys( $yourls_filters[ $hook ] ) as $priority ) {
        if ( isset( $yourls_filters[ $hook ][ $priority ][ $idx ] ) ) {
            return $priority;
        }
    }
    return false;
}










function yourls_has_action( $hook, $function_to_check = false ) {
    return yourls_has_filter( $hook, $function_to_check );
}






function yourls_has_active_plugins() {
    return count( yourls_get_db('read-has_active_plugins')->get_plugins() );
}






function yourls_get_plugins() {
    $plugins = (array)glob( YOURLS_PLUGINDIR.'/*/plugin.php' );

    if ( is_array( $plugins ) ) {
        foreach ( $plugins as $key => $plugin ) {
            $plugins[ yourls_plugin_basename( $plugin ) ] = yourls_get_plugin_data( $plugin );
            unset( $plugins[ $key ] );
        }
    }

    return empty( $plugins ) ? [] : $plugins;
}







function yourls_is_active_plugin( $plugin ) {
    return yourls_has_active_plugins() > 0 ?
        in_array( yourls_plugin_basename( $plugin ), yourls_get_db('read-is_active_plugin')->get_plugins() )
        : false;
}




























function yourls_get_plugin_data( $file ) {
    $fp = fopen( $file, 'r' );
    $data = fread( $fp, 8192 );
    fclose( $fp );


    if ( !preg_match( '!.*?/\*(.*?)\*/!ms', $data, $matches ) ) {
        return [];
    }


    unset( $data );
    $lines = preg_split( "[\n|\r]", $matches[ 1 ] );
    unset( $matches );

    $plugin_data = [];
    foreach ( $lines as $line ) {
        if ( !preg_match( '!(\s*)?\*?(\s*)?(.*?):\s+(.*)!', $line, $matches ) ) {
            continue;
        }

        $plugin_data[ trim($matches[3]) ] = yourls_esc_html(trim($matches[4]));
    }

    return $plugin_data;
}












function yourls_load_plugins() {

    if ( yourls_is_installing() OR yourls_is_upgrading() OR !yourls_is_installed() ) {
        return [
            'loaded' => false,
            'info'   => 'install/upgrade'
        ];
    }

    $active_plugins = (array)yourls_get_option( 'active_plugins' );
    if ( empty( $active_plugins ) ) {
        return [
            'loaded' => false,
            'info'   => 'no active plugin'
        ];
    }

    $plugins = [];
    foreach ( $active_plugins as $key => $plugin ) {
        $file = YOURLS_PLUGINDIR . '/' . $plugin;
        if ( yourls_is_a_plugin_file($file) && yourls_include_file_sandbox( $file ) === true ) {
            $plugins[] = $plugin;
            unset( $active_plugins[ $key ] );
        }
    }


    yourls_get_db('read-load_plugins')->set_plugins( $plugins );
    $info = count( $plugins ).' activated';


    $missing_count = count( $active_plugins );
    if ( $missing_count > 0 ) {
        yourls_update_option( 'active_plugins', $plugins );
        $message = yourls_n( 'Could not find and deactivate plugin :', 'Could not find and deactivate plugins :', $missing_count );
        $missing = '<strong>'.implode( '</strong>, <strong>', $active_plugins ).'</strong>';
        yourls_add_notice( $message.' '.$missing );
        $info .= ', '.$missing_count.' removed';
    }

    return [
        'loaded' => true,
        'info'   => $info
    ];
}










function yourls_is_a_plugin_file($file) {
    return false === strpos( $file, '..' )
           && false === strpos( $file, './' )
           && 'plugin.php' === substr( $file, -10 )
           && is_readable( $file );
}








function yourls_activate_plugin( $plugin ) {

    $plugin = yourls_plugin_basename( $plugin );
    $plugindir = yourls_sanitize_filename( YOURLS_PLUGINDIR );
    if ( !yourls_is_a_plugin_file($plugindir . '/' . $plugin ) ) {
        return yourls__( 'Not a valid plugin file' );
    }


    $ydb = yourls_get_db('read-activate_plugin');
    if ( yourls_is_active_plugin( $plugin ) ) {
        return yourls__( 'Plugin already activated' );
    }


    $attempt = yourls_include_file_sandbox( $plugindir.'/'.$plugin );
    if( $attempt !== true ) {
        return yourls_s( 'Plugin generated unexpected output. Error was: <br/><pre>%s</pre>', $attempt );
    }


    $ydb->add_plugin( $plugin );
    yourls_update_option( 'active_plugins', $ydb->get_plugins() );
    yourls_do_action( 'activated_plugin', $plugin );
    yourls_do_action( 'activated_'.$plugin );

    return true;
}








function yourls_deactivate_plugin( $plugin ) {
    $plugin = yourls_plugin_basename( $plugin );


    if ( !yourls_is_active_plugin( $plugin ) ) {
        return yourls__( 'Plugin not active' );
    }


    $uninst_file = YOURLS_PLUGINDIR . '/' . dirname($plugin) . '/uninstall.php';
    $attempt = yourls_include_file_sandbox( $uninst_file );


    if ( is_string( $attempt ) ) {
        $message = yourls_s( 'Loading %s generated unexpected output. Error was: <br/><pre>%s</pre>', $uninst_file, $attempt );
        return( $message );
    }

    if ( $attempt === true ) {
        define('YOURLS_UNINSTALL_PLUGIN', true);
    }


    $ydb = yourls_get_db('read-deactivate_plugin');
    $plugins = $ydb->get_plugins();
    $key = array_search( $plugin, $plugins );
    if ( $key !== false ) {
        array_splice( $plugins, $key, 1 );
    }

    $ydb->set_plugins( $plugins );
    yourls_update_option( 'active_plugins', $plugins );
    yourls_do_action( 'deactivated_plugin', $plugin );
    yourls_do_action( 'deactivated_'.$plugin );

    return true;
}








function yourls_plugin_basename( $file ) {
    return trim( str_replace( yourls_sanitize_filename( YOURLS_PLUGINDIR ), '', yourls_sanitize_filename( $file ) ), '/' );
}








function yourls_plugin_url( $file ) {
    $url = YOURLS_PLUGINURL.'/'.yourls_plugin_basename( $file );
    if ( yourls_is_ssl() or yourls_needs_ssl() ) {
        $url = str_replace( 'http://', 'https://', $url );
    }
    return (string)yourls_apply_filter( 'plugin_url', $url, $file );
}







function yourls_list_plugin_admin_pages() {
    $plugin_links = [];
    foreach ( yourls_get_db('read-list_plugin_admin_pages')->get_plugin_pages() as $plugin => $page ) {
        $plugin_links[ $plugin ] = [
            'url'    => yourls_admin_url( 'plugins.php?page='.$page[ 'slug' ] ),
            'anchor' => $page[ 'title' ],
        ];
    }
    return $plugin_links;
}










function yourls_register_plugin_page( $slug, $title, $function ) {
    yourls_get_db('read-register_plugin_page')->add_plugin_page( $slug, $title, $function );
}








function yourls_plugin_admin_page( $plugin_page ) {

    $pages = yourls_get_db('read-plugin_admin_page')->get_plugin_pages();
    if ( !isset( $pages[ $plugin_page ] ) ) {
        yourls_die( yourls__( 'This page does not exist. Maybe a plugin you thought was activated is inactive?' ), yourls__( 'Invalid link' ) );
    }


    $page_function = $pages[ $plugin_page ][ 'function' ];
    if (!is_callable($page_function)) {
        yourls_die( yourls__( 'This page cannot be displayed because the displaying function is not callable.' ), yourls__( 'Invalid code' ) );
    }


    yourls_do_action( 'load-'.$plugin_page );
    yourls_html_head( 'plugin_page_'.$plugin_page, $pages[ $plugin_page ][ 'title' ] );
    yourls_html_logo();
    yourls_html_menu();

    $page_function( );

    yourls_html_footer();
}












function yourls_plugins_sort_callback( $plugin_a, $plugin_b ) {
    $orderby = yourls_apply_filter( 'plugins_sort_callback', 'Plugin Name' );
    $order = yourls_apply_filter( 'plugins_sort_callback', 'ASC' );

    $a = isset( $plugin_a[ $orderby ] ) ? $plugin_a[ $orderby ] : '';
    $b = isset( $plugin_b[ $orderby ] ) ? $plugin_b[ $orderby ] : '';

    if ( $a == $b ) {
        return 0;
    }

    if ( 'DESC' == $order ) {
        return ( $a < $b ) ? 1 : -1;
    }
    else {
        return ( $a < $b ) ? -1 : 1;
    }
}


















function yourls_shutdown() {
    yourls_do_action( 'shutdown' );
}









function yourls_return_true() {
    return true;
}









function yourls_return_false() {
    return false;
}









function yourls_return_zero() {
    return 0;
}









function yourls_return_empty_array() {
    return [];
}









function yourls_return_null() {
    return null;
}









function yourls_return_empty_string() {
    return '';
}








function yourls_shunt_default() {
    return '__yourls_shunt__';
}
