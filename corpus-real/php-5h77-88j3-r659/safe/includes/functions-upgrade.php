<?php















function yourls_upgrade($step, $oldver, $newver, $oldsql, $newsql ) {








    $step   = intval($step);
    $oldsql = intval($oldsql);
    $newsql = intval($newsql);
    $oldver = yourls_sanitize_version($oldver);
    $newver = yourls_sanitize_version($newver);

    yourls_maintenance_mode(true);


    if( $oldsql == 100 ) {
        yourls_upgrade_to_14( $step );
    }


    switch( $step ) {

    case 1:
    case 2:
        if( $oldsql < 210 )
            yourls_upgrade_to_141();

        if( $oldsql < 220 )
            yourls_upgrade_to_143();

        if( $oldsql < 250 )
            yourls_upgrade_to_15();

        if( $oldsql < 482 )
            yourls_upgrade_482();

        if( $oldsql < 506 ) {







            if( $oldsql == 505 ) {
                yourls_upgrade_505_to_506();
            } else {
                yourls_upgrade_to_506();
            }
        }

        if( $oldsql < 507 ) {
            yourls_upgrade_to_507();
        }

        yourls_redirect_javascript( yourls_admin_url( "upgrade.php?step=3" ) );

        break;

    case 3:

        yourls_update_option( 'version', YOURLS_VERSION );
        yourls_update_option( 'db_version', YOURLS_DB_VERSION );
        yourls_maintenance_mode(false);
        break;
    }
}







function yourls_upgrade_to_507() {
    echo "<p>Adding index for url column. Please wait...</p>";

    $table = YOURLS_DB_TABLE_URL;

    $query = sprintf("ALTER TABLE `%s` ADD INDEX `url_idx` (`url`(50));", $table);

    try {
        yourls_get_db('write-upgrade_to_507')->perform($query);
    } catch (\Exception $e) {
        echo "<p class='error'>Unable to update the DB.</p>";
        echo "<p>Could not index urls. You will have to fix things manually :(. The error was
        <pre>";
        echo $e->getMessage();
        echo "\n</pre>";
        die();
    }

    echo "<p class='success'>OK!</p>";
}





function yourls_upgrade_505_to_506() {
    echo "<p>Updating DB. Please wait...</p>";

    $query = sprintf('ALTER TABLE `%s` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;', YOURLS_DB_TABLE_URL);

    try {
        yourls_get_db('write-upgrade_505_to_506')->perform($query);
    } catch (\Exception $e) {
        echo "<p class='error'>Unable to update the DB.</p>";
        echo "<p>Could not change collation. You will have to fix things manually :(. The error was
        <pre>";
        echo $e->getMessage();
        echo "\n</pre>";
        die();
    }

    echo "<p class='success'>OK!</p>";
}





function yourls_upgrade_to_506() {
    $ydb = yourls_get_db('write-upgrade_to_506');
    $error_msg = [];

    echo "<p>Updating DB. Please wait...</p>";

    $queries = array(
        'database charset'     => sprintf('ALTER DATABASE `%s` CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci;', YOURLS_DB_NAME),
        'options charset'      => sprintf('ALTER TABLE `%s` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;', YOURLS_DB_TABLE_OPTIONS),
        'short URL varchar'    => sprintf("ALTER TABLE `%s` CHANGE `keyword` `keyword` VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '';", YOURLS_DB_TABLE_URL),
        'short URL type url'   => sprintf("ALTER TABLE `%s` CHANGE `url` `url` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;", YOURLS_DB_TABLE_URL),
        'short URL type title' => sprintf("ALTER TABLE `%s` CHANGE `title` `title` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", YOURLS_DB_TABLE_URL),
        'short URL charset'    => sprintf('ALTER TABLE `%s` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;', YOURLS_DB_TABLE_URL),
    );

    foreach($queries as $what => $query) {
        try {
            $ydb->perform($query);
        } catch (\Exception $e) {
            $error_msg[] = $e->getMessage();
        }
    }

    if( $error_msg ) {
        echo "<p class='error'>Unable to update the DB.</p>";
        echo "<p>You will have to manually fix things, sorry for the inconvenience :(</p>";
        echo "<p>The errors were:
        <pre>";
        foreach( $error_msg as $error ) {
            echo "$error\n";
        }
        echo "</pre>";
        die();
    }

    echo "<p class='success'>OK!</p>";
}







function yourls_upgrade_482() {

    $table_url = YOURLS_DB_TABLE_URL;
    $sql = "ALTER TABLE `$table_url` CHANGE `title` `title` TEXT CHARACTER SET utf8;";
    yourls_get_db('write-upgrade_482')->perform( $sql );
    echo "<p>Updating table structure. Please wait...</p>";
}







function yourls_upgrade_to_15( ) {

    if( yourls_get_option( 'active_plugins' ) === false )
        yourls_add_option( 'active_plugins', array() );
    echo "<p>Enabling the plugin API. Please wait...</p>";


    $table_url = YOURLS_DB_TABLE_URL;
    $sql = "ALTER TABLE `$table_url` ADD `title` TEXT AFTER `url`;";
    yourls_get_db('write-upgrade_to_15')->perform( $sql );
    echo "<p>Updating table structure. Please wait...</p>";


    yourls_create_htaccess();
    echo "<p>Updating .htaccess file. Please wait...</p>";
}







function yourls_upgrade_to_143( ) {

    $ydb = yourls_get_db('write-upgrade_to_143');
    $table_log = YOURLS_DB_TABLE_LOG;
    $sql = "SHOW COLUMNS FROM `$table_log`";
    $cols = $ydb->fetchObjects( $sql );
    if ( $cols[2]->Field == 'keyword' ) {
        $sql = "ALTER TABLE `$table_log` CHANGE `keyword` `shorturl` VARCHAR( 200 ) BINARY;";
        $ydb->query( $sql );
    }
    echo "<p>Structure of existing tables updated. Please wait...</p>";
}







function yourls_upgrade_to_141( ) {

    setcookie('yourls_username', '', time() - 3600 );
    setcookie('yourls_password', '', time() - 3600 );

    yourls_alter_url_table_to_141();

    yourls_create_htaccess();
}





function yourls_alter_url_table_to_141() {
    $table_url = YOURLS_DB_TABLE_URL;
    $alter = "ALTER TABLE `$table_url` CHANGE `keyword` `keyword` VARCHAR( 200 ) BINARY, CHANGE `url` `url` TEXT BINARY ";
    yourls_get_db('write-alter_url_table_to_141')->perform( $alter );
    echo "<p>Structure of existing tables updated. Please wait...</p>";
}








function yourls_upgrade_to_14( $step ) {

    switch( $step ) {
    case 1:



        yourls_create_tables_for_14();
        yourls_alter_url_table_to_14();
        $clean = yourls_clean_htaccess_for_14();
        $create = yourls_create_htaccess();
        if ( !$create )
            echo "<p class='warning'>Please create your <tt>.htaccess</tt> file (I could not do it for you). Please refer to <a href='http://yourls.org/htaccess'>http://yourls.org/htaccess</a>.";
        yourls_redirect_javascript( yourls_admin_url( "upgrade.php?step=2&oldver=1.3&newver=1.4&oldsql=100&newsql=200" ), $create );
        break;

    case 2:

        yourls_update_table_to_14();
        break;

    case 3:

        yourls_alter_url_table_to_14_part_two();


        yourls_update_options_to_14();

        yourls_redirect_javascript( yourls_admin_url( "upgrade.php?step=1&oldver=1.4&newver=1.4.1&oldsql=200&newsql=210" ) );
        break;
    }
}





function yourls_update_options_to_14() {
    yourls_update_option( 'version', '1.4' );
    yourls_update_option( 'db_version', '200' );

    if( defined('YOURLS_DB_TABLE_NEXTDEC') ) {
        $table = YOURLS_DB_TABLE_NEXTDEC;
        $next_id = yourls_get_db('read-update_options_to_14')->fetchValue("SELECT `next_id` FROM `$table`");
        yourls_update_option( 'next_id', $next_id );
        yourls_get_db('write-update_options_to_14')->perform( "DROP TABLE `$table`" );
    } else {
        yourls_update_option( 'next_id', 1 );
    }
}





function yourls_create_tables_for_14() {
    $ydb = yourls_get_db('write-create_tables_for_14');

    $queries = array();

    $queries[YOURLS_DB_TABLE_OPTIONS] =
        'CREATE TABLE IF NOT EXISTS `'.YOURLS_DB_TABLE_OPTIONS.'` ('.
        '`option_id` int(11) unsigned NOT NULL auto_increment,'.
        '`option_name` varchar(64) NOT NULL default "",'.
        '`option_value` longtext NOT NULL,'.
        'PRIMARY KEY (`option_id`,`option_name`),'.
        'KEY `option_name` (`option_name`)'.
        ');';

    $queries[YOURLS_DB_TABLE_LOG] =
        'CREATE TABLE IF NOT EXISTS `'.YOURLS_DB_TABLE_LOG.'` ('.
        '`click_id` int(11) NOT NULL auto_increment,'.
        '`click_time` datetime NOT NULL,'.
        '`shorturl` varchar(200) NOT NULL,'.
        '`referrer` varchar(200) NOT NULL,'.
        '`user_agent` varchar(255) NOT NULL,'.
        '`ip_address` varchar(41) NOT NULL,'.
        '`country_code` char(2) NOT NULL,'.
        'PRIMARY KEY (`click_id`),'.
        'KEY `shorturl` (`shorturl`)'.
        ');';

    foreach( $queries as $query ) {
        $ydb->perform( $query );
    }

    echo "<p>New tables created. Please wait...</p>";

}





function yourls_alter_url_table_to_14() {
    $ydb = yourls_get_db('write-alter_url_table_to_14');
    $table = YOURLS_DB_TABLE_URL;

    $alters = array();
    $results = array();
    $alters[] = "ALTER TABLE `$table` CHANGE `id` `keyword` VARCHAR( 200 ) NOT NULL";
    $alters[] = "ALTER TABLE `$table` CHANGE `url` `url` TEXT NOT NULL";
    $alters[] = "ALTER TABLE `$table` DROP PRIMARY KEY";

    foreach ( $alters as $query ) {
        $ydb->perform( $query );
    }

    echo "<p>Structure of existing tables updated. Please wait...</p>";
}





function yourls_alter_url_table_to_14_part_two() {
    $ydb = yourls_get_db('write-alter_url_table_to_14_part_two');
    $table = YOURLS_DB_TABLE_URL;

    $alters = array();
    $alters[] = "ALTER TABLE `$table` ADD PRIMARY KEY ( `keyword` )";
    $alters[] = "ALTER TABLE `$table` ADD INDEX ( `ip` )";
    $alters[] = "ALTER TABLE `$table` ADD INDEX ( `timestamp` )";

    foreach ( $alters as $query ) {
        $ydb->perform( $query );
    }

    echo "<p>New table index created</p>";
}





function yourls_update_table_to_14() {
    $ydb = yourls_get_db('write-update_table_to_14');
    $table = YOURLS_DB_TABLE_URL;


    $chunk = 45;
    $from = isset($_GET['from']) ? intval( $_GET['from'] ) : 0 ;
    $total = yourls_get_db_stats();
    $total = $total['total_links'];

    $sql = "SELECT `keyword`,`url` FROM `$table` WHERE 1=1 ORDER BY `url` ASC LIMIT $from, $chunk ;";

    $rows = $ydb->fetchObjects($sql);

    $count = 0;
    $queries = 0;
    foreach( $rows as $row ) {
        $keyword = $row->keyword;
        $url = $row->url;
        $newkeyword = yourls_int2string( $keyword );
        if( true === $ydb->perform("UPDATE `$table` SET `keyword` = '$newkeyword' WHERE `url` = '$url';") ) {
            $queries++;
        } else {
            echo "<p>Huho... Could not update rown with url='$url', from keyword '$keyword' to keyword '$newkeyword'</p>";
        }
        $count++;
    }


    $success = true;
    if( $count != $queries ) {
        $success = false;
        $num = $count - $queries;
        echo "<p>$num error(s) occurred while updating the URL table :(</p>";
    }

    if ( $count == $chunk ) {

        $from = $from + $chunk;
        $remain = $total - $from;
        echo "<p>Converted $chunk database rows ($remain remaining). Continuing... Please do not close this window until it's finished!</p>";
        yourls_redirect_javascript( yourls_admin_url( "upgrade.php?step=2&oldver=1.3&newver=1.4&oldsql=100&newsql=200&from=$from" ), $success );
    } else {

        echo '<p>All rows converted! Please wait...</p>';
        yourls_redirect_javascript( yourls_admin_url( "upgrade.php?step=3&oldver=1.3&newver=1.4&oldsql=100&newsql=200" ), $success );
    }

}





function yourls_clean_htaccess_for_14() {
    $filename = YOURLS_ABSPATH.'/.htaccess';

    $result = false;
    if( is_writeable( $filename ) ) {
        $contents = implode( '', file( $filename ) );

        $contents = preg_replace( '/# BEGIN ShortURL.*# END ShortURL/s', '', $contents );

        $find = 'RewriteRule .* - [E=REMOTE_USER:%{HTTP:Authorization},L]';
        $replace = "# You can safely remove this 5 lines block -- it's no longer used in YOURLS\n".
                "# $find";
        $contents = str_replace( $find, $replace, $contents );


        $f = fopen( $filename, 'w' );
        fwrite( $f, $contents );
        fclose( $f );

        $result = true;
    }

    return $result;
}
