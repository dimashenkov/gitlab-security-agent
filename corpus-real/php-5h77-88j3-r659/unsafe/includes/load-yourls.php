<?php






require __DIR__ . '/vendor/autoload.php';



$config = new \YOURLS\Config\Config;




if (!defined('YOURLS_CONFIGFILE')) {
    try {
        define('YOURLS_CONFIGFILE', $config->find_config());
    } catch (\YOURLS\Exceptions\ConfigException $e) {
        die($e->getMessage());
    }
}

require_once YOURLS_CONFIGFILE;
try {
    $config->define_core_constants();
} catch (\YOURLS\Exceptions\ConfigException $e) {
    die($e->getMessage());
}



$init_defaults = new \YOURLS\Config\InitDefaults;
new \YOURLS\Config\Init($init_defaults);
