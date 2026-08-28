<?php namespace Backend\Controllers;

use Backend;
use BackendMenu;
use Backend\Classes\Controller;
use System\Classes\SettingsManager;







class AccessLogs extends Controller
{



    public $implement = [
        \Backend\Behaviors\ListController::class,
    ];




    public $requiredPermissions = ['system.access_logs'];




    public function __construct()
    {
        parent::__construct();

        BackendMenu::setContext('Winter.System', 'system', 'settings');
        SettingsManager::setContext('Winter.Backend', 'access_logs');
    }

    public function index_onRefresh()
    {
        return $this->listRefresh();
    }
}
