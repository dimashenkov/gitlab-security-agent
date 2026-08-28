<?php namespace Backend\Controllers;

use BackendMenu;
use Backend\Classes\Controller;
use System\Classes\SettingsManager;








class UserGroups extends Controller
{



    public $implement = [
        \Backend\Behaviors\FormController::class,
        \Backend\Behaviors\ListController::class,
    ];




    public $requiredPermissions = ['backend.manage_users'];




    public function __construct()
    {
        parent::__construct();

        BackendMenu::setContext('Winter.System', 'system', 'users');
        SettingsManager::setContext('Winter.System', 'administrators');
    }
}
