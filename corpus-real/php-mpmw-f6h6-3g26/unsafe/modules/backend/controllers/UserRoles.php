<?php

namespace Backend\Controllers;

use Backend\Classes\Controller;
use Backend\Facades\BackendMenu;
use System\Classes\SettingsManager;








class UserRoles extends Controller
{



    public $implement = [
        \Backend\Behaviors\FormController::class,
        \Backend\Behaviors\ListController::class,
        \Backend\Behaviors\RelationController::class,
    ];




    public $requiredPermissions = ['backend.manage_users'];




    public function __construct()
    {
        parent::__construct();

        BackendMenu::setContext('Winter.System', 'system', 'users');
        SettingsManager::setContext('Winter.System', 'administrators');




        $this->bindEvent('page.beforeDisplay', function () {
            if (!$this->user->isSuperUser()) {
                abort(403);
            }
        });
    }
}
