<?php

namespace Backend\Controllers;

use Backend\Behaviors\FormController;
use Backend\Classes\Controller;
use Backend\Facades\BackendAuth;
use Backend\Facades\BackendMenu;
use System\Classes\SettingsManager;











class MyAccount extends Controller
{



    public $implement = [
        FormController::class,
    ];





    public $requiredPermissions = [];




    public $bodyClass = 'compact-container';

    public $formLayout = 'sidebar';




    public function __construct()
    {
        parent::__construct();

        BackendMenu::setContext('Winter.System', 'system', 'users');
        SettingsManager::setContext('Winter.Backend', 'myaccount');
    }




    public function index()
    {
        $this->pageTitle = 'backend::lang.myaccount.menu_label';
        return $this->asExtension('FormController')->update($this->user->id, 'myaccount');
    }




    public function index_onSave()
    {
        $result = $this->asExtension('FormController')->update_onSave($this->user->id, 'myaccount');




        $loginChanged = $this->user->login != post('User[login]');
        $passwordChanged = strlen(post('User[password]'));
        if ($loginChanged || $passwordChanged) {
            BackendAuth::login($this->user->reload(), true);
        }

        return $result;
    }
}
