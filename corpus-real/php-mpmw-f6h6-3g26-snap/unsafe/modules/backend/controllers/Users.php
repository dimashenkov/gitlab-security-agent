<?php

namespace Backend\Controllers;

use Backend\Behaviors\FormController;
use Backend\Behaviors\ListController;
use Backend\Behaviors\RelationController;
use Backend\Classes\Controller;
use Backend\Facades\Backend;
use Backend\Facades\BackendAuth;
use Backend\Facades\BackendMenu;
use Backend\Models\UserGroup;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Str;
use System\Classes\SettingsManager;
use Winter\Storm\Support\Facades\Flash;
use Winter\Storm\Support\Facades\Mail;








class Users extends Controller
{



    public $implement = [
        FormController::class,
        ListController::class,
        RelationController::class,
    ];




    public $requiredPermissions = ['backend.manage_users'];




    public $bodyClass = 'compact-container';

    public $formLayout = 'sidebar';




    public function __construct()
    {
        parent::__construct();

        BackendMenu::setContext('Winter.System', 'system', 'users');
        SettingsManager::setContext('Winter.System', 'administrators');
    }




    public function listExtendQuery($query)
    {
        if (!$this->user->isSuperUser()) {
            $query->where('is_superuser', false);
        }
    }




    public function listFilterExtendScopes($filterWidget)
    {
        if (!$this->user->isSuperUser()) {
            $filterWidget->removeScope('is_superuser');
        }
    }




    public function listInjectRowClass($record, $definition = null)
    {
        if ($record->trashed()) {
            return 'strike';
        }
    }




    public function formExtendQuery($query)
    {
        if (!$this->user->isSuperUser()) {
            $query->where('is_superuser', false);
        }


        $query->withTrashed();
    }




    public function formBeforeCreate($model)
    {
        if (post('User._auto_generate_password')) {
            $password = Str::random(22);
            $model->password = $password;
            $model->password_confirmation = $password;
        }
    }




    public function update($recordId, $context = null)
    {

        if ($context != 'myaccount' && $recordId == $this->user->id) {
            return Backend::redirect('backend/myaccount');
        }

        return $this->asExtension('FormController')->update($recordId, $context);
    }




    public function update_onRestore($recordId)
    {
        $this->formFindModelObject($recordId)->restore();

        Flash::success(Lang::get('backend::lang.form.restore_success', ['name' => Lang::get('backend::lang.user.name')]));

        return Redirect::refresh();
    }




    public function update_onImpersonateUser($recordId)
    {
        if (!$this->user->hasAccess('backend.impersonate_users')) {
            return Response::make(Lang::get('backend::lang.page.access_denied.label'), 403);
        }

        $model = $this->formFindModelObject($recordId);

        BackendAuth::impersonate($model);

        Flash::success(Lang::get('backend::lang.account.impersonate_success'));

        return Backend::redirect('backend/myaccount');
    }




    public function update_onUnsuspendUser($recordId)
    {
        $model = $this->formFindModelObject($recordId);

        $model->unsuspend();

        Flash::success(Lang::get('backend::lang.account.unsuspend_success'));

        return Redirect::refresh();
    }




    public function myaccount()
    {
        return Backend::redirect('backend/myaccount');
    }





    public function formExtendFields($form)
    {
        if ($form->getContext() == 'myaccount') {
            return;
        }

        if (!$this->user->isSuperUser()) {
            $form->removeField('is_superuser');
        }




        $form->addTabFields($this->generatePermissionsField());




        if (!$form->model->exists) {
            $defaultGroupIds = UserGroup::where('is_new_user_default', true)->lists('id');

            $groupField = $form->getField('groups');
            if ($groupField) {
                $groupField->value = $defaultGroupIds;
            }
        }
    }





    protected function generatePermissionsField()
    {
        return [
            'permissions' => [
                'tab' => 'backend::lang.user.permissions',
                'type' => 'Backend\FormWidgets\PermissionEditor',
                'trigger' => [
                    'action' => 'disable',
                    'field' => 'is_superuser',
                    'condition' => 'checked'
                ]
            ]
        ];
    }




    public function update_onManualPasswordReset($recordId)
    {
        $user = $this->formFindModelObject($recordId);

        if ($user) {
            $code = $user->getResetPasswordCode();
            $link = Backend::url('backend/auth/reset/' . $user->id . '/' . $code);

            $data = [
                'name' => $user->full_name,
                'link' => $link,
            ];

            Mail::send('backend::mail.restore', $data, function ($message) use ($user) {
                $message->to($user->email, $user->full_name)->subject(trans('backend::lang.account.password_reset'));
            });
        }

        Flash::success(Lang::get('backend::lang.account.manual_password_reset_success'));

        return Redirect::refresh();
    }
}
