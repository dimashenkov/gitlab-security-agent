<?php namespace Backend\Classes;

use Config;
use System\Classes\PluginManager;
use Winter\Storm\Auth\Manager as StormAuthManager;
use Winter\Storm\Exception\SystemException;







class AuthManager extends StormAuthManager
{
    protected static $instance;

    protected $sessionKey = 'admin_auth';

    protected $userModel = 'Backend\Models\User';

    protected $groupModel = 'Backend\Models\UserGroup';

    protected $throttleModel = 'Backend\Models\UserThrottle';

    protected $requireActivation = false;





    protected static $permissionDefaults = [
        'code'    => null,
        'label'   => null,
        'comment' => null,
        'roles'   => null,
        'order'   => 500
    ];




    protected $callbacks = [];




    protected $permissions = [];




    protected $aliases = [];




    protected $permissionRoles = false;




    protected $permissionCache = false;

    protected function init()
    {
        $this->useThrottle = Config::get('auth.throttle.enabled', true);
        parent::init();
    }













    public function registerCallback(callable $callback)
    {
        $this->callbacks[] = $callback;
    }













    public function registerPermissions($owner, array $definitions)
    {

        $owner = $this->aliases[$owner] ?? $owner;

        foreach ($definitions as $code => $definition) {
            $permission = (object) array_merge(self::$permissionDefaults, array_merge($definition, [
                'code' => $code,
                'owner' => $owner
            ]));

            $this->permissions[] = $permission;
        }


        $this->permissionCache = false;
    }








    public function registerPermissionOwnerAlias(string $owner, string $alias)
    {
        $this->aliases[$alias] = $owner;
    }







    public function removePermission($owner, $code)
    {
        if (!$this->permissions) {
            throw new SystemException('Unable to remove permissions before they are loaded.');
        }


        $owner = $this->aliases[$owner] ?? $owner;

        $ownerPermissions = array_filter($this->permissions, function ($permission) use ($owner) {
            return $permission->owner === $owner;
        });

        foreach ($ownerPermissions as $key => $permission) {
            if ($permission->code === $code) {
                unset($this->permissions[$key]);
            }
        }


        $this->permissionCache = false;
    }





    public function listPermissions()
    {
        if ($this->permissionCache !== false) {
            return $this->permissionCache;
        }




        foreach ($this->callbacks as $callback) {
            $callback($this);
        }




        $plugins = PluginManager::instance()->getPlugins();

        foreach ($plugins as $id => $plugin) {
            $items = $plugin->registerPermissions();
            if (!is_array($items)) {
                continue;
            }

            $this->registerPermissions($id, $items);
        }




        usort($this->permissions, function ($a, $b) {
            if ($a->order == $b->order) {
                return 0;
            }

            return $a->order > $b->order ? 1 : -1;
        });

        return $this->permissionCache = $this->permissions;
    }





    public function listTabbedPermissions()
    {
        $tabs = [];

        foreach ($this->listPermissions() as $permission) {
            $tab = $permission->tab ?? 'backend::lang.form.undefined_tab';

            if (!array_key_exists($tab, $tabs)) {
                $tabs[$tab] = [];
            }

            $tabs[$tab][] = $permission;
        }

        return $tabs;
    }




    protected function createUserModelQuery()
    {
        return parent::createUserModelQuery()->withTrashed();
    }





    protected function validateUserModel($user)
    {
        if ( ! $user instanceof $this->userModel) {
            return false;
        }




        if (array_key_exists('deleted_at', $user->getAttributes()) && $user->deleted_at !== null) {
            return false;
        }

        return $user;
    }







    public function listPermissionsForRole($role, $includeOrphans = true)
    {
        if ($this->permissionRoles === false) {
            $this->permissionRoles = [];

            foreach ($this->listPermissions() as $permission) {
                if ($permission->roles) {
                    foreach ((array) $permission->roles as $_role) {
                        $this->permissionRoles[$_role][$permission->code] = 1;
                    }
                }
                else {
                    $this->permissionRoles['*'][$permission->code] = 1;
                }
            }
        }

        $result = $this->permissionRoles[$role] ?? [];

        if ($includeOrphans) {
            $result += $this->permissionRoles['*'] ?? [];
        }

        return $result;
    }

    public function hasPermissionsForRole($role)
    {
        return !!$this->listPermissionsForRole($role, false);
    }
}
