<?php namespace Backend\Classes;

use Event;
use BackendAuth;
use System\Classes\PluginManager;
use Validator;
use SystemException;
use Log;
use Config;







class NavigationManager
{
    use \Winter\Storm\Support\Traits\Singleton;
    use \System\Traits\LazyOwnerAlias;




    protected $callbacks = [];




    protected $aliases = [];




    protected $items;




    protected $quickActions;

    protected $contextSidenavPartials = [];

    protected $contextOwner;
    protected $contextMainMenuItemCode;
    protected $contextSideMenuItemCode;




    protected $pluginManager;




    protected function init()
    {
        foreach (static::$lazyAliases as $alias => $owner) {
            $this->registerOwnerAlias($owner, $alias);
        }
        $this->pluginManager = PluginManager::instance();
    }






    protected function loadItems()
    {
        $this->items = [];
        $this->quickActions = [];




        foreach ($this->callbacks as $callback) {
            $callback($this);
        }




        $plugins = $this->pluginManager->getPlugins();

        foreach ($plugins as $id => $plugin) {
            $items = $plugin->registerNavigation();
            $quickActions = $plugin->registerQuickActions();

            if (!is_array($items) && !is_array($quickActions)) {
                continue;
            }

            if (is_array($items)) {
                $this->registerMenuItems($id, $items);
            }
            if (is_array($quickActions)) {
                $this->registerQuickActions($id, $quickActions);
            }
        }














        Event::fire('backend.menu.extendItems', [$this]);




        $this->applyDefaultOrders($this->items);
        uasort($this->items, static function ($a, $b) {
            return $a->order - $b->order;
        });
        $this->applyDefaultOrders($this->quickActions);
        uasort($this->quickActions, static function ($a, $b) {
            return $a->order - $b->order;
        });




        $user = BackendAuth::getUser();
        $this->items = $this->filterItemPermissions($user, $this->items);
        $this->quickActions = $this->filterItemPermissions($user, $this->quickActions);

        foreach ($this->items as $item) {
            if (!$item->sideMenu || !count($item->sideMenu)) {
                continue;
            }

            $this->applyDefaultOrders($item->sideMenu);




            uasort($item->sideMenu, static function ($a, $b) {
                return $a->order - $b->order;
            });




            $item->sideMenu = $this->filterItemPermissions($user, $item->sideMenu);
        }
    }








    protected function applyDefaultOrders(array $items)
    {
        $orderCount = 0;
        foreach ($items as $item) {
            if ($item->order !== -1 && is_integer($item->order)) {
                continue;
            }
            $item->order = ($orderCount += 100);
        }
    }













    public function registerCallback(callable $callback)
    {
        $this->callbacks[] = $callback;
    }
































    public function registerMenuItems($owner, array $definitions)
    {
        $validator = Validator::make($definitions, [
            '*.label' => 'required',
            '*.icon' => 'required_without:*.iconSvg',
            '*.url' => 'required',
            '*.sideMenu.*.label' => 'nullable|required',
            '*.sideMenu.*.icon' => 'nullable|required_without:*.sideMenu.*.iconSvg',
            '*.sideMenu.*.url' => 'nullable|required',
        ]);

        if ($validator->fails()) {
            $errorMessage = 'Invalid menu item detected in ' . $owner . '. Contact the plugin author to fix (' . $validator->errors()->first() . ')';
            if (Config::get('app.debug', false)) {
                throw new SystemException($errorMessage);
            }

            Log::error($errorMessage);
        }

        $this->addMainMenuItems($owner, $definitions);
    }








    public function registerOwnerAlias(string $owner, string $alias)
    {
        $this->aliases[strtoupper($alias)] = strtoupper($owner);
    }






    public function addMainMenuItems($owner, array $definitions)
    {
        foreach ($definitions as $code => $definition) {
            $this->addMainMenuItem($owner, $code, $definition);
        }
    }







    public function addMainMenuItem($owner, $code, array $definition)
    {
        $itemKey = $this->makeItemKey($owner, $code);

        if (isset($this->items[$itemKey])) {
            $definition = array_merge((array) $this->items[$itemKey], $definition);
        }

        $item = array_merge($definition, [
            'code'  => $code,
            'owner' => $owner
        ]);

        $this->items[$itemKey] = MainMenuItem::createFromArray($item);

        if (array_key_exists('sideMenu', $item)) {
            $this->addSideMenuItems($owner, $code, $item['sideMenu']);
        }
    }







    public function getMainMenuItem(string $owner, string $code)
    {
        $itemKey = $this->makeItemKey($owner, $code);

        if (!array_key_exists($itemKey, $this->items)) {
            throw new SystemException('No main menu item found with key ' . $itemKey);
        }

        return $this->items[$itemKey];
    }






    public function removeMainMenuItem($owner, $code)
    {
        $itemKey = $this->makeItemKey($owner, $code);
        unset($this->items[$itemKey]);
    }







    public function addSideMenuItems($owner, $code, array $definitions)
    {
        foreach ($definitions as $sideCode => $definition) {
            $this->addSideMenuItem($owner, $code, $sideCode, (array) $definition);
        }
    }









    public function addSideMenuItem($owner, $code, $sideCode, array $definition)
    {
        $itemKey = $this->makeItemKey($owner, $code);

        if (!isset($this->items[$itemKey])) {
            return false;
        }

        $mainItem = $this->items[$itemKey];

        $definition = array_merge($definition, [
            'code'  => $sideCode,
            'owner' => $owner
        ]);

        if (isset($mainItem->sideMenu[$sideCode])) {
            $definition = array_merge((array) $mainItem->sideMenu[$sideCode], $definition);
        }

        $item = SideMenuItem::createFromArray($definition);

        $this->items[$itemKey]->addSideMenuItem($item);
        return true;
    }









    public function removeSideMenuItems($owner, $code, $sideCodes)
    {
        foreach ($sideCodes as $sideCode) {
            $this->removeSideMenuItem($owner, $code, $sideCode);
        }
    }








    public function removeSideMenuItem($owner, $code, $sideCode)
    {
        $itemKey = $this->makeItemKey($owner, $code);
        if (!isset($this->items[$itemKey])) {
            return false;
        }

        $mainItem = $this->items[$itemKey];
        $mainItem->removeSideMenuItem($sideCode);
        return true;
    }






    public function listMainMenuItems()
    {
        if ($this->items === null && $this->quickActions === null) {
            $this->loadItems();
        }

        if ($this->items === null) {
            return [];
        }

        foreach ($this->items as $item) {
            if ($item->badge) {
                $item->counter = (string) $item->badge;
                continue;
            }
            if ($item->counter === false) {
                continue;
            }

            if ($item->counter !== null && is_callable($item->counter)) {
                $item->counter = call_user_func($item->counter, $item);
            } elseif (!empty((int) $item->counter)) {
                $item->counter = (int) $item->counter;
            } elseif (!empty($sideItems = $this->listSideMenuItems($item->owner, $item->code))) {
                $item->counter = 0;
                foreach ($sideItems as $sideItem) {
                    if ($sideItem->badge) {
                        continue;
                    }
                    $item->counter += $sideItem->counter;
                }
            }

            if (empty($item->counter) || !is_numeric($item->counter)) {
                $item->counter = null;
            }
        }

        return $this->items;
    }









    public function listSideMenuItems($owner = null, $code = null)
    {
        $activeItem = null;

        if ($owner !== null && $code !== null) {
            $activeItem = @$this->items[$this->makeItemKey($owner, $code)];
        } else {
            foreach ($this->listMainMenuItems() as $item) {
                if ($this->isMainMenuItemActive($item)) {
                    $activeItem = $item;
                    break;
                }
            }
        }

        if (!$activeItem) {
            return [];
        }

        $items = $activeItem->sideMenu;

        foreach ($items as $item) {
            if ($item->badge) {
                $item->counter = (string) $item->badge;
                continue;
            }
            if ($item->counter !== null && is_callable($item->counter)) {
                $item->counter = call_user_func($item->counter, $item);
                if (empty($item->counter)) {
                    $item->counter = null;
                }
            }
            if (!is_null($item->counter) && !is_numeric($item->counter)) {
                throw new SystemException("The menu item {$activeItem->code}.{$item->code}'s counter property is invalid. Check to make sure it's numeric or callable. Value: " . var_export($item->counter, true));
            }
        }

        return $items;
    }























    public function registerQuickActions($owner, array $definitions)
    {
        $validator = Validator::make($definitions, [
            '*.label' => 'required',
            '*.icon' => 'required_without:*.iconSvg',
            '*.url' => 'required'
        ]);

        if ($validator->fails()) {
            $errorMessage = 'Invalid quick action item detected in ' . $owner . '. Contact the plugin author to fix (' . $validator->errors()->first() . ')';
            if (Config::get('app.debug', false)) {
                throw new SystemException($errorMessage);
            }

            Log::error($errorMessage);
        }

        $this->addQuickActionItems($owner, $definitions);
    }








    public function addQuickActionItems($owner, array $definitions)
    {
        foreach ($definitions as $code => $definition) {
            $this->addQuickActionItem($owner, $code, $definition);
        }
    }









    public function addQuickActionItem($owner, $code, array $definition)
    {
        $itemKey = $this->makeItemKey($owner, $code);

        if (isset($this->quickActions[$itemKey])) {
            $definition = array_merge((array) $this->quickActions[$itemKey], $definition);
        }

        $item = array_merge($definition, [
            'code'  => $code,
            'owner' => $owner
        ]);

        $this->quickActions[$itemKey] = QuickActionItem::createFromArray($item);
    }









    public function getQuickActionItem(string $owner, string $code)
    {
        $itemKey = $this->makeItemKey($owner, $code);

        if (!array_key_exists($itemKey, $this->quickActions)) {
            throw new SystemException('No quick action item found with key ' . $itemKey);
        }

        return $this->quickActions[$itemKey];
    }








    public function removeQuickActionItem($owner, $code)
    {
        $itemKey = $this->makeItemKey($owner, $code);
        unset($this->quickActions[$itemKey]);
    }







    public function listQuickActionItems()
    {
        if ($this->items === null && $this->quickActions === null) {
            $this->loadItems();
        }

        if ($this->quickActions === null) {
            return [];
        }

        return $this->quickActions;
    }








    public function setContext($owner, $mainMenuItemCode, $sideMenuItemCode = null)
    {
        $this->setContextOwner($owner);
        $this->setContextMainMenu($mainMenuItemCode);
        $this->setContextSideMenu($sideMenuItemCode);
    }






    public function setContextOwner($owner)
    {
        $this->contextOwner = strtoupper($owner);
    }




    public function getContextOwner()
    {
        return $this->aliases[$this->contextOwner] ?? $this->contextOwner;
    }





    public function setContextMainMenu($mainMenuItemCode)
    {
        $this->contextMainMenuItemCode = $mainMenuItemCode;
    }








    public function getContext()
    {
        return (object)[
            'mainMenuCode' => $this->contextMainMenuItemCode,
            'sideMenuCode' => $this->contextSideMenuItemCode,
            'owner' => $this->getContextOwner(),
        ];
    }






    public function setContextSideMenu($sideMenuItemCode)
    {
        $this->contextSideMenuItemCode = $sideMenuItemCode;
    }






    public function isMainMenuItemActive($item)
    {
        return $this->getContextOwner() === strtoupper($item->owner) && $this->contextMainMenuItemCode === $item->code;
    }






    public function getActiveMainMenuItem()
    {
        foreach ($this->listMainMenuItems() as $item) {
            if ($this->isMainMenuItemActive($item)) {
                return $item;
            }
        }

        return null;
    }






    public function isSideMenuItemActive($item)
    {
        if ($this->contextSideMenuItemCode === true) {
            $this->contextSideMenuItemCode = null;
            return true;
        }

        return $this->getContextOwner() === strtoupper($item->owner) && $this->contextSideMenuItemCode === $item->code;
    }








    public function registerContextSidenavPartial($owner, $mainMenuItemCode, $partial)
    {
        $this->contextSidenavPartials[$this->makeItemKey($owner, $mainMenuItemCode)] = $partial;
    }









    public function getContextSidenavPartial($owner, $mainMenuItemCode)
    {
        return $this->contextSidenavPartials[$this->makeItemKey($owner, $mainMenuItemCode)] ?? null;
    }







    protected function filterItemPermissions($user, array $items)
    {
        if (!$user) {
            return $items;
        }

        $items = array_filter($items, static function ($item) use ($user) {
            if (!$item->permissions || !count($item->permissions)) {
                return true;
            }

            return $user->hasAnyAccess($item->permissions);
        });

        return $items;
    }







    protected function makeItemKey($owner, $code)
    {
        $owner = strtoupper($owner);
        return ($this->aliases[$owner] ?? $owner) . '.' . strtoupper($code);
    }
}
