<?php namespace Backend\Classes;

use Str;
use BackendAuth;
use SystemException;
use System\Classes\PluginManager;
use Event;







class WidgetManager
{
    use \Winter\Storm\Support\Traits\Singleton;




    protected $formWidgets;




    protected $formWidgetCallbacks = [];




    protected $formWidgetHints;




    protected $reportWidgets;




    protected $reportWidgetCallbacks = [];




    protected $pluginManager;




    protected function init()
    {
        $this->pluginManager = PluginManager::instance();
    }









    public function listFormWidgets()
    {
        if ($this->formWidgets === null) {
            $this->formWidgets = [];




            foreach ($this->formWidgetCallbacks as $callback) {
                $callback($this);
            }




            $plugins = $this->pluginManager->getPlugins();

            foreach ($plugins as $plugin) {
                if (!is_array($widgets = $plugin->registerFormWidgets())) {
                    continue;
                }

                foreach ($widgets as $className => $widgetInfo) {
                    $this->registerFormWidget($className, $widgetInfo);
                }
            }
        }

        return $this->formWidgets;
    }







    public function registerFormWidget($className, $widgetInfo = null)
    {
        if (!is_array($widgetInfo)) {
            $widgetInfo = ['code' => $widgetInfo];
        }

        $widgetCode = $widgetInfo['code'] ?? null;

        if (!$widgetCode) {
            $widgetCode = Str::getClassId($className);
        }

        $this->formWidgets[$className] = $widgetInfo;
        $this->formWidgetHints[$widgetCode] = $className;
    }









    public function registerFormWidgets(callable $definitions)
    {
        $this->formWidgetCallbacks[] = $definitions;
    }







    public function resolveFormWidget($name)
    {
        if ($this->formWidgets === null) {
            $this->listFormWidgets();
        }

        $hints = $this->formWidgetHints;

        if (isset($hints[$name])) {
            return $hints[$name];
        }

        $_name = Str::normalizeClassName($name);
        if (isset($this->formWidgets[$_name])) {
            return $_name;
        }

        return $name;
    }









    public function listReportWidgets()
    {
        if ($this->reportWidgets === null) {
            $this->reportWidgets = [];




            foreach ($this->reportWidgetCallbacks as $callback) {
                $callback($this);
            }




            $plugins = $this->pluginManager->getPlugins();

            foreach ($plugins as $plugin) {
                if (!is_array($widgets = $plugin->registerReportWidgets())) {
                    continue;
                }

                foreach ($widgets as $className => $widgetInfo) {
                    $this->registerReportWidget($className, $widgetInfo);
                }
            }
        }
















        Event::fire('system.reportwidgets.extendItems', [$this]);

        $user = BackendAuth::getUser();
        foreach ($this->reportWidgets as $widget => $config) {
            if (!empty($config['permissions'])) {
                if (!$user->hasAccess($config['permissions'], false)) {
                    unset($this->reportWidgets[$widget]);
                }
            }
        }

        return $this->reportWidgets;
    }





    public function getReportWidgets()
    {
        return $this->reportWidgets;
    }




    public function registerReportWidget($className, $widgetInfo)
    {
        $this->reportWidgets[$className] = $widgetInfo;
    }












    public function registerReportWidgets(callable $definitions)
    {
        $this->reportWidgetCallbacks[] = $definitions;
    }






    public function removeReportWidget($className)
    {
        if (!$this->reportWidgets) {
            throw new SystemException('Unable to remove a widget before widgets are loaded.');
        }

        unset($this->reportWidgets[$className]);
    }
}
