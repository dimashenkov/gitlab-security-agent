<?php namespace Backend\Classes;

use Lang;
use ApplicationException;
use Winter\Storm\Extension\ExtensionBase;
use System\Traits\ViewMaker;
use Winter\Storm\Html\Helper as HtmlHelper;







class ControllerBehavior extends ExtensionBase
{
    use \Backend\Traits\WidgetMaker;
    use \Backend\Traits\SessionMaker;
    use \System\Traits\AssetMaker;
    use \System\Traits\ConfigMaker;
    use \System\Traits\ViewMaker {
        ViewMaker::makeFileContents as localMakeFileContents;
    }




    protected $config;




    protected $controller;




    protected $requiredProperties = [];




    protected $actions;




    public function __construct($controller)
    {
        $this->controller = $controller;
        $this->viewPath = $this->configPath = $this->guessViewPath('/partials');
        $this->assetPath = $this->guessViewPath('/assets', true);




        foreach ($this->requiredProperties as $property) {
            if (!isset($controller->{$property})) {
                throw new ApplicationException(Lang::get('system::lang.behavior.missing_property', [
                    'class' => get_class($controller),
                    'property' => $property,
                    'behavior' => get_called_class()
                ]));
            }
        }


        if (is_array($this->actions)) {
            $this->hideAction(array_diff(get_class_methods(get_class($this)), $this->actions));
        }


        $this->controller->appendViewPath($this->guessViewPath('/views'));
    }






    public function setConfig($config, $required = [])
    {
        $this->config = $this->makeConfig($config, $required);
    }







    public function getConfig($name = null, $default = null)
    {



        if ($name === null) {
            return $this->config;
        }




        $keyParts = HtmlHelper::nameToArray($name);




        $fieldName = array_shift($keyParts);
        if (!isset($this->config->{$fieldName})) {
            return $default;
        }

        $result = $this->config->{$fieldName};




        foreach ($keyParts as $key) {
            if (!is_array($result) || !array_key_exists($key, $result)) {
                return $default;
            }

            $result = $result[$key];
        }

        return $result;
    }









    protected function hideAction($methodName)
    {
        if (!is_array($methodName)) {
            $methodName = [$methodName];
        }

        $this->controller->hiddenActions = array_merge($this->controller->hiddenActions, $methodName);
    }







    public function makeFileContents($filePath, $extraParams = [])
    {
        $this->controller->vars = array_merge($this->controller->vars, $this->vars);
        return $this->controller->makeFileContents($filePath, $extraParams);
    }






    protected function controllerMethodExists($methodName)
    {
        return method_exists($this->controller, $methodName);
    }
}
