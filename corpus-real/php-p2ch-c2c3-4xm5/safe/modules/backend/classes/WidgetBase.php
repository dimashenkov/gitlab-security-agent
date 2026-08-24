<?php namespace Backend\Classes;

use Winter\Storm\Html\Helper as HtmlHelper;
use Winter\Storm\Extension\Extendable;
use stdClass;







abstract class WidgetBase extends Extendable
{
    use \System\Traits\ViewMaker;
    use \System\Traits\AssetMaker;
    use \System\Traits\ConfigMaker;
    use \System\Traits\EventEmitter;
    use \Backend\Traits\ErrorMaker;
    use \Backend\Traits\WidgetMaker;
    use \Backend\Traits\SessionMaker;




    public $config;




    protected $controller;




    public $alias;




    protected $defaultAlias = 'widget';






    public function __construct($controller, $configuration = [])
    {
        $this->controller = $controller;
        $this->viewPath = $this->configPath = $this->guessViewPath('/partials');
        $this->assetPath = $this->guessViewPath('/assets', true);





        if ($this->config === null) {
            $this->config = $this->makeConfig($configuration);
        }




        if (!isset($this->alias)) {
            $this->alias = $this->config->alias ?? $this->defaultAlias;
        }




        $this->loadAssets();

        parent::__construct();




        if (!$this->getConfig('noInit', false)) {
            $this->init();
        }
    }





    public function init()
    {
    }





    public function render()
    {
    }






    protected function loadAssets()
    {
    }





    public function bindToController()
    {
        if ($this->controller->widget === null) {
            $this->controller->widget = new stdClass;
        }

        $this->controller->widget->{$this->alias} = $this;
    }








    protected function fillFromConfig($properties = null)
    {
        if ($properties === null) {
            $properties = array_keys((array) $this->config);
        }

        foreach ($properties as $property) {
            if (property_exists($this, $property)) {
                $this->{$property} = $this->getConfig($property, $this->{$property});
            }
        }
    }






    public function getId($suffix = null)
    {
        $id = class_basename(get_called_class());

        if ($this->alias != $this->defaultAlias) {
            $id .= '-' . $this->alias;
        }

        if ($suffix !== null) {
            $id .= '-' . $suffix;
        }

        return HtmlHelper::nameToId($id);
    }






    public function getEventHandler($name)
    {
        return $this->alias . '::' . $name;
    }







    public function getConfig($name, $default = null)
    {



        $keyParts = HtmlHelper::nameToArray($name);




        $fieldName = array_shift($keyParts);
        if (!isset($this->config->{$fieldName})) {
            return $default;
        }

        $result = $this->config->{$fieldName};




        foreach ($keyParts as $key) {
            if (!array_key_exists($key, $result)) {
                return $default;
            }

            $result = $result[$key];
        }

        return $result;
    }




    public function getController()
    {
        return $this->controller;
    }
}
