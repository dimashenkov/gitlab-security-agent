<?php namespace Backend\Classes;

use Winter\Storm\Html\Helper as HtmlHelper;








class FilterScope
{



    public $scopeName;




    public $idPrefix;




    public $nameFrom = 'name';




    public $descriptionFrom;




    public $label;




    public $value;




    public $type = 'group';




    public $options;




    public $dependsOn;




    public $context;




    public $disabled = false;




    public $defaults;




    public $conditions;




    public $scope;




    public $cssClass;




    public $config;

    public function __construct($scopeName, $label)
    {
        $this->scopeName = $scopeName;
        $this->label = $label;
    }








    public function displayAs($type, $config = [])
    {
        $this->type = strtolower($type) ?: $this->type;
        $this->config = $this->evalConfig($config);
        return $this;
    }






    protected function evalConfig($config)
    {
        if ($config === null) {
            $config = [];
        }




        $applyConfigValues = [
            'options',
            'dependsOn',
            'context',
            'default',
            'conditions',
            'scope',
            'cssClass',
            'nameFrom',
            'descriptionFrom',
            'disabled',
        ];

        foreach ($applyConfigValues as $value) {
            if (array_key_exists($value, $config)) {
                $this->{$value} = $config[$value];
            }
        }

        return $config;
    }




    public function getId($suffix = null)
    {
        $id = 'scope';
        $id .= '-'.$this->scopeName;

        if ($suffix) {
            $id .= '-'.$suffix;
        }

        if ($this->idPrefix) {
            $id = $this->idPrefix . '-' . $id;
        }

        return HtmlHelper::nameToId($id);
    }
}
