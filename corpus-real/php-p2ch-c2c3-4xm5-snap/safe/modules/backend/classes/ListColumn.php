<?php namespace Backend\Classes;

use Winter\Storm\Database\Model;
use Winter\Storm\Html\Helper as HtmlHelper;








class ListColumn
{



    public $columnName;




    public $label;




    public $type = 'text';




    public $searchable = false;




    public $invisible = false;




    public $sortable = true;




    public $summable = false;




    public $clickable = true;





    public $valueFrom;




    public $defaults;





    public $sqlSelect;




    public $relation;






    public $width;




    public $cssClass;




    public $headCssClass;




    public $format;




    public $path;




    public $align;




    public $config;






    public function __construct($columnName, $label)
    {
        $this->columnName = $columnName;
        $this->label = $label;
    }







    public function displayAs($type, $config)
    {
        $this->type = strtolower($type) ?: $this->type;
        $this->config = $this->evalConfig($config);
        return $this;
    }






    protected function evalConfig($config)
    {
        if (isset($config['width'])) {
            $this->width = $config['width'];
        }
        if (isset($config['cssClass'])) {
            $this->cssClass = $config['cssClass'];
        }
        if (isset($config['headCssClass'])) {
            $this->headCssClass = $config['headCssClass'];
        }
        if (isset($config['searchable'])) {
            $this->searchable = $config['searchable'];
        }
        if (isset($config['sortable'])) {
            $this->sortable = $config['sortable'];
        }
        if (isset($config['summable'])) {
            $this->summable = $config['summable'];
        }
        if (isset($config['clickable'])) {
            $this->clickable = $config['clickable'];
        }
        if (isset($config['invisible'])) {
            $this->invisible = $config['invisible'];
        }
        if (isset($config['valueFrom'])) {
            $this->valueFrom = $config['valueFrom'];
        }
        if (isset($config['default'])) {
            $this->defaults = $config['default'];
        }
        if (isset($config['select'])) {
            $this->sqlSelect = $config['select'];
        }
        if (isset($config['relation'])) {
            $this->relation = $config['relation'];
        }
        if (isset($config['format'])) {
            $this->format = $config['format'];
        }
        if (isset($config['path'])) {
            $this->path = $config['path'];
        }
        if (isset($config['align']) && \in_array($config['align'], ['left', 'right', 'center'])) {
            $this->align = $config['align'];
        }

        return $config;
    }





    public function getName()
    {
        return HtmlHelper::nameToId($this->columnName);
    }






    public function getId($suffix = null)
    {
        $id = 'column';

        $id .= '-'.$this->columnName;

        if ($suffix) {
            $id .= '-'.$suffix;
        }

        return HtmlHelper::nameToId($id);
    }





    public function getAlignClass()
    {
        return $this->align ? 'list-cell-align-' . $this->align : '';
    }







    public function getConfig($value, $default = null)
    {
        return array_get($this->config, $value, $default);
    }








    public function getValueFromData($data, $default = null)
    {
        $columnName = $this->valueFrom ?: $this->columnName;
        return $this->getColumnNameFromData($columnName, $data, $default);
    }








    protected function getColumnNameFromData($columnName, $data, $default = null)
    {



        $keyParts = HtmlHelper::nameToArray($columnName);
        $result = $data;






        foreach ($keyParts as $key) {
            if ($result instanceof Model && $result->hasRelation($key)) {
                $result = $result->{$key};
            }
            else {
                if (is_array($result) && array_key_exists($key, $result)) {
                    $result = $result[$key];
                } elseif (!isset($result->{$key})) {
                    return $default;
                } else {
                    $result = $result->{$key};
                }
            }
        }

        return $result;
    }
}
