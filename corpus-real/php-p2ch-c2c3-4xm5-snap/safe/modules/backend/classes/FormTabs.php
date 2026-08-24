<?php namespace Backend\Classes;

use IteratorAggregate;
use ArrayIterator;
use ArrayAccess;
use Traversable;








class FormTabs implements IteratorAggregate, ArrayAccess
{
    const SECTION_OUTSIDE = 'outside';
    const SECTION_PRIMARY = 'primary';
    const SECTION_SECONDARY = 'secondary';




    public $section = 'outside';




    public $fields = [];




    public $lazy = [];




    public $defaultTab = 'backend::lang.form.undefined_tab';




    public $icons = [];




    public $stretch;




    public $suppressTabs = false;




    public $cssClass;




    public $paneCssClass;




    public $linkable = true;










    public function __construct($section, $config = [])
    {
        $this->section = strtolower($section) ?: $this->section;
        $this->evalConfig($config);

        if ($this->section == self::SECTION_OUTSIDE) {
            $this->suppressTabs = true;
        }
    }




    protected function evalConfig(array $config): void
    {
        if (array_key_exists('defaultTab', $config)) {
            $this->defaultTab = $config['defaultTab'];
        }

        if (array_key_exists('icons', $config)) {
            $this->icons = $config['icons'];
        }

        if (array_key_exists('stretch', $config)) {
            $this->stretch = $config['stretch'];
        }

        if (array_key_exists('suppressTabs', $config)) {
            $this->suppressTabs = $config['suppressTabs'];
        }

        if (array_key_exists('cssClass', $config)) {
            $this->cssClass = $config['cssClass'];
        }

        if (array_key_exists('paneCssClass', $config)) {
            $this->paneCssClass = $config['paneCssClass'];
        }

        if (array_key_exists('linkable', $config)) {
            $this->linkable = (bool) $config['linkable'];
        }

        if (array_key_exists('lazy', $config)) {
            $this->lazy = $config['lazy'];
        }
    }







    public function addField($name, FormField $field, $tab = null)
    {
        if (!$tab) {
            $tab = $this->defaultTab;
        }

        $this->fields[$tab][$name] = $field;
    }






    public function removeField($name)
    {
        foreach ($this->fields as $tab => $fields) {
            foreach ($fields as $fieldName => $field) {
                if ($fieldName == $name) {
                    unset($this->fields[$tab][$fieldName]);




                    if (!count($this->fields[$tab])) {
                        unset($this->fields[$tab]);
                    }

                    return true;
                }
            }
        }

        return false;
    }





    public function hasFields()
    {
        return count($this->fields) > 0;
    }





    public function getFields()
    {
        return $this->fields;
    }





    public function getAllFields()
    {
        $tablessFields = [];

        foreach ($this->getFields() as $tab) {
            $tablessFields += $tab;
        }

        return $tablessFields;
    }






    public function getIcon($name)
    {
        if (!empty($this->icons[$name])) {
            return $this->icons[$name];
        }
    }







    public function getPaneCssClass($index = null, $label = null)
    {
        if (is_string($this->paneCssClass)) {
            return $this->paneCssClass;
        }

        if ($index !== null && isset($this->paneCssClass[$index])) {
            return $this->paneCssClass[$index];
        }

        if ($label !== null && isset($this->paneCssClass[$label])) {
            return $this->paneCssClass[$label];
        }
    }




    public function getIterator(): Traversable
    {
        return new ArrayIterator(
            $this->suppressTabs
                ? $this->getAllFields()
                : $this->getFields()
        );
    }




    public function offsetSet($offset, $value): void
    {
        $this->fields[$offset] = $value;
    }




    public function offsetExists($offset): bool
    {
        return isset($this->fields[$offset]);
    }




    public function offsetUnset($offset): void
    {
        unset($this->fields[$offset]);
    }




    public function offsetGet($offset): mixed
    {
        return $this->fields[$offset] ?? null;
    }
}
