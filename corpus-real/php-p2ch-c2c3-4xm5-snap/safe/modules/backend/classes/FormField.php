<?php

namespace Backend\Classes;

use BackedEnum;
use Illuminate\Support\Facades\Lang;
use Winter\Storm\Database\Model;
use Winter\Storm\Html\Helper as HtmlHelper;
use Winter\Storm\Support\Facades\Html;
use Winter\Storm\Support\Str;








class FormField
{



    const NO_SAVE_DATA = -1;




    const HIERARCHY_UP = '^';




    public $fieldName;






    public $arrayName;




    public $idPrefix;




    public $label;




    public $value;




    public $valueFrom;




    public $defaults;




    public $defaultFrom;




    public $tab;




    public $type = 'text';




    public $options;




    public $span = 'full';




    public $size;




    public $context;




    public $required;




    public $readOnly = false;




    public $disabled = false;




    public $hidden = false;




    public $stretch = false;




    public $comment = '';




    public $commentPosition = 'below';




    public $commentHtml = false;




    public $placeholder = '';




    public $attributes;




    public $cssClass;




    public $path;




    public $config;




    public $dependsOn;




    public $trigger;




    public $preset;






    public function __construct($fieldName, $label)
    {
        $this->fieldName = $fieldName;
        $this->label = $label;
    }




    public function tab($value)
    {
        $this->tab = $value;
        return $this;
    }





    public function span($value = 'full')
    {
        $this->span = $value;
        return $this;
    }





    public function size($value = 'large')
    {
        $this->size = $value;
        return $this;
    }






    public function options($value = null)
    {
        if ($value === null) {
            if (is_array($this->options)) {
                return $this->options;
            } elseif (is_callable($this->options)) {
                $callable = $this->options;
                return $callable();
            } elseif (is_string($this->options) && is_array($options = Lang::get($this->options))) {
                return $options;
            }

            return [];
        }

        $this->options = $value;

        return $this;
    }













    public function displayAs($type, $config = [])
    {
        if (in_array($type, ['textarea', 'widget'])) {

            $this->size = 'large';
        }

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
            'commentHtml',
            'context',
            'cssClass',
            'dependsOn',
            'disabled',
            'hidden',
            'path',
            'placeholder',
            'preset',
            'readOnly',
            'required',
            'stretch',
            'trigger',
        ];

        foreach ($applyConfigValues as $value) {
            if (array_key_exists($value, $config)) {
                $this->{$value} = $config[$value];
            }
        }




        if (isset($config['options'])) {
            $this->options($config['options']);
        }
        if (isset($config['span'])) {
            $this->span($config['span']);
        }
        if (isset($config['size'])) {
            $this->size($config['size']);
        }
        if (isset($config['tab'])) {
            $this->tab($config['tab']);
        }
        if (isset($config['commentAbove'])) {
            $this->comment($config['commentAbove'], 'above');
        }
        if (isset($config['comment'])) {
            $this->comment($config['comment']);
        }
        if (isset($config['default'])) {
            $this->defaults = $config['default'];
        }
        if (isset($config['defaultFrom'])) {
            $this->defaultFrom = $config['defaultFrom'];
        }
        if (isset($config['attributes'])) {
            $this->attributes($config['attributes']);
        }
        if (isset($config['containerAttributes'])) {
            $this->attributes($config['containerAttributes'], 'container');
        }

        if (isset($config['valueFrom'])) {
            $this->valueFrom = $config['valueFrom'];
        }
        else {
            $this->valueFrom = $this->fieldName;
        }

        return $config;
    }








    public function comment($text, $position = 'below', $isHtml = null)
    {
        $this->comment = $text;
        $this->commentPosition = $position;

        if ($isHtml !== null) {
            $this->commentHtml = $isHtml;
        }

        return $this;
    }






    public function isSelected($value = true)
    {
        if ($this->value === null) {
            return false;
        }

        $value = ($value instanceof BackedEnum) ? $value->value : $value;
        $currentValue = ($this->value instanceof BackedEnum) ? $this->value->value : $this->value;

        return (string) $value === (string) $currentValue;
    }









    public function attributes($items, $position = 'field')
    {
        if (!is_array($items)) {
            return;
        }

        $multiArray = array_filter($items, 'is_array');
        if (!$multiArray) {
            $this->attributes[$position] = $items;
            return;
        }

        foreach ($items as $_position => $_items) {
            $this->attributes($_items, $_position);
        }

        return $this;
    }







    public function hasAttribute($name, $position = 'field')
    {
        if (!isset($this->attributes[$position])) {
            return false;
        }

        return array_key_exists($name, $this->attributes[$position]);
    }






    public function getAttributes($position = 'field', $htmlBuild = true)
    {
        $result = array_get($this->attributes, $position, []);
        $result = $this->filterAttributes($result, $position);


        if ($position === 'field' && $this->required && (!isset($result['required']) || $result['required'])) {
            $result['required'] = '';
        } elseif ($position === 'field' && isset($result['required']) && !$result['required']) {

            unset($result['required']);
        }

        return $htmlBuild ? Html::attributes($result) : $result;
    }








    protected function filterAttributes($attributes, $position = 'field')
    {
        $position = strtolower($position);

        $attributes = $this->filterTriggerAttributes($attributes, $position);
        $attributes = $this->filterPresetAttributes($attributes, $position);

        if ($position == 'field' && $this->disabled) {
            $attributes = $attributes + ['disabled' => 'disabled'];
        }

        if ($position == 'field' && $this->readOnly) {
            $attributes = $attributes + ['readonly' => 'readonly'];

            if ($this->type == 'checkbox' || $this->type == 'switch') {
                $attributes = $attributes + ['onclick' => 'return false;'];
            }
        }

        return $attributes;
    }







    protected function filterTriggerAttributes($attributes, $position = 'field')
    {
        if (!$this->trigger || !is_array($this->trigger)) {
            return $attributes;
        }

        $triggerAction = array_get($this->trigger, 'action');
        $triggerField = array_get($this->trigger, 'field');
        $triggerCondition = array_get($this->trigger, 'condition');
        $triggerForm = $this->arrayName;
        $triggerMulti = '';


        if (in_array($triggerAction, ['hide', 'show']) && $position != 'container') {
            return $attributes;
        }


        if (in_array($triggerAction, ['enable', 'disable', 'empty']) && $position != 'field') {
            return $attributes;
        }


        $triggerFieldParentLevel = Str::getPrecedingSymbols($triggerField, self::HIERARCHY_UP);
        if ($triggerFieldParentLevel > 0) {

            $triggerField = substr($triggerField, $triggerFieldParentLevel);
            $triggerForm = HtmlHelper::reduceNameHierarchy($triggerForm, $triggerFieldParentLevel);
        }


        if (Str::endsWith($triggerField, '[]')) {
            $triggerField = substr($triggerField, 0, -2);
            $triggerMulti = '[]';
        }


        if ($this->arrayName) {
            $fullTriggerField = $triggerForm.'['.implode('][', HtmlHelper::nameToArray($triggerField)).']'.$triggerMulti;
        }
        else {
            $fullTriggerField = $triggerField.$triggerMulti;
        }

        $newAttributes = [
            'data-trigger' => '[name="'.$fullTriggerField.'"]',
            'data-trigger-action' => $triggerAction,
            'data-trigger-condition' => $triggerCondition,
            'data-trigger-closest-parent' => 'form, div[data-control="formwidget"]'
        ];

        return $attributes + $newAttributes;
    }







    protected function filterPresetAttributes($attributes, $position = 'field')
    {
        if (!$this->preset || $position != 'field') {
            return $attributes;
        }

        if (!is_array($this->preset)) {
            $this->preset = ['field' => $this->preset, 'type' => 'slug'];
        }

        $presetField = array_get($this->preset, 'field');
        $presetType = array_get($this->preset, 'type');

        if ($this->arrayName) {
            $fullPresetField = $this->arrayName.'['.implode('][', HtmlHelper::nameToArray($presetField)).']';
        }
        else {
            $fullPresetField = $presetField;
        }

        $newAttributes = [
            'data-input-preset' => '[name="'.$fullPresetField.'"]',
            'data-input-preset-type' => $presetType,
            'data-input-preset-closest-parent' => 'form'
        ];

        if ($prefixInput = array_get($this->preset, 'prefixInput')) {
            $newAttributes['data-input-preset-prefix-input'] = $prefixInput;
        }

        return $attributes + $newAttributes;
    }






    public function getName($arrayName = null)
    {
        if ($arrayName === null) {
            $arrayName = $this->arrayName;
        }

        if ($arrayName) {
            return $arrayName.'['.implode('][', HtmlHelper::nameToArray($this->fieldName)).']';
        }

        return $this->fieldName;
    }






    public function getId($suffix = null)
    {
        $id = 'field';
        if ($this->arrayName) {
            $id .= '-'.$this->arrayName;
        }

        $id .= '-'.$this->fieldName;

        if ($suffix) {
            $id .= '-'.$suffix;
        }

        if ($this->idPrefix) {
            $id = $this->idPrefix . '-' . $id;
        }

        return HtmlHelper::nameToId($id);
    }







    public function getConfig($value, $default = null)
    {
        return array_get($this->config, $value, $default);
    }








    public function getValueFromData($data, $default = null)
    {
        $fieldName = $this->valueFrom ?: $this->fieldName;
        return $this->getFieldNameFromData($fieldName, $data, $default);
    }







    public function getDefaultFromData($data)
    {
        if ($this->defaultFrom) {
            return $this->getFieldNameFromData($this->defaultFrom, $data);
        }

        if ($this->defaults !== '') {
            return $this->defaults;
        }

        return null;
    }









    public function resolveModelAttribute($model, $attribute = null)
    {
        if ($attribute === null) {
            $attribute = $this->valueFrom ?: $this->fieldName;
        }

        $parts = is_array($attribute) ? $attribute : HtmlHelper::nameToArray($attribute);
        $last = array_pop($parts);

        foreach ($parts as $part) {
            $model = $model->{$part};
        }

        return [$model, $last];
    }








    protected function getFieldNameFromData($fieldName, $data, $default = null)
    {



        $keyParts = HtmlHelper::nameToArray($fieldName);
        $lastField = end($keyParts);
        $result = $data;






        foreach ($keyParts as $key) {
            if ($result instanceof Model && $result->hasRelation($key)) {
                if ($key == $lastField) {
                    $result = $result->getRelationValue($key) ?: $default;
                } else {
                    $result = $result->{$key};
                }
            } elseif (is_array($result)) {
                if (!array_key_exists($key, $result)) {
                    return $default;
                }
                $result = $result[$key];
            } else {
                if (!isset($result->{$key})) {
                    return $default;
                }
                $result = $result->{$key};
            }
        }

        if ($result instanceof BackedEnum) {
            $result = $result->value;
        }

        return $result;
    }





    public function __get($name)
    {
        if (is_array($this->config) && array_key_exists($name, $this->config)) {
            return array_get($this->config, $name);
        }
        if (property_exists($this, $name)) {
            return $this->{$name};
        }
        return null;
    }





    public function __isset($name)
    {
        if (is_array($this->config) && array_key_exists($name, $this->config)) {
            return true;
        }
        return property_exists($this, $name) && !is_null($this->{$name});
    }
}
