<?php namespace Backend\Classes;

use Winter\Storm\Html\Helper as HtmlHelper;








abstract class FormWidgetBase extends WidgetBase
{








    public $model;




    public $data;




    public $sessionKey;




    public $previewMode = false;




    public $showLabels = true;








    protected $formField;




    protected $parentForm = null;




    protected $fieldName;




    protected $valueFrom;







    public function __construct($controller, $formField, $configuration = [])
    {
        $this->formField = $formField;
        $this->fieldName = $formField->fieldName;
        $this->valueFrom = $formField->valueFrom;

        $this->config = $this->makeConfig($configuration);

        $this->fillFromConfig([
            'model',
            'data',
            'sessionKey',
            'previewMode',
            'showLabels',
            'parentForm',
        ]);

        parent::__construct($controller, $configuration);
    }






    public function getParentForm()
    {
        return $this->parentForm;
    }






    public function getFieldName()
    {
        return $this->formField->getName();
    }




    public function getId($suffix = null)
    {
        $id = parent::getId($suffix);
        $id .= '-' . $this->fieldName;
        return HtmlHelper::nameToId($id);
    }







    public function getSaveValue($value)
    {
        return $value;
    }






    public function getLoadValue()
    {
        if ($this->formField->value !== null) {
            return $this->formField->value;
        }

        $defaultValue = !$this->model->exists
            ? $this->formField->getDefaultFromData($this->data ?: $this->model)
            : null;

        return $this->formField->getValueFromData($this->data ?: $this->model, $defaultValue);
    }
}
