<?php namespace Backend\Widgets;

use ApplicationException;
use Backend\Classes\FormField;
use Backend\Classes\FormTabs;
use Backend\Classes\FormWidgetBase;
use Backend\Classes\WidgetBase;
use Backend\Classes\WidgetManager;
use BackendAuth;
use Exception;
use Form as FormHelper;
use Lang;
use Winter\Storm\Database\Model;
use Winter\Storm\Html\Helper as HtmlHelper;








class Form extends WidgetBase
{
    use \Backend\Traits\FormModelSaver;








    public $fields;




    public $tabs;




    public $secondaryTabs;




    public $model;




    public $data;





    public $context;





    public $arrayName;





    public $isNested = false;








    protected $defaultAlias = 'form';




    protected $fieldsDefined = false;





    protected $allFields = [];





    protected $allTabs = [
        'outside'   => null,
        'primary'   => null,
        'secondary' => null,
    ];




    protected $formWidgets = [];




    public $sessionKey;




    public $previewMode = false;




    protected $widgetManager;




    public function init()
    {
        $this->fillFromConfig([
            'fields',
            'tabs',
            'secondaryTabs',
            'model',
            'data',
            'context',
            'arrayName',
            'isNested',
        ]);

        $this->widgetManager = WidgetManager::instance();
        $this->allTabs = (object) $this->allTabs;
        $this->validateModel();
    }








    public function bindToController()
    {
        $this->defineFormFields();
        parent::bindToController();
    }




    protected function loadAssets()
    {
        $this->addJs('js/winter.form.js', 'core');
    }
















    public function render($options = [])
    {
        if (isset($options['preview'])) {
            $this->previewMode = $options['preview'];
        }
        if (!isset($options['useContainer'])) {
            $options['useContainer'] = true;
        }
        if (!isset($options['section'])) {
            $options['section'] = null;
        }

        $extraVars = [];
        $targetPartial = 'form';




        if ($section = $options['section']) {
            $section = strtolower($section);

            if (isset($this->allTabs->{$section})) {
                $extraVars['tabs'] = $this->allTabs->{$section};
            }

            $targetPartial = 'section';
            $extraVars['renderSection'] = $section;
        }




        if ($useContainer = $options['useContainer']) {
            $targetPartial = $section ? 'section-container' : 'form-container';
        }

        $this->prepareVars();




        if ($this->previewMode) {
            foreach ($this->formWidgets as $widget) {
                $widget->previewMode = $this->previewMode;
            }
        }

        return $this->makePartial($targetPartial, $extraVars);
    }











    public function renderField($field, $options = [])
    {
        $this->prepareVars();

        if (is_string($field)) {
            if (!isset($this->allFields[$field])) {
                throw new ApplicationException(Lang::get(
                    'backend::lang.form.missing_definition',
                    compact('field')
                ));
            }

            $field = $this->allFields[$field];
        }

        $targetPartial = ($options['useContainer'] ?? true) ? 'field-container' : 'field';

        return $this->makePartial($targetPartial, ['field' => $field]);
    }






    public function renderFieldElement($field)
    {
        return $this->makePartial(
            'field_' . $field->type,
            [
                'field' => $field,
                'formModel' => $this->model
            ]
        );
    }






    protected function validateModel()
    {
        if (!$this->model) {
            throw new ApplicationException(Lang::get(
                'backend::lang.form.missing_model',
                ['class'=>get_class($this->controller)]
            ));
        }

        $this->data = isset($this->data)
            ? (object) $this->data
            : $this->model;

        return $this->model;
    }






    protected function prepareVars()
    {
        $this->defineFormFields();
        $this->applyFiltersFromModel();
        $this->vars['sessionKey'] = $this->getSessionKey();
        $this->vars['outsideTabs'] = $this->allTabs->outside;
        $this->vars['primaryTabs'] = $this->allTabs->primary;
        $this->vars['secondaryTabs'] = $this->allTabs->secondary;
    }






    public function setFormValues($data = null)
    {
        if ($data === null) {
            $data = $this->getSaveData();
        }




        $this->prepareModelsToSave($this->model, $data);




        if ($this->data !== $this->model) {
            $this->data = (object) array_merge((array) $this->data, (array) $data);
        }




        foreach ($this->allFields as $field) {
            $field->value = $this->getFieldValue($field);
        }

        return $data;
    }






    public function onRefresh()
    {
        $result = [];
        $saveData = $this->getSaveData();













        $dataHolder = (object) ['data' => $saveData];
        $this->fireSystemEvent('backend.form.beforeRefresh', [$dataHolder]);
        $saveData = $dataHolder->data;




        $this->setFormValues($saveData);
        $this->prepareVars();


















        $this->fireSystemEvent('backend.form.refreshFields', [$this->allFields]);




        if (($updateFields = post('fields')) && is_array($updateFields)) {
            foreach ($updateFields as $field) {
                if (!isset($this->allFields[$field])) {
                    continue;
                }


                $fieldObject = $this->allFields[$field];
                $result['#' . $fieldObject->getId('group')] = $this->makePartial('field', ['field' => $fieldObject]);
            }
        }




        if (empty($result)) {
            $result = ['#'.$this->getId() => $this->makePartial('form')];
        }




















        $eventResults = $this->fireSystemEvent('backend.form.refresh', [$result], false);

        foreach ($eventResults as $eventResult) {
            if (!is_array($eventResult)) {
                continue;
            }

            $result = $eventResult + $result;
        }

        return $result;
    }






    public function onLazyLoadTab()
    {
        $target  = post('target');
        $tabName = post('name');
        $tabSection = post('section');

        $fields = array_get(optional($this->getTab($tabSection))->fields, $tabName);

        return [
            $target => $this->makePartial('form_fields', ['fields' => $fields]),
        ];
    }








    public function nameToId($input)
    {
        return HtmlHelper::nameToId($input);
    }







    protected function defineFormFields()
    {
        if ($this->fieldsDefined) {
            return;
        }


















































        $this->fireSystemEvent('backend.form.extendFieldsBefore');




        if (!isset($this->fields) || !is_array($this->fields)) {
            $this->fields = [];
        }

        $this->allTabs->outside = new FormTabs(FormTabs::SECTION_OUTSIDE, (array) $this->config);
        $this->addFields($this->fields);




        if (!isset($this->tabs['fields']) || !is_array($this->tabs['fields'])) {
            $this->tabs['fields'] = [];
        }

        $this->allTabs->primary = new FormTabs(FormTabs::SECTION_PRIMARY, $this->tabs);
        $this->addFields($this->tabs['fields'], FormTabs::SECTION_PRIMARY);




        if (!isset($this->secondaryTabs['fields']) || !is_array($this->secondaryTabs['fields'])) {
            $this->secondaryTabs['fields'] = [];
        }

        $this->allTabs->secondary = new FormTabs(FormTabs::SECTION_SECONDARY, $this->secondaryTabs);
        $this->addFields($this->secondaryTabs['fields'], FormTabs::SECTION_SECONDARY);
























































        $this->fireSystemEvent('backend.form.extendFields', [$this->allFields]);




        foreach ($this->allTabs->outside->getFields() as $fields) {
            $this->processAutoSpan($fields);
        }

        foreach ($this->allTabs->primary->getFields() as $fields) {
            $this->processAutoSpan($fields);
        }

        foreach ($this->allTabs->secondary->getFields() as $fields) {
            $this->processAutoSpan($fields);
        }




        if (
            $this->allTabs->secondary->stretch === null
            && $this->allTabs->primary->stretch === null
            && $this->allTabs->outside->stretch === null
        ) {
            if ($this->allTabs->secondary->hasFields()) {
                $this->allTabs->secondary->stretch = true;
            }
            elseif ($this->allTabs->primary->hasFields()) {
                $this->allTabs->primary->stretch = true;
            }
            else {
                $this->allTabs->outside->stretch = true;
            }
        }




        foreach ($this->allFields as $field) {
            if ($field->type !== 'widget') {
                continue;
            }

            $widget = $this->makeFormFieldWidget($field);
            $widget->bindToController();
        }

        $this->fieldsDefined = true;
    }







    protected function processAutoSpan($fields)
    {
        $prevSpan = null;

        foreach ($fields as $field) {
            if (strtolower($field->span) === 'auto') {
                if ($prevSpan === 'left') {
                    $field->span = 'right';
                }
                else {
                    $field->span = 'left';
                }
            }

            $prevSpan = $field->span;
        }
    }








    public function addFields(array $fields, $addToArea = '')
    {
        foreach ($fields as $name => $config) {

            $permissions = array_get($config, 'permissions');
            if (!empty($permissions) && !BackendAuth::getUser()->hasAccess($permissions, false)) {
                continue;
            }

            $fieldObj = $this->makeFormField($name, $config);
            $fieldTab = is_array($config) ? array_get($config, 'tab') : null;


            if ($fieldObj->context !== null) {
                $context = is_array($fieldObj->context) ? $fieldObj->context : [$fieldObj->context];
                if (!in_array($this->getContext(), $context)) {
                    continue;
                }
            }


            $attrName = implode('.', HtmlHelper::nameToArray($fieldObj->fieldName));

            if ($this->model && method_exists($this->model, 'setValidationAttributeName')) {
                $this->model->setValidationAttributeName($attrName, $fieldObj->label);
            }

            $this->allFields[$fieldObj->fieldName] = $fieldObj;

            switch (strtolower($addToArea)) {
                case FormTabs::SECTION_PRIMARY:
                    $this->allTabs->primary->addField($fieldObj->fieldName, $fieldObj, $fieldTab);
                    break;
                case FormTabs::SECTION_SECONDARY:
                    $this->allTabs->secondary->addField($fieldObj->fieldName, $fieldObj, $fieldTab);
                    break;
                default:
                    $this->allTabs->outside->addField($fieldObj->fieldName, $fieldObj);
                    break;
            }
        }
    }







    public function addTabFields(array $fields)
    {
        $this->addFields($fields, 'primary');
    }





    public function addSecondaryTabFields(array $fields)
    {
        $this->addFields($fields, 'secondary');
    }







    public function removeField($name)
    {
        if (!isset($this->allFields[$name])) {
            return false;
        }




        $this->allTabs->primary->removeField($name);
        $this->allTabs->secondary->removeField($name);
        $this->allTabs->outside->removeField($name);




        unset($this->allFields[$name]);

        return true;
    }







    public function removeTab($name)
    {
        foreach ($this->allFields as $fieldName => $field) {
            if ($field->tab == $name) {
                $this->removeField($fieldName);
            }
        }
    }








    protected function makeFormField($name, $config = [])
    {
        $label = $config['label'] ?? null;
        list($fieldName, $fieldContext) = $this->getFieldName($name);

        $field = new FormField($fieldName, $label);

        if ($fieldContext) {
            $field->context = $fieldContext;
        }

        $attrName = implode('.', HtmlHelper::nameToArray($field->fieldName));
        $field->arrayName = $this->arrayName;
        $field->idPrefix = $this->getId();




        if (is_string($config)) {
            if ($this->isFormWidget($config) !== false) {
                $field->displayAs('widget', ['widget' => $config]);
            }
            else {
                $field->displayAs($config);
            }
        }



        else {
            $fieldType = $config['type'] ?? null;
            if (!is_string($fieldType) && $fieldType !== null) {
                throw new ApplicationException(Lang::get(
                    'backend::lang.field.invalid_type',
                    ['type' => gettype($fieldType)]
                ));
            }




            if ($this->isFormWidget($fieldType) !== false) {
                $config['widget'] = $fieldType;
                $fieldType = 'widget';
            }

            $field->displayAs($fieldType, $config);
        }




        $field->value = $this->getFieldValue($field);




        if ($field->required === null && $this->model && method_exists($this->model, 'isAttributeRequired')) {

            if ($this->isNested) {

                $nameArray = HtmlHelper::nameToArray($this->arrayName);
                unset($nameArray[0]);


                foreach ($nameArray as $i => $value) {
                    if (preg_match('/^[0-9]*$/', $value)) {
                        $nameArray[$i] = '*';
                    }
                }


                $attrName = implode('.', $nameArray) . ".{$attrName}";
            }

            $field->required = $this->model->isAttributeRequired($attrName);
        }




        $optionModelTypes = ['dropdown', 'radio', 'checkboxlist', 'balloon-selector'];

        if (in_array($field->type, $optionModelTypes, false)) {



            $field->options(function () use ($field, $config) {
                $fieldOptions = $config['options'] ?? null;
                $fieldOptions = $this->getOptionsFromModel($field, $fieldOptions);
                return $fieldOptions;
            });
        }

        return $field;
    }







    protected function isFormWidget($fieldType)
    {
        if ($fieldType === null) {
            return false;
        }

        if (strpos($fieldType, '\\')) {
            return true;
        }

        $widgetClass = $this->widgetManager->resolveFormWidget($fieldType);

        if (!class_exists($widgetClass)) {
            return false;
        }

        if (is_subclass_of($widgetClass, 'Backend\Classes\FormWidgetBase')) {
            return true;
        }

        return false;
    }







    protected function makeFormFieldWidget($field)
    {
        if ($field->type !== 'widget') {
            return null;
        }

        if (isset($this->formWidgets[$field->fieldName])) {
            return $this->formWidgets[$field->fieldName];
        }

        $widgetConfig = $this->makeConfig($field->config);
        $widgetConfig->alias = $this->alias . studly_case($this->nameToId($field->fieldName));
        $widgetConfig->sessionKey = $this->getSessionKey();
        $widgetConfig->previewMode = $this->previewMode;
        $widgetConfig->model = $this->model;
        $widgetConfig->data = $this->data;
        $widgetConfig->parentForm = $this;

        $widgetName = $widgetConfig->widget;
        $widgetClass = $this->widgetManager->resolveFormWidget($widgetName);

        if (!class_exists($widgetClass)) {
            throw new ApplicationException(Lang::get(
                'backend::lang.widget.not_registered',
                ['name' => $widgetClass]
            ));
        }

        $widget = $this->makeFormWidget($widgetClass, $field, $widgetConfig);




        if (isset($field->config['options'])) {
            $field->options(function () use ($field) {
                $fieldOptions = $field->config['options'];
                if ($fieldOptions === true) {
                    $fieldOptions = null;
                }
                $fieldOptions = $this->getOptionsFromModel($field, $fieldOptions);
                return $fieldOptions;
            });
        }

        return $this->formWidgets[$field->fieldName] = $widget;
    }






    public function getFormWidgets()
    {
        return $this->formWidgets;
    }







    public function getFormWidget($field)
    {
        if (isset($this->formWidgets[$field])) {
            return $this->formWidgets[$field];
        }

        return null;
    }






    public function getFields()
    {
        return $this->allFields;
    }







    public function getField($field)
    {
        if (isset($this->allFields[$field])) {
            return $this->allFields[$field];
        }

        return null;
    }






    public function getTabs()
    {
        return $this->allTabs;
    }








    public function getTab($tab)
    {
        if (isset($this->allTabs->$tab)) {
            return $this->allTabs->$tab;
        }

        return null;
    }






    protected function getFieldName($field)
    {
        if (strpos($field, '@') === false) {
            return [$field, null];
        }

        return explode('@', $field);
    }






    protected function getFieldValue($field)
    {
        if (is_string($field)) {
            if (!isset($this->allFields[$field])) {
                throw new ApplicationException(Lang::get(
                    'backend::lang.form.missing_definition',
                    compact('field')
                ));
            }

            $field = $this->allFields[$field];
        }

        $defaultValue = $this->shouldFetchDefaultValues()
            ? $field->getDefaultFromData($this->data)
            : null;

        return $field->getValueFromData(
            $this->data,
            is_string($defaultValue) ? trans($defaultValue) : $defaultValue
        );
    }





    protected function shouldFetchDefaultValues()
    {
        $enableDefaults = object_get($this->config, 'enableDefaults');
        if ($enableDefaults === false) {
            return false;
        }
        return !$this->model->exists || $enableDefaults;
    }







    protected function getFieldDepends($field)
    {
        if (!$field->dependsOn) {
            return '';
        }

        $dependsOn = is_array($field->dependsOn) ? $field->dependsOn : [$field->dependsOn];
        $dependsOn = htmlspecialchars(json_encode($dependsOn), ENT_QUOTES, 'UTF-8');
        return $dependsOn;
    }







    protected function showFieldLabels($field)
    {
        if (in_array($field->type, ['checkbox', 'switch', 'section'])) {
            return false;
        }

        if ($field->type === 'widget') {
            return $this->makeFormFieldWidget($field)->showLabels;
        }

        return true;
    }




    public function getSaveData(): array
    {
        $this->defineFormFields();

        $result = [];




        $data = $this->arrayName ? post($this->arrayName) : post();
        if (!$data) {
            $data = [];
        }




        foreach ($this->allFields as $field) {



            if ($field->disabled || $field->hidden) {
                continue;
            }




            $parts = HtmlHelper::nameToArray($field->fieldName);
            if (($value = $this->dataArrayGet($data, $parts)) !== null) {



                if ($field->type === 'number') {
                    $value = !strlen(trim($value)) ? null : (float) $value;
                }

                $this->dataArraySet($result, $parts, $value);
            }
        }




        foreach ($this->formWidgets as $field => $widget) {
            $parts = HtmlHelper::nameToArray($field);

            if ((isset($widget->config->disabled) && $widget->config->disabled)
                || (isset($widget->config->hidden) && $widget->config->hidden)) {
                continue;
            }


            $fieldValue = $this->dataArrayGet($result, $parts, FormField::NO_SAVE_DATA);
            if ($fieldValue === FormField::NO_SAVE_DATA) {
                continue;
            }


            $widgetValue = $widget->getSaveValue($fieldValue);
            if ($widgetValue === FormField::NO_SAVE_DATA) {
                continue;
            }
            $this->dataArraySet($result, $parts, $widgetValue);
        }

        return $result;
    }




    protected function applyFiltersFromModel()
    {



        if (method_exists($this->model, 'filterFields')) {
            $this->model->filterFields((object) $this->allFields, $this->getContext());
        }




        if (method_exists($this->model, 'fireEvent')) {




















            $this->model->fireEvent('model.form.filterFields', [$this, (object) $this->allFields, $this->getContext()]);
        }
    }








    public function getOptionsFromModel($field, $fieldOptions)
    {




        if (is_array($fieldOptions) && is_callable($fieldOptions)) {
            $fieldOptions = call_user_func($fieldOptions, $this, $field);
        }




        if (!is_array($fieldOptions) && !$fieldOptions) {
            try {
                list($model, $attribute) = $field->resolveModelAttribute($this->model, $field->fieldName);
                if (!$model) {
                    throw new Exception();
                }
            }
            catch (Exception $ex) {
                throw new ApplicationException(Lang::get('backend::lang.field.options_method_invalid_model', [
                    'model' => get_class($this->model),
                    'field' => $field->fieldName
                ]));
            }

            $methodName = 'get'.studly_case($attribute).'Options';
            if (
                !$this->objectMethodExists($model, $methodName) &&
                !$this->objectMethodExists($model, 'getDropdownOptions')
            ) {
                throw new ApplicationException(Lang::get('backend::lang.field.options_method_not_exists', [
                    'model'  => get_class($model),
                    'method' => $methodName,
                    'field'  => $field->fieldName
                ]));
            }

            if ($this->objectMethodExists($model, $methodName)) {
                $fieldOptions = $model->$methodName($field->value, $this->data);
            }
            else {
                $fieldOptions = $model->getDropdownOptions($attribute, $field->value, $this->data);
            }
        }



        elseif (is_string($fieldOptions)) {

            if (str_contains($fieldOptions, '::')) {
                $options = explode('::', $fieldOptions);
                if (count($options) === 2 && class_exists($options[0]) && method_exists($options[0], $options[1])) {
                    $result = $options[0]::{$options[1]}($this, $field);
                    if (!is_array($result)) {
                        throw new ApplicationException(Lang::get('backend::lang.field.options_static_method_invalid_value', [
                            'class' => $options[0],
                            'method' => $options[1]
                        ]));
                    }
                    return $result;
                } else {

                    if (is_array($options = Lang::get($fieldOptions))) {
                        return $options;
                    }
                }
            }


            if (!$this->objectMethodExists($this->model, $fieldOptions)) {
                throw new ApplicationException(Lang::get('backend::lang.field.options_method_not_exists', [
                    'model'  => get_class($this->model),
                    'method' => $fieldOptions,
                    'field'  => $field->fieldName
                ]));
            }

            $fieldOptions = $this->model->$fieldOptions($field->value, $field->fieldName, $this->data);
        }

        return $fieldOptions;
    }






    public function getSessionKey()
    {
        if ($this->sessionKey) {
            return $this->sessionKey;
        }

        if (post('_session_key')) {
            return $this->sessionKey = post('_session_key');
        }

        return $this->sessionKey = FormHelper::getSessionKey();
    }






    public function getContext()
    {
        return $this->context;
    }








    protected function objectMethodExists($object, $method)
    {
        if (method_exists($object, 'methodExists')) {
            return $object->methodExists($method);
        }

        return method_exists($object, $method);
    }









    protected function dataArrayGet(array $array, array $parts, $default = null)
    {
        if ($parts === null) {
            return $array;
        }

        if (count($parts) === 1) {
            $key = array_shift($parts);
            if (isset($array[$key])) {
                return $array[$key];
            }

            return $default;
        }

        foreach ($parts as $segment) {
            if (!is_array($array) || !array_key_exists($segment, $array)) {
                return $default;
            }

            $array = $array[$segment];
        }

        return $array;
    }









    protected function dataArraySet(array &$array, array $parts, $value)
    {
        if ($parts === null) {
            return $value;
        }

        while (count($parts) > 1) {
            $key = array_shift($parts);

            if (!isset($array[$key]) || !is_array($array[$key])) {
                $array[$key] = [];
            }

            $array =& $array[$key];
        }

        $array[array_shift($parts)] = $value;

        return $array;
    }
}
