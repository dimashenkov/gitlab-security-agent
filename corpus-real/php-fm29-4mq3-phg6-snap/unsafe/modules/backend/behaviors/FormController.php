<?php namespace Backend\Behaviors;

use Db;
use Str;
use Lang;
use Flash;
use Event;
use Redirect;
use Backend;
use Backend\Classes\ControllerBehavior;
use Winter\Storm\Router\Helper as RouterHelper;
use ApplicationException;
use Exception;


























class FormController extends ControllerBehavior
{
    use \Backend\Traits\FormModelSaver;




    const CONTEXT_CREATE = 'create';




    const CONTEXT_UPDATE = 'update';




    const CONTEXT_PREVIEW = 'preview';




    protected $controller;




    protected $formWidget;






    protected $requiredConfig = ['modelClass', 'form'];




    protected $actions = ['create', 'update', 'preview'];




    protected $context;




    protected $model;




    public $formConfig = 'config_form.yaml';





    public function __construct($controller)
    {
        parent::__construct($controller);




        $this->config = $this->makeConfig($controller->formConfig ?: $this->formConfig, $this->requiredConfig);
        $this->config->modelClass = Str::normalizeClassName($this->config->modelClass);
    }













    public function initForm($model, $context = null)
    {
        $context = $this->context = $context ?? $this->formGetContext();




        $formFields = $this->getConfig("{$context}[form]", $this->config->form);

        $config = $this->makeConfig($formFields);
        $config->model = $model;
        $config->arrayName = class_basename($model);
        $config->context = $context;




        $this->formWidget = $this->makeWidget('Backend\Widgets\Form', $config);


        if ($config->context === 'preview') {
            $this->formWidget->previewMode = true;
        }

        $this->formWidget->bindEvent('form.extendFieldsBefore', function () {
            $this->controller->formExtendFieldsBefore($this->formWidget);
        });

        $this->formWidget->bindEvent('form.extendFields', function ($fields) {
            $this->controller->formExtendFields($this->formWidget, $fields);
        });

        $this->formWidget->bindEvent('form.beforeRefresh', function ($holder) {
            $result = $this->controller->formExtendRefreshData($this->formWidget, $holder->data);
            if (is_array($result)) {
                $holder->data = $result;
            }
        });

        $this->formWidget->bindEvent('form.refreshFields', function ($fields) {
            return $this->controller->formExtendRefreshFields($this->formWidget, $fields);
        });

        $this->formWidget->bindEvent('form.refresh', function ($result) {
            return $this->controller->formExtendRefreshResults($this->formWidget, $result);
        });

        $this->formWidget->bindToController();




        if ($this->controller->isClassExtendedWith(\Backend\Behaviors\RelationController::class)) {
            $this->controller->initRelation(clone $model);
        }

        $this->prepareVars($model);
        $this->model = $model;
    }





    protected function prepareVars($model)
    {
        $this->controller->vars['formModel'] = $model;
        $this->controller->vars['formConfig'] = $this->getConfig();
        $this->controller->vars['formContext'] = $this->formGetContext();
        $this->controller->vars['formController'] = $this;
        $this->controller->vars['formRecordName'] = Lang::get($this->getConfig('name', 'backend::lang.model.name'));
    }











    public function create($context = null)
    {
        try {
            $this->context = strlen($context) ? $context : $this->getConfig('create[context]', self::CONTEXT_CREATE);
            $this->controller->pageTitle = $this->controller->pageTitle ?: $this->getLang(
                "{$this->context}[title]",
                'backend::lang.form.create_title'
            );

            $model = $this->controller->formCreateModelObject();
            $model = $this->controller->formExtendModel($model) ?: $model;

            $this->initForm($model);
        }
        catch (Exception $ex) {
            $this->controller->handleError($ex);
        }
    }











    public function create_onSave($context = null)
    {
        $this->context = strlen($context) ? $context : $this->getConfig('create[context]', self::CONTEXT_CREATE);

        $model = $this->controller->formCreateModelObject();
        $model = $this->controller->formExtendModel($model) ?: $model;

        $this->initForm($model);

        $this->controller->formBeforeSave($model);
        $this->controller->formBeforeCreate($model);

        $modelsToSave = $this->prepareModelsToSave($model, $this->formWidget->getSaveData());
        Db::transaction(function () use ($modelsToSave) {
            foreach ($modelsToSave as $modelToSave) {
                $modelToSave->save(null, $this->formWidget->getSessionKey());
            }
        });

        $this->controller->formAfterSave($model);
        $this->controller->formAfterCreate($model);

        Flash::success($this->getLang("{$this->context}[flashSave]", 'backend::lang.form.create_success'));

        if ($redirect = $this->makeRedirect($this->context, $model)) {
            return $redirect;
        }
    }














    public function update($recordId = null, $context = null)
    {
        try {
            $this->context = strlen($context) ? $context : $this->getConfig('update[context]', self::CONTEXT_UPDATE);
            $this->controller->pageTitle = $this->controller->pageTitle ?: $this->getLang(
                "{$this->context}[title]",
                'backend::lang.form.update_title'
            );

            $model = $this->controller->formFindModelObject($recordId);
            $this->initForm($model);
        }
        catch (Exception $ex) {
            $this->controller->handleError($ex);
        }
    }













    public function update_onSave($recordId = null, $context = null)
    {
        $this->context = strlen($context) ? $context : $this->getConfig('update[context]', self::CONTEXT_UPDATE);
        $model = $this->controller->formFindModelObject($recordId);
        $this->initForm($model);

        $this->controller->formBeforeSave($model);
        $this->controller->formBeforeUpdate($model);

        $modelsToSave = $this->prepareModelsToSave($model, $this->formWidget->getSaveData());
        Db::transaction(function () use ($modelsToSave) {
            foreach ($modelsToSave as $modelToSave) {
                $modelToSave->save(null, $this->formWidget->getSessionKey());
            }
        });

        $this->controller->formAfterSave($model);
        $this->controller->formAfterUpdate($model);

        Flash::success($this->getLang("{$this->context}[flashSave]", 'backend::lang.form.update_success'));

        if ($redirect = $this->makeRedirect($this->context, $model)) {
            return $redirect;
        }
    }













    public function update_onDelete($recordId = null)
    {
        $this->context = $this->getConfig('update[context]', self::CONTEXT_UPDATE);
        $model = $this->controller->formFindModelObject($recordId);
        $this->initForm($model);

        $model->delete();

        $this->controller->formAfterDelete($model);

        Flash::success($this->getLang("{$this->context}[flashDelete]", 'backend::lang.form.delete_success'));

        if ($redirect = $this->makeRedirect('delete', $model)) {
            return $redirect;
        }
    }














    public function preview($recordId = null, $context = null)
    {
        try {
            $this->context = strlen($context) ? $context : $this->getConfig('preview[context]', self::CONTEXT_PREVIEW);
            $this->controller->pageTitle = $this->controller->pageTitle ?: $this->getLang(
                "{$this->context}[title]",
                'backend::lang.form.preview_title'
            );

            $model = $this->controller->formFindModelObject($recordId);
            $this->initForm($model);
        }
        catch (Exception $ex) {
            $this->controller->handleError($ex);
        }
    }





















    public function formRender($options = [])
    {
        if (!$this->formWidget) {
            throw new ApplicationException(Lang::get('backend::lang.form.behavior_not_ready'));
        }

        return $this->formWidget->render($options);
    }








    public function formGetModel()
    {
        return $this->model;
    }








    public function formGetContext()
    {
        return $this->context;
    }






    protected function createModel()
    {
        $class = $this->config->modelClass;
        return new $class;
    }









    public function makeRedirect($context = null, $model = null)
    {
        $redirectUrl = null;
        if (post('close') && !ends_with($context, '-close')) {
            $context .= '-close';
        }

        if (post('refresh', false)) {
            return Redirect::refresh();
        }

        if (post('new', false)) {
            return Redirect::to($this->controller->actionUrl('create'));
        }

        if (post('redirect', true)) {
            $redirectUrl = $this->controller->formGetRedirectUrl($context, $model);
        }

        if ($model && $redirectUrl) {
            $redirectUrl = RouterHelper::replaceParameters($model, $redirectUrl);
        }

        if (starts_with($redirectUrl, 'http://') || starts_with($redirectUrl, 'https://')) {

            $redirect = Redirect::to($redirectUrl);
        } else {

            $redirect = $redirectUrl ? Backend::redirect($redirectUrl) : null;
        }

        return $redirect;
    }










    public function formGetRedirectUrl($context = null, $model = null)
    {
        $redirectContext = explode('-', $context, 2)[0];
        $redirectSource = ends_with($context, '-close') ? 'redirectClose' : 'redirect';


        $redirects = [$context => $this->getConfig("{$redirectContext}[{$redirectSource}]", '')];



        $redirects['default'] = $this->getConfig('defaultRedirect', '');

        if (empty($redirects[$context])) {
            return $redirects['default'];
        }

        return $redirects[$context];
    }









    protected function getLang($name, $default = null, $extras = [])
    {
        $name = $this->getConfig($name, $default);
        $vars = [
            'name' => Lang::get($this->getConfig('name', 'backend::lang.model.name'))
        ];
        $vars = array_merge($vars, $extras);
        return Lang::get($name, $vars);
    }














    public function formRenderField($name, $options = [])
    {
        return $this->formWidget->renderField($name, $options);
    }









    public function formRenderPreview()
    {
        return $this->formRender(['preview' => true]);
    }











    public function formHasOutsideFields()
    {
        return $this->formWidget->getTab('outside')->hasFields();
    }










    public function formRenderOutsideFields()
    {
        return $this->formRender(['section' => 'outside']);
    }











    public function formHasPrimaryTabs()
    {
        return $this->formWidget->getTab('primary')->hasFields();
    }










    public function formRenderPrimaryTabs()
    {
        return $this->formRender(['section' => 'primary']);
    }











    public function formHasSecondaryTabs()
    {
        return $this->formWidget->getTab('secondary')->hasFields();
    }










    public function formRenderSecondaryTabs()
    {
        return $this->formRender(['section' => 'secondary']);
    }






    public function formGetWidget()
    {
        return $this->formWidget;
    }















    public function formGetId($suffix = null)
    {
        return $this->formWidget->getId($suffix);
    }






    public function formGetSessionKey()
    {
        return $this->formWidget->getSessionKey();
    }









    public function formBeforeSave($model)
    {
    }





    public function formAfterSave($model)
    {
    }





    public function formBeforeCreate($model)
    {
    }





    public function formAfterCreate($model)
    {
    }





    public function formBeforeUpdate($model)
    {
    }





    public function formAfterUpdate($model)
    {
    }





    public function formAfterDelete($model)
    {
    }








    public function formFindModelObject($recordId)
    {
        if (!strlen($recordId)) {
            throw new ApplicationException($this->getLang('not-found-message', 'backend::lang.form.missing_id'));
        }

        $model = $this->controller->formCreateModelObject();




        $query = $model->newQuery();
        $this->controller->formExtendQuery($query);
        $result = $query->find($recordId);

        if (!$result) {
            throw new ApplicationException($this->getLang('not-found-message', 'backend::lang.form.not_found', [
                'class' => get_class($model), 'id' => $recordId
            ]));
        }

        $result = $this->controller->formExtendModel($result) ?: $result;

        return $result;
    }






    public function formCreateModelObject()
    {
        return $this->createModel();
    }






    public function formExtendFieldsBefore($host)
    {
    }







    public function formExtendFields($host, $fields)
    {
    }







    public function formExtendRefreshData($host, $saveData)
    {
    }







    public function formExtendRefreshFields($host, $fields)
    {
    }







    public function formExtendRefreshResults($host, $result)
    {
    }







    public function formExtendModel($model)
    {
    }







    public function formExtendQuery($query)
    {
    }






    public static function extendFormFields($callback)
    {
        $calledClass = self::getCalledExtensionClass();
        Event::listen('backend.form.extendFields', function ($widget) use ($calledClass, $callback) {
            if (!is_a($widget->getController(), $calledClass)) {
                return;
            }
            call_user_func_array($callback, [$widget, $widget->model, $widget->getContext()]);
        });
    }




    public function formMakePartial(string $partial, array $params = []): string
    {
        $contents = $this->controller->makePartial('form_' . $this->context . '_' . $partial, $params + $this->vars, false);
        if (!$contents) {
            $contents = $this->controller->makePartial('form_' . $partial, $params + $this->vars, false);
        }
        if (!$contents) {
            $contents = $this->makePartial($partial, $params);
        }

        return $contents;
    }
}
