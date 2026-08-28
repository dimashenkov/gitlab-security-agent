<?php namespace Backend\Behaviors;

use Db;
use Lang;
use Request;
use Form as FormHelper;
use Backend\Classes\ControllerBehavior;
use Winter\Storm\Database\Model;
use Winter\Storm\Database\Models\DeferredBinding;
use ApplicationException;



















class RelationController extends ControllerBehavior
{
    use \Backend\Traits\FormModelSaver;




    const PARAM_FIELD = '_relation_field';




    const PARAM_MODE = '_relation_mode';




    const PARAM_EXTRA_CONFIG = '_relation_extra_config';




    protected $searchWidget;




    protected $toolbarWidget;




    protected $viewWidget;




    protected $viewFilterWidget;




    protected $manageWidget;




    protected $manageFilterWidget;




    protected $pivotWidget;




    protected $requiredRelationProperties = ['label'];




    protected $requiredConfig = [];




    protected $actions = [];




    protected $originalConfig;




    protected $extraConfig;




    protected $initialized = false;




    public $relationType;




    public $relationName;




    public $relationModel;




    public $relationObject;




    protected $model;




    protected $field;




    protected $alias;




    protected $toolbarButtons;




    protected $viewModel;




    protected $viewMode;




    protected $manageTitle;




    protected $manageMode;




    protected $forceViewMode;




    protected $forceManageMode;




    protected $eventTarget;




    protected $manageId;




    protected $foreignId;




    public $relationConfig = 'config_relation.yaml';




    public $sessionKey;




    public $readOnly = false;




    public $deferredBinding = false;





    public function __construct($controller)
    {
        parent::__construct($controller);

        $this->addJs('js/winter.relation.js', 'core');
        $this->addCss('css/relation.css', 'core');




        $this->config = $this->originalConfig = $this->makeConfig($controller->relationConfig ?: $this->relationConfig, $this->requiredConfig);
    }






    protected function validateField($field = null)
    {
        $field = $field ?: post(self::PARAM_FIELD);

        if ($field && $field != $this->field) {
            $this->initRelation($this->model, $field);
        }

        if (!$field && !$this->field) {
            throw new ApplicationException(Lang::get('backend::lang.relation.missing_definition', compact('field')));
        }

        return $field ?: $this->field;
    }





    public function prepareVars()
    {
        $this->vars['relationManageId'] = $this->manageId;
        $this->vars['relationLabel'] = $this->config->label ?: $this->field;
        $this->vars['relationManageTitle'] = $this->manageTitle;
        $this->vars['relationField'] = $this->field;
        $this->vars['relationType'] = $this->relationType;
        $this->vars['relationSearchWidget'] = $this->searchWidget;
        $this->vars['relationManageFilterWidget'] = $this->manageFilterWidget;
        $this->vars['relationViewFilterWidget'] = $this->viewFilterWidget;
        $this->vars['relationToolbarWidget'] = $this->toolbarWidget;
        $this->vars['relationManageMode'] = $this->manageMode;
        $this->vars['relationManageWidget'] = $this->manageWidget;
        $this->vars['relationToolbarButtons'] = $this->toolbarButtons;
        $this->vars['relationViewMode'] = $this->viewMode;
        $this->vars['relationViewWidget'] = $this->viewWidget;
        $this->vars['relationViewModel'] = $this->viewModel;
        $this->vars['relationPivotWidget'] = $this->pivotWidget;
        $this->vars['relationSessionKey'] = $this->relationGetSessionKey();
        $this->vars['relationExtraConfig'] = $this->extraConfig;
    }






    protected function beforeAjax()
    {
        if ($this->initialized) {
            return;
        }

        $this->controller->pageAction();
        if ($fatalError = $this->controller->getFatalError()) {
            throw new ApplicationException($fatalError);
        }

        $this->validateField();
        $this->prepareVars();
        $this->initialized = true;
    }











    public function initRelation($model, $field = null)
    {
        if ($field == null) {
            $field = post(self::PARAM_FIELD);
        }

        $this->config = $this->originalConfig;
        $this->model = $model;
        $this->field = $field;

        if ($field == null) {
            return;
        }

        if (!$this->model) {
            throw new ApplicationException(Lang::get('backend::lang.relation.missing_model', [
                'class' => get_class($this->controller),
            ]));
        }

        if (!$this->model instanceof Model) {
            throw new ApplicationException(Lang::get('backend::lang.model.invalid_class', [
                'model' => get_class($this->model),
                'class' => get_class($this->controller),
            ]));
        }

        if (!$this->getConfig($field)) {
            throw new ApplicationException(Lang::get('backend::lang.relation.missing_definition', compact('field')));
        }

        if ($extraConfig = post(self::PARAM_EXTRA_CONFIG)) {
            $this->applyExtraConfig($extraConfig);
        }

        $this->alias = camel_case('relation ' . $field);
        $this->config = $this->makeConfig($this->getConfig($field), $this->requiredRelationProperties);
        $this->controller->relationExtendConfig($this->config, $this->field, $this->model);




        $this->relationName = $field;
        $this->relationType = $this->model->getRelationType($field);
        $this->relationObject = $this->model->{$field}();
        $this->relationModel = $this->relationObject->getRelated();

        $this->manageId = post('manage_id');
        $this->foreignId = post('foreign_id');
        $this->readOnly = $this->getConfig('readOnly');
        $this->deferredBinding = $this->getConfig('deferredBinding') || !$this->model->exists;
        $this->viewMode = $this->evalViewMode();
        $this->manageMode = $this->evalManageMode();
        $this->manageTitle = $this->evalManageTitle();
        $this->toolbarButtons = $this->evalToolbarButtons();




        if ($this->toolbarWidget = $this->makeToolbarWidget()) {
            $this->toolbarWidget->bindToController();
        }




        if ($this->searchWidget = $this->makeSearchWidget()) {
            $this->searchWidget->bindToController();
        }




        if ($this->manageFilterWidget = $this->makeFilterWidget('manage')) {
            $this->controller->relationExtendManageFilterWidget($this->manageFilterWidget, $this->field, $this->model);
            $this->manageFilterWidget->bindToController();
        }

        if ($this->viewFilterWidget = $this->makeFilterWidget('view')) {
            $this->controller->relationExtendViewFilterWidget($this->viewFilterWidget, $this->field, $this->model);
            $this->viewFilterWidget->bindToController();
        }




        if ($this->viewWidget = $this->makeViewWidget()) {
            $this->controller->relationExtendViewWidget($this->viewWidget, $this->field, $this->model);
            $this->viewWidget->bindToController();
        }




        if ($this->manageWidget = $this->makeManageWidget()) {
            $this->controller->relationExtendManageWidget($this->manageWidget, $this->field, $this->model);
            $this->manageWidget->bindToController();
        }




        if ($this->manageMode === 'pivot' && $this->pivotWidget = $this->makePivotWidget()) {
            $this->controller->relationExtendPivotWidget($this->pivotWidget, $this->field, $this->model);
            $this->pivotWidget->bindToController();
        }
    }







    public function relationRender($field, $options = [])
    {



        if (is_string($options)) {
            $options = ['sessionKey' => $options];
        }

        if (isset($options['sessionKey'])) {
            $this->sessionKey = $options['sessionKey'];
        }




        $allowConfig = ['readOnly', 'recordUrl', 'recordOnClick'];
        $extraConfig = array_only($options, $allowConfig);
        $this->extraConfig = $extraConfig;
        $this->applyExtraConfig($extraConfig, $field);




        $this->validateField($field);
        $this->prepareVars();




        $section = $options['section'] ?? null;
        switch (strtolower($section)) {
            case 'toolbar':
                return $this->toolbarWidget ? $this->toolbarWidget->render() : null;

            case 'view':
                return $this->relationMakePartial('view');

            default:
                return $this->relationMakePartial('container');
        }
    }






    public function relationRefresh($field = null)
    {
        $field = $this->validateField($field);

        $result = ['#'.$this->relationGetId('view') => $this->relationRenderView($field)];
        if ($toolbar = $this->relationRenderToolbar($field)) {
            $result['#'.$this->relationGetId('toolbar')] = $toolbar;
        }

        if ($eventResult = $this->controller->relationExtendRefreshResults($field)) {
            $result = $eventResult + $result;
        }

        return $result;
    }






    public function relationRenderToolbar($field = null)
    {
        return $this->relationRender($field, ['section' => 'toolbar']);
    }






    public function relationRenderView($field = null)
    {
        return $this->relationRender($field, ['section' => 'view']);
    }







    public function relationMakePartial($partial, $params = [])
    {
        $contents = $this->controller->makePartial('relation_'.$partial, $params + $this->vars, false);
        if (!$contents) {
            $contents = $this->makePartial($partial, $params);
        }

        return $contents;
    }






    public function relationGetId($suffix = null)
    {
        $id = class_basename($this);
        if ($this->field) {
            $id .= '-' . $this->field;
        }

        if ($suffix !== null) {
            $id .= '-' . $suffix;
        }

        return $this->controller->getId($id);
    }




    public function relationGetSessionKey($force = false)
    {
        if ($this->sessionKey && !$force) {
            return $this->sessionKey;
        }

        if (post('_relation_session_key')) {
            return $this->sessionKey = post('_relation_session_key');
        }

        if (post('_session_key')) {
            return $this->sessionKey = post('_session_key');
        }

        return $this->sessionKey = FormHelper::getSessionKey();
    }












    protected function applyDeferredRelationOrder($records)
    {
        if (!$this->deferredBinding || !$this->model->isSortableRelation($this->relationName)) {
            return $records;
        }

        $column = $this->model->getRelationSortOrderColumn($this->relationName);
        $sessionKey = $this->relationGetSessionKey();
        $map = [];




        if ($this->model->exists) {
            $relation = $this->model->{$this->relationName}();
            $query = Db::table($relation->getTable())
                ->where($relation->getForeignPivotKeyName(), $this->model->getKey());


            if (method_exists($relation, 'getMorphType') && method_exists($relation, 'getMorphClass')) {
                $query->where($relation->getMorphType(), $relation->getMorphClass());
            }

            $map = $query
                ->pluck($column, $relation->getRelatedPivotKeyName())
                ->map(function ($value) {
                    return (int) $value;
                })
                ->all();
        }




        $bindings = DeferredBinding::where('master_type', get_class($this->model))
            ->where('master_field', $this->relationName)
            ->where('session_key', $sessionKey)
            ->where('is_bind', 1)
            ->get();

        foreach ($bindings as $binding) {
            $pivotData = $binding->pivot_data ?: [];
            if (array_key_exists($column, $pivotData)) {
                $map[$binding->slave_id] = (int) $pivotData[$column];
            }
        }

        foreach ($records as $record) {
            if (array_key_exists($record->getKey(), $map)) {
                $record->pivot->{$column} = $map[$record->getKey()];
            }
        }

        return $records->sortBy(function ($record) use ($column) {

            return $record->pivot->{$column} ?? PHP_INT_MAX;
        })->values();
    }











    protected function makeFilterWidget($type)
    {
        if (!$this->getConfig($type . '[filter]')) {
            return null;
        }

        $filterConfig = $this->makeConfig($this->getConfig($type . '[filter]'));
        $filterConfig->alias = $this->alias . ucfirst($type) . 'Filter';
        $filterWidget = $this->makeWidget('Backend\Widgets\Filter', $filterConfig);

        return $filterWidget;
    }


    protected function makeToolbarWidget()
    {
        $defaultConfig = [];




        $defaultButtons = null;

        if (!$this->readOnly && $this->toolbarButtons) {
            $defaultButtons = '~/modules/backend/behaviors/relationcontroller/partials/_toolbar.php';
        }

        $defaultConfig['buttons'] = $this->getConfig('view[toolbarPartial]', $defaultButtons);




        $toolbarConfig = $this->makeConfig($this->getConfig('toolbar', $defaultConfig));
        $toolbarConfig->alias = $this->alias . 'Toolbar';




        $useSearch = $this->viewMode === 'multi' && $this->getConfig('view[showSearch]');

        if ($useSearch) {
            $toolbarConfig->search = $this->getSearchConfig('view[search]');
        }




        if (empty($toolbarConfig->search) && empty($toolbarConfig->buttons)) {
            return;
        }

        $toolbarWidget = $this->makeWidget('Backend\Widgets\Toolbar', $toolbarConfig);
        $toolbarWidget->cssClasses[] = 'list-header';

        return $toolbarWidget;
    }

    protected function getSearchConfig($key)
    {
        $config = $this->getConfig($key);
        $searchConfig = $this->makeConfig();

        $searchConfig->prompt = array_get($config, 'prompt', 'backend::lang.list.search_prompt');
        $searchConfig->mode = array_get($config, 'mode', 'all');
        $searchConfig->scope = array_get($config, 'scope');
        $searchConfig->searchOnEnter = array_get($config, 'searchOnEnter', false);

        return $searchConfig;
    }

    protected function makeSearchWidget()
    {
        if (!$this->getConfig('manage[showSearch]')) {
            return null;
        }

        $config = $this->getSearchConfig('manage[search]');
        $config->alias = $this->alias . 'ManageSearch';
        $config->growable = false;

        $widget = $this->makeWidget('Backend\Widgets\Search', $config);
        $widget->cssClasses[] = 'recordfinder-search';




        if (!Request::ajax()) {
            $widget->setActiveTerm(null);
        }

        return $widget;
    }

    protected function makeViewWidget()
    {
        $widget = null;




        if ($this->viewMode === 'multi') {
            $config = $this->makeConfigForMode('view', 'list');
            $config->model = $this->relationModel;
            $config->alias = $this->alias . 'ViewList';
            $config->showSetup = $this->getConfig('view[showSetup]', true);
            $config->showSorting = $this->getConfig('view[showSorting]', true);
            $config->defaultSort = $this->getConfig('view[defaultSort]');
            $config->recordsPerPage = $this->getConfig('view[recordsPerPage]');
            $config->showPageNumbers = $this->getConfig('view[showPageNumbers]', true);
            $config->showCheckboxes = $this->getConfig('view[showCheckboxes]', !$this->readOnly);
            $config->recordUrl = $this->getConfig('view[recordUrl]');
            $config->customViewPath = $this->getConfig('view[customViewPath]');
            $config->noRecordsMessage = $this->getConfig('view[noRecordsMessage]');

            $defaultOnClick = sprintf(
                "$.wn.relationBehavior.clickViewListRecord(':%s', '%s', '%s')",
                $this->relationModel->getKeyName(),
                $this->relationGetId(),
                $this->relationGetSessionKey()
            );

            if ($config->recordUrl) {
                $defaultOnClick = null;
            }
            elseif (
                !$this->makeConfigForMode('manage', 'form', false) &&
                !$this->makeConfigForMode('pivot', 'form', false)
            ) {
                $defaultOnClick = null;
            }

            $config->recordOnClick = $this->getConfig('view[recordOnClick]', $defaultOnClick);

            if ($emptyMessage = $this->getConfig('emptyMessage')) {
                $config->noRecordsMessage = $emptyMessage;
            }





            $sortable = $this->getConfig('view[sortable]', false);
            if ($sortable) {
                if (
                    !in_array(\Winter\Storm\Database\Traits\HasSortableRelations::class, class_uses_recursive($this->model))
                    || !$this->model->isSortableRelation($this->relationName)
                ) {
                    throw new ApplicationException(sprintf(
                        'To use "sortable" on the "%s" relation, the model "%s" must use the %s trait and declare the relation in $sortableRelations.',
                        $this->relationName,
                        get_class($this->model),
                        \Winter\Storm\Database\Traits\HasSortableRelations::class
                    ));
                }






                $conflicts = array_keys(array_filter([
                    'showSearch'     => $this->getConfig('view[showSearch]'),
                    'filter'         => $this->getConfig('view[filter]'),
                    'recordsPerPage' => $this->getConfig('view[recordsPerPage]'),
                    'defaultSort'    => $this->getConfig('view[defaultSort]'),
                ]));
                if ($conflicts) {
                    throw new ApplicationException(sprintf(
                        'The "%s" relation cannot combine "sortable" with: %s. Drag-and-drop reordering requires the whole relation in a fixed order. Remove these options, or use the ReorderController for a dedicated reordering page.',
                        $this->relationName,
                        implode(', ', $conflicts)
                    ));
                }

                $config->sortable = true;
            }

            $widget = $this->makeWidget('Backend\Widgets\Lists', $config);




            if ($sortable) {
                $widget->bindEvent('list.reorder', function ($ids, $orders) {
                    $sessionKey = $this->deferredBinding ? $this->relationGetSessionKey() : null;
                    $this->model->setRelationOrder($this->relationName, $ids, $orders, $sessionKey);
                });

                $widget->bindEvent('list.extendRecords', function ($records) {
                    return $this->applyDeferredRelationOrder($records);
                });
            }




            if ($sqlConditions = $this->getConfig('view[conditions]')) {
                $widget->bindEvent('list.extendQueryBefore', function ($query) use ($sqlConditions) {
                    $query->whereRaw($sqlConditions);
                });
            }
            elseif ($scopeMethod = $this->getConfig('view[scope]')) {
                $widget->bindEvent('list.extendQueryBefore', function ($query) use ($scopeMethod) {
                    $query->$scopeMethod($this->model);
                });
            }
            else {
                $widget->bindEvent('list.extendQueryBefore', function ($query) use ($widget) {
                    $this->relationObject->addDefinedConstraintsToQuery($query);
                    if ($widget->getSortColumn()) {
                        $query->getQuery()->orders = [];
                    }
                });
            }




            $widget->bindEvent('list.extendQuery', function ($query) {
                $this->relationObject->setQuery($query);

                $sessionKey = $this->deferredBinding ? $this->relationGetSessionKey() : null;

                if ($sessionKey) {
                    $this->relationObject->withDeferred($sessionKey);
                }
                elseif ($this->model->exists) {
                    $this->relationObject->addConstraints();
                }




                if ($this->relationType === 'belongsToMany'
                    || $this->relationType === 'morphToMany'
                    || $this->relationType === 'morphedByMany'
                ) {
                    $this->relationObject->setQuery($query->getQuery());






                    if ($sessionKey && $this->getConfig('view[sortable]', false)) {
                        $query->reorder();
                        $this->relationObject->reorder();
                    }

                    return $this->relationObject;
                }
            });




            if ($this->toolbarWidget && $this->getConfig('view[showSearch]')
                && $searchWidget = $this->toolbarWidget->getSearchWidget()
            ) {
                $searchWidget->bindEvent('search.submit', function () use ($widget, $searchWidget) {
                    $widget->setSearchTerm($searchWidget->getActiveTerm());
                    return $widget->onRefresh();
                });

                $widget->setSearchOptions([
                    'mode' => $searchWidget->mode,
                    'scope' => $searchWidget->scope,
                ]);




                if (Request::ajax()) {
                    $widget->setSearchTerm($searchWidget->getActiveTerm());
                }
                else {
                    $searchWidget->setActiveTerm(null);
                }
            }




            if ($this->viewFilterWidget) {
                $this->viewFilterWidget->bindEvent('filter.update', function () use ($widget) {
                    return $widget->onFilter();
                });


                $widget->addFilter([$this->viewFilterWidget, 'applyAllScopesToQuery']);
            }
        }



        elseif ($this->viewMode === 'single') {
            $this->viewModel = $this->relationObject->getResults()
                ?: $this->relationModel;

            $config = $this->makeConfigForMode('view', 'form');
            $config->model = $this->viewModel;
            $config->arrayName = class_basename($this->relationModel);
            $config->context = 'relation';
            $config->alias = $this->alias . 'ViewForm';

            $widget = $this->makeWidget('Backend\Widgets\Form', $config);
            $widget->previewMode = true;
        }

        return $widget;
    }

    protected function makeManageWidget()
    {
        $widget = null;




        if ($this->manageMode === 'list' || $this->manageMode === 'pivot') {
            $isPivot = $this->manageMode === 'pivot';

            $config = $this->makeConfigForMode('manage', 'list');
            $config->model = $this->relationModel;
            $config->alias = $this->alias . 'ManageList';
            $config->showSetup = $this->getConfig('manage[showSetup]', !$isPivot);
            $config->showCheckboxes = $this->getConfig('manage[showCheckboxes]', !$isPivot);
            $config->showSorting = $this->getConfig('manage[showSorting]', !$isPivot);
            $config->defaultSort = $this->getConfig('manage[defaultSort]');
            $config->recordsPerPage = $this->getConfig('manage[recordsPerPage]');
            $config->showPageNumbers = $this->getConfig('manage[showPageNumbers]', true);
            $config->noRecordsMessage = $this->getConfig('manage[noRecordsMessage]');

            if ($this->viewMode === 'single') {
                $config->showCheckboxes = false;
                $config->recordOnClick = sprintf(
                    "$.wn.relationBehavior.clickManageListRecord(':%s', '%s', '%s')",
                    $this->relationModel->getKeyName(),
                    $this->relationGetId(),
                    $this->relationGetSessionKey()
                );
            }
            elseif ($config->showCheckboxes) {
                $config->recordOnClick = "$.wn.relationBehavior.toggleListCheckbox(this)";
            }
            elseif ($isPivot) {
                $config->recordOnClick = sprintf(
                    "$.wn.relationBehavior.clickManagePivotListRecord(':%s', '%s', '%s')",
                    $this->relationModel->getKeyName(),
                    $this->relationGetId(),
                    $this->relationGetSessionKey()
                );
            }

            $widget = $this->makeWidget('Backend\Widgets\Lists', $config);




            if ($sqlConditions = $this->getConfig('manage[conditions]')) {
                $widget->bindEvent('list.extendQueryBefore', function ($query) use ($sqlConditions) {
                    $query->whereRaw($sqlConditions);
                });
            }
            elseif ($scopeMethod = $this->getConfig('manage[scope]')) {
                $widget->bindEvent('list.extendQueryBefore', function ($query) use ($scopeMethod) {
                    $query->$scopeMethod($this->model);
                });
            }
            else {
                $widget->bindEvent('list.extendQueryBefore', function ($query) use ($widget) {
                    $this->relationObject->addDefinedConstraintsToQuery($query);
                    if ($widget->getSortColumn()) {
                        $query->getQuery()->orders = [];
                    }
                });
            }




            if ($this->searchWidget) {
                $this->searchWidget->bindEvent('search.submit', function () use ($widget) {
                    $widget->setSearchTerm($this->searchWidget->getActiveTerm());
                    return $widget->onRefresh();
                });

                $widget->setSearchOptions([
                    'mode' => $this->searchWidget->mode,
                    'scope' => $this->searchWidget->scope,
                ]);




                if (Request::ajax()) {
                    $widget->setSearchTerm($this->searchWidget->getActiveTerm());
                }
            }




            if ($this->manageFilterWidget) {
                $this->manageFilterWidget->bindEvent('filter.update', function () use ($widget) {
                    return $widget->onFilter();
                });


                $widget->addFilter([$this->manageFilterWidget, 'applyAllScopesToQuery']);
            }
        }



        elseif ($this->manageMode === 'form') {
            if (!$config = $this->makeConfigForMode('manage', 'form', false)) {
                return null;
            }

            $config->model = $this->relationModel;
            $config->arrayName = class_basename($this->relationModel);
            $config->context = $this->evalFormContext('manage', !!$this->manageId);
            $config->alias = $this->alias . 'ManageForm';




            if ($this->manageId) {
                $model = $config->model->find($this->manageId);
                if ($model) {
                    $config->model = $model;
                } else {
                    throw new ApplicationException(Lang::get('backend::lang.model.not_found', [
                        'class' => get_class($config->model),
                        'id' => $this->manageId,
                    ]));
                }
            }

            $widget = $this->makeWidget('Backend\Widgets\Form', $config);
        }

        if (!$widget) {
            return null;
        }




        if ($this->manageMode === 'pivot' || $this->manageMode === 'list') {
            $widget->bindEvent('list.extendQuery', function ($query) {



                $existingIds = $this->findExistingRelationIds();
                if (count($existingIds)) {
                    $query->whereNotIn($this->relationModel->getQualifiedKeyName(), $existingIds);
                }
            });
        }

        return $widget;
    }

    protected function makePivotWidget()
    {
        $config = $this->makeConfigForMode('pivot', 'form');
        $config->model = $this->relationModel;
        $config->arrayName = class_basename($this->relationModel);
        $config->context = $this->evalFormContext('pivot', !!$this->manageId);
        $config->alias = $this->alias . 'ManagePivotForm';

        $foreignKeyName = $this->relationModel->getQualifiedKeyName();




        if ($this->manageId) {
            $hydratedModel = $this->relationObject->where($foreignKeyName, $this->manageId)->first();

            if ($hydratedModel) {
                $config->model = $hydratedModel;
            } else {
                throw new ApplicationException(Lang::get('backend::lang.model.not_found', [
                    'class' => get_class($config->model),
                    'id' => $this->manageId,
                ]));
            }
        }



        else {
            if ($this->foreignId) {
                $foreignModel = $this->relationModel
                    ->whereIn($foreignKeyName, (array) $this->foreignId)
                    ->first();

                if ($foreignModel) {
                    $foreignModel->exists = false;
                    $config->model = $foreignModel;
                }
            }

            $pivotModel = $this->relationObject->newPivot();
            $config->model->setRelation('pivot', $pivotModel);
        }

        return $this->makeWidget('Backend\Widgets\Form', $config);
    }





    public function onRelationButtonAdd()
    {
        $this->eventTarget = 'button-add';

        return $this->onRelationManageForm();
    }

    public function onRelationButtonCreate()
    {
        $this->eventTarget = 'button-create';

        return $this->onRelationManageForm();
    }

    public function onRelationButtonDelete()
    {
        return $this->onRelationManageDelete();
    }

    public function onRelationButtonLink()
    {
        $this->eventTarget = 'button-link';

        return $this->onRelationManageForm();
    }

    public function onRelationButtonRefresh()
    {
        $this->beforeAjax();
        return $this->relationRefresh();
    }

    public function onRelationButtonUnlink()
    {
        return $this->onRelationManageRemove();
    }

    public function onRelationButtonRemove()
    {
        return $this->onRelationManageRemove();
    }

    public function onRelationButtonUpdate()
    {
        $this->eventTarget = 'button-update';

        return $this->onRelationManageForm();
    }





    public function onRelationClickManageList()
    {
        return $this->onRelationManageAdd();
    }

    public function onRelationClickManageListPivot()
    {
        return $this->onRelationManagePivotForm();
    }

    public function onRelationClickViewList()
    {
        $this->eventTarget = 'list';
        return $this->onRelationManageForm();
    }





    public function onRelationManageForm()
    {
        $this->beforeAjax();

        if ($this->manageMode === 'pivot' && $this->manageId) {
            return $this->onRelationManagePivotForm();
        }


        $this->vars['newSessionKey'] = str_random(40);

        $view = 'manage_' . $this->manageMode;

        return $this->relationMakePartial($view);
    }




    public function onRelationManageCreate()
    {
        $this->forceManageMode = 'form';
        $this->beforeAjax();
        $saveData = $this->manageWidget->getSaveData();
        $sessionKey = $this->deferredBinding ? $this->relationGetSessionKey(true) : null;

        if ($this->viewMode === 'multi') {
            $newModel = $this->relationModel;






            if (in_array($this->relationType, ['hasOne', 'hasMany'])) {
                $newModel->setAttribute(
                    $this->relationObject->getForeignKeyName(),
                    $this->relationObject->getParentKey()
                );
            }


            $isPivot = false;
            if (
                in_array($this->relationType, ['belongsToMany', 'morphToMany', 'morphedByMany'])
                && !empty($saveData['pivot'])
            ) {
                $isPivot = true;
                $pivotModel = $this->relationObject->newPivot();
                $newModel->setRelation('pivot', $pivotModel);
            }

            $modelsToSave = $this->prepareModelsToSave($newModel, $saveData);

            foreach ($modelsToSave as $modelToSave) {
                if ($modelToSave instanceof \Winter\Storm\Database\Pivot) {
                    $pivotData = $modelToSave->getAttributes();
                    continue;
                }

                $modelToSave->save(null, $this->manageWidget->getSessionKey());
            }

            if ($isPivot && !empty($pivotData)) {
                $this->relationObject->add($newModel, $sessionKey, $pivotData);
            } else {
                $this->relationObject->add($newModel, $sessionKey);
            }
        } elseif ($this->viewMode === 'single') {
            $newModel = $this->viewModel = $this->viewWidget->model = $this->manageWidget->model;
            $this->viewWidget->setFormValues($saveData);




            if ($this->deferredBinding || $this->relationType != 'hasOne') {
                $newModel->save(null, $this->manageWidget->getSessionKey());
            }

            if ($this->relationType === 'hasOne') {

                $relation = $this->relationObject->getParent()->{$this->relationName} ?? null;

                if ($relation) {
                    $this->relationObject->remove($relation, $sessionKey);
                }
            }

            $this->relationObject->add($newModel, $sessionKey);





            if (!$this->deferredBinding && $this->relationType === 'belongsTo') {
                $parentModel = $this->relationObject->getParent();
                if ($parentModel->exists) {
                    $parentModel->save();
                }
            }
        }

        return $this->relationRefresh();
    }




    public function onRelationManageUpdate()
    {
        $this->forceManageMode = 'form';
        $this->beforeAjax();
        $saveData = $this->manageWidget->getSaveData();

        if ($this->viewMode === 'multi') {
            $model = $this->manageWidget->model;
            $modelsToSave = $this->prepareModelsToSave($model, $saveData);
            foreach ($modelsToSave as $modelToSave) {
                $modelToSave->save(null, $this->manageWidget->getSessionKey());
            }
        }
        elseif ($this->viewMode === 'single') {




            $this->viewModel = $this->viewWidget->model = $this->manageWidget->model;

            $this->viewWidget->setFormValues($saveData);
            $this->viewModel->save(null, $this->manageWidget->getSessionKey());
        }

        return $this->relationRefresh();
    }




    public function onRelationManageDelete()
    {
        $this->beforeAjax();




        if ($this->viewMode === 'multi') {
            if (($checkedIds = post('checked')) && is_array($checkedIds)) {
                foreach ($checkedIds as $relationId) {
                    if (!$obj = $this->relationModel->find($relationId)) {
                        continue;
                    }

                    $obj->delete();
                }
            }
        }



        elseif ($this->viewMode === 'single') {
            $relatedModel = $this->viewModel;
            if ($relatedModel->exists) {
                $relatedModel->delete();
            }


            $this->initRelation($this->model);

            $this->viewWidget->setFormValues([]);
            $this->viewModel = $this->relationModel;
        }

        return $this->relationRefresh();
    }




    public function onRelationManageAdd()
    {
        $this->beforeAjax();

        $recordId = post('record_id');
        $sessionKey = $this->deferredBinding ? $this->relationGetSessionKey() : null;




        if ($this->viewMode === 'multi') {
            $checkedIds = $recordId ? [$recordId] : post('checked');

            if (is_array($checkedIds)) {



                $existingIds = $this->findExistingRelationIds($checkedIds);
                $checkedIds = array_diff($checkedIds, $existingIds);
                $foreignKeyName = $this->relationModel->getKeyName();

                $models = $this->relationModel->whereIn($foreignKeyName, $checkedIds)->get();
                foreach ($models as $model) {
                    $this->relationObject->add($model, $sessionKey);
                }
            }
        }



        elseif ($this->viewMode === 'single') {
            if ($recordId && ($model = $this->relationModel->find($recordId))) {
                if ($this->relationType === 'hasOne') {

                    $relation = $this->relationObject->getParent()->{$this->relationName} ?? null;

                    if ($relation) {
                        $this->relationObject->remove($relation, $sessionKey);
                    }
                }

                $this->relationObject->add($model, $sessionKey);
                $this->viewWidget->setFormValues($model->attributes);





                if (!$this->deferredBinding && $this->relationType === 'belongsTo') {
                    $parentModel = $this->relationObject->getParent();
                    if ($parentModel->exists) {
                        $parentModel->save();
                    }
                }
            }
        }

        return $this->relationRefresh();
    }




    public function onRelationManageRemove()
    {
        $this->beforeAjax();

        $recordId = post('record_id');
        $sessionKey = $this->deferredBinding ? $this->relationGetSessionKey() : null;
        $relatedModel = $this->relationModel;




        if ($this->viewMode === 'multi') {
            $checkedIds = $recordId ? [$recordId] : post('checked');

            if (is_array($checkedIds)) {
                $foreignKeyName = $relatedModel->getKeyName();

                $models = $relatedModel->whereIn($foreignKeyName, $checkedIds)->get();
                foreach ($models as $model) {
                    $this->relationObject->remove($model, $sessionKey);
                }
            }
        }



        elseif ($this->viewMode === 'single') {
            if ($this->relationType === 'belongsTo') {
                $this->relationObject->dissociate();
                $this->relationObject->getParent()->save();


                if (is_null($sessionKey)) {
                    $this->model->refresh();
                    $this->initRelation($this->model);
                }
            }
            elseif ($this->relationType === 'hasOne' || $this->relationType === 'morphOne') {
                if ($obj = $relatedModel->find($recordId)) {
                    $this->relationObject->remove($obj, $sessionKey);
                }
                elseif ($this->viewModel->exists) {
                    $this->relationObject->remove($this->viewModel, $sessionKey);
                }
            }


            $this->initRelation($this->model);

            $this->viewWidget->setFormValues([]);
            $this->viewModel = $this->relationModel;
        }

        return $this->relationRefresh();
    }




    public function onRelationManageAddPivot()
    {
        return $this->onRelationManagePivotForm();
    }

    public function onRelationManagePivotForm()
    {
        $this->beforeAjax();

        $this->vars['foreignId'] = $this->foreignId ?: post('checked');

        return $this->relationMakePartial('pivot_form');
    }

    public function onRelationManagePivotCreate()
    {
        $this->beforeAjax();




        Db::transaction(function () {



            $foreignIds = (array) $this->foreignId;
            $saveData = $this->pivotWidget->getSaveData();
            $foreignModels = $this->relationModel->whereIn($this->relationModel->getKeyName(), $foreignIds)->get();
            $this->relationObject->syncWithPivotValues($foreignModels, $saveData['pivot'] ?? [], false);




            $foreignKeyName = $this->relationModel->getQualifiedKeyName();
            $hydratedModels = $this->relationObject->whereIn($foreignKeyName, $foreignIds)->get();

            foreach ($hydratedModels as $hydratedModel) {
                $modelsToSave = $this->prepareModelsToSave($hydratedModel, $saveData);
                foreach ($modelsToSave as $modelToSave) {
                    $modelToSave->save(null, $this->pivotWidget->getSessionKey());
                }
            }
        });

        return ['#'.$this->relationGetId('view') => $this->relationRenderView()];
    }

    public function onRelationManagePivotUpdate()
    {
        $this->beforeAjax();

        $hydratedModel = $this->pivotWidget->model;
        $saveData = $this->pivotWidget->getSaveData();




        Db::transaction(function () use ($hydratedModel, $saveData) {
            $modelsToSave = $this->prepareModelsToSave($hydratedModel, $saveData);
            foreach ($modelsToSave as $modelToSave) {
                $modelToSave->save(null, $this->pivotWidget->getSessionKey());
            }
        });

        return ['#'.$this->relationGetId('view') => $this->relationRenderView()];
    }











    public function relationExtendConfig($config, $field, $model)
    {
    }







    public function relationExtendViewWidget($widget, $field, $model)
    {
    }







    public function relationExtendManageWidget($widget, $field, $model)
    {
    }







    public function relationExtendPivotWidget($widget, $field, $model)
    {
    }







    public function relationExtendManageFilterWidget($widget, $field, $model)
    {
    }







    public function relationExtendViewFilterWidget($widget, $field, $model)
    {
    }











    public function relationExtendRefreshResults($field)
    {
    }








    protected function findExistingRelationIds($checkIds = null)
    {
        $foreignKeyName = $this->relationModel->getQualifiedKeyName();

        $results = $this->relationObject
            ->getBaseQuery()
            ->select($foreignKeyName);

        if ($checkIds !== null && is_array($checkIds) && count($checkIds)) {
            $results = $results->whereIn($foreignKeyName, $checkIds);
        }

        return $results->lists($foreignKeyName);
    }





    protected function evalToolbarButtons()
    {
        $buttons = $this->getConfig('view[toolbarButtons]');

        if (!is_array($buttons)) {
            if ($buttons === false) {
                return null;
            } elseif (is_string($buttons)) {
                $buttons = array_map('trim', explode('|', $buttons));
            } elseif ($this->manageMode === 'pivot') {
                $buttons = ['add', 'remove'];
            } else {
                switch ($this->relationType) {
                    case 'hasMany':
                    case 'morphMany':
                    case 'morphToMany':
                    case 'morphedByMany':
                    case 'belongsToMany':
                        $buttons = ['create', 'add', 'delete', 'remove'];
                        break;

                    case 'hasOne':
                    case 'morphOne':
                    case 'belongsTo':
                        $buttons = ['create', 'update', 'link', 'delete', 'unlink'];
                        break;
                }
            }
        }

        $buttonText = [];

        foreach ($buttons as $type => $text) {
            if (is_numeric($type) || !$text) {
                if (is_numeric($type) && $text) {
                    $type = $text;
                }

                switch ($type) {
                    case 'create':
                        $text = 'backend::lang.relation.create_name';
                        break;

                    case 'update':
                        $text = 'backend::lang.relation.update_name';
                        break;

                    case 'delete':
                        $text = 'backend::lang.relation.delete';
                        break;

                    case 'add':
                        $text = 'backend::lang.relation.add_name';
                        break;

                    case 'refresh':
                        $text = 'backend::lang.relation.refresh';
                        break;

                    case 'remove':
                        $text = 'backend::lang.relation.remove';
                        break;

                    case 'link':
                        $text = 'backend::lang.relation.link_name';
                        break;

                    case 'unlink':
                        $text = 'backend::lang.relation.unlink';
                        break;
                }
            }

            $buttonText[$type] = $text;
        }

        return $buttonText;
    }





    protected function evalViewMode()
    {
        if ($this->forceViewMode) {
            return $this->forceViewMode;
        }

        switch ($this->relationType) {
            case 'hasMany':
            case 'morphMany':
            case 'morphToMany':
            case 'morphedByMany':
            case 'belongsToMany':
                return 'multi';

            case 'hasOne':
            case 'morphOne':
            case 'belongsTo':
                return 'single';
        }
    }





    protected function evalManageTitle()
    {
        $customTitle = $this->getConfig('manage[title]');

        if (is_string($customTitle)) {
            return $customTitle;
        }

        $customTitles = is_array($customTitle) ? $customTitle : [];

        switch ($this->manageMode) {
            case 'pivot':
                if (array_key_exists('pivot', $customTitles)) {
                    return $customTitles['pivot'];
                } elseif ($this->eventTarget === 'button-link') {
                    return 'backend::lang.relation.link_a_new';
                }

                return 'backend::lang.relation.add_a_new';
            case 'list':
                if (array_key_exists('list', $customTitles)) {
                    return $customTitles['list'];
                } elseif ($this->eventTarget === 'button-link') {
                    return 'backend::lang.relation.link_a_new';
                }

                return 'backend::lang.relation.add_a_new';
            case 'form':
                if (array_key_exists('form', $customTitles)) {
                    return $customTitles['form'];
                } elseif ($this->readOnly) {
                    return 'backend::lang.relation.preview_name';
                } elseif ($this->manageId) {
                    return 'backend::lang.relation.update_name';
                }

                return 'backend::lang.relation.create_name';
        }
    }





    protected function evalManageMode()
    {
        if ($mode = post(self::PARAM_MODE)) {
            return $mode;
        }

        if ($this->forceManageMode) {
            return $this->forceManageMode;
        }

        switch ($this->eventTarget) {
            case 'button-create':
            case 'button-update':
                return 'form';

            case 'button-link':
                return 'list';
        }

        switch ($this->relationType) {
            case 'belongsTo':
                return 'list';

            case 'morphToMany':
            case 'morphedByMany':
            case 'belongsToMany':
                if (isset($this->config->pivot)) {
                    return 'pivot';
                }
                elseif ($this->eventTarget === 'list') {
                    return 'form';
                }
                else {
                    return 'list';
                }

            case 'hasOne':
            case 'morphOne':
            case 'hasMany':
            case 'morphMany':
                if ($this->eventTarget === 'button-add') {
                    return 'list';
                }

                return 'form';
        }
    }




    protected function evalFormContext($mode = 'manage', $exists = false)
    {
        $config = $this->config->{$mode} ?? [];

        if (($context = array_get($config, 'context')) && is_array($context)) {
            $context = $exists
                ? array_get($context, 'update')
                : array_get($context, 'create');
        }

        if (!$context) {
            $context = $exists ? 'update' : 'create';
        }

        return $context;
    }




    protected function applyExtraConfig($config, $field = null)
    {
        if (!$field) {
            $field = $this->field;
        }

        if (!$config || !isset($this->originalConfig->{$field})) {
            return;
        }

        if (
            !is_array($config) &&
            (!$config = @json_decode(@base64_decode($config), true))
        ) {
            return;
        }

        $parsedConfig = array_only($config, ['readOnly']);
        $parsedConfig['view'] = array_only($config, ['recordUrl', 'recordOnClick']);

        $this->originalConfig->{$field} = array_replace_recursive(
            $this->originalConfig->{$field},
            $parsedConfig
        );
    }





    protected function makeConfigForMode($mode = 'view', $type = 'list', $throwException = true)
    {
        $config = null;




        if (
            isset($this->config->{$mode}) &&
            array_key_exists($type, $this->config->{$mode})
        ) {
            $config = $this->config->{$mode}[$type];
        }



        elseif (isset($this->config->{$type})) {
            $config = $this->config->{$type};
        }






        if (!$config) {
            if ($mode === 'manage' && $type === 'list') {
                return $this->makeConfigForMode('view', $type);
            }

            if ($throwException) {
                throw new ApplicationException('Missing configuration for '.$mode.'.'.$type.' in RelationController definition '.$this->field);
            }

            return false;
        }

        return $this->makeConfig($config);
    }






    public function relationGetManageWidget()
    {
        return $this->manageWidget;
    }






    public function relationGetViewWidget()
    {
        return $this->viewWidget;
    }
}
