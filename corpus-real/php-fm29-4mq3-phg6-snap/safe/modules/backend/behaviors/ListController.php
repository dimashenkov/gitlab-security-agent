<?php

namespace Backend\Behaviors;

use Backend\Classes\ControllerBehavior;
use Illuminate\Support\Facades\Lang;
use Winter\Storm\Exception\ApplicationException;
use Winter\Storm\Support\Facades\Event;
use Winter\Storm\Support\Facades\Flash;



















class ListController extends ControllerBehavior
{



    protected $listDefinitions;




    protected $primaryDefinition;




    protected $listWidgets = [];




    protected $toolbarWidgets = [];




    protected $filterWidgets = [];






    protected $requiredConfig = ['modelClass', 'list'];




    protected $actions = ['index'];




    public $listConfig = 'config_list.yaml';





    public function __construct($controller)
    {
        parent::__construct($controller);




        $config = $controller->listConfig ?: $this->listConfig;
        if (is_array($config)) {
            $this->listDefinitions = $config;
            $this->primaryDefinition = key($this->listDefinitions);
        }
        else {
            $this->listDefinitions = ['list' => $config];
            $this->primaryDefinition = 'list';
        }




        $this->setConfig($this->listDefinitions[$this->primaryDefinition], $this->requiredConfig);
    }





    public function makeLists()
    {
        foreach ($this->listDefinitions as $definition => $config) {
            $this->listWidgets[$definition] = $this->makeList($definition);
        }

        return $this->listWidgets;
    }





    public function makeList($definition = null)
    {
        if (!$definition || !isset($this->listDefinitions[$definition])) {
            $definition = $this->primaryDefinition;
        }

        $listConfig = $this->controller->listGetConfig($definition);




        $class = $listConfig->modelClass;
        $model = new $class;
        $model = $this->controller->listExtendModel($model, $definition);




        $columnConfig = $this->makeConfig($listConfig->list);
        $columnConfig->model = $model;
        $columnConfig->alias = $definition;




        $configFieldsToTransfer = [
            'recordUrl',
            'recordOnClick',
            'recordsPerPage',
            'perPageOptions',
            'showPageNumbers',
            'noRecordsMessage',
            'defaultSort',
            'showSorting',
            'showSetup',
            'showCheckboxes',
            'showTree',
            'treeExpanded',
            'customViewPath',
            'sortable',
        ];

        foreach ($configFieldsToTransfer as $field) {
            if (isset($listConfig->{$field})) {
                $columnConfig->{$field} = $listConfig->{$field};
            }
        }




        $widget = $this->makeWidget(\Backend\Widgets\Lists::class, $columnConfig);




        if (!empty($listConfig->sortable)) {
            if (!in_array(\Winter\Storm\Database\Traits\Sortable::class, class_uses_recursive($model))) {
                throw new ApplicationException(sprintf(
                    'To use "sortable" on a list, the model "%s" must use the %s trait.',
                    get_class($model),
                    \Winter\Storm\Database\Traits\Sortable::class
                ));
            }






            $toolbar = $listConfig->toolbar ?? null;
            $conflicts = array_keys(array_filter([
                'toolbar search' => is_array($toolbar) && !empty($toolbar['search']),
                'filter'         => $listConfig->filter ?? null,
                'recordsPerPage' => $listConfig->recordsPerPage ?? null,
                'defaultSort'    => $listConfig->defaultSort ?? null,
            ]));
            if ($conflicts) {
                throw new ApplicationException(sprintf(
                    'A "sortable" list cannot also use: %s. Drag-and-drop reordering requires the whole list in a fixed order. Remove these options, or use the ReorderController for a dedicated reordering page.',
                    implode(', ', $conflicts)
                ));
            }

            $widget->bindEvent('list.reorder', function ($ids, $orders) use ($model) {
                $model->setSortableOrder($ids, $orders);
            });
        }

        $widget->bindEvent('list.extendColumnsBefore', function () use ($widget) {
            $this->controller->listExtendColumnsBefore($widget);
        });

        $widget->bindEvent('list.extendColumns', function () use ($widget) {
            $this->controller->listExtendColumns($widget);
        });

        $widget->bindEvent('list.extendQueryBefore', function ($query) use ($definition) {
            $this->controller->listExtendQueryBefore($query, $definition);
        });

        $widget->bindEvent('list.extendQuery', function ($query) use ($definition) {
            $this->controller->listExtendQuery($query, $definition);
        });

        $widget->bindEvent('list.extendRecords', function ($records) use ($definition) {
            return $this->controller->listExtendRecords($records, $definition);
        });

        $widget->bindEvent('list.injectRowClass', function ($record) use ($definition) {
            return $this->controller->listInjectRowClass($record, $definition);
        });

        $widget->bindEvent('list.overrideColumnValue', function ($record, $column, $value) use ($definition) {
            return $this->controller->listOverrideColumnValue($record, $column->columnName, $definition);
        });

        $widget->bindEvent('list.overrideHeaderValue', function ($column, $value) use ($definition) {
            return $this->controller->listOverrideHeaderValue($column->columnName, $definition);
        });

        $widget->bindToController();




        if (isset($listConfig->toolbar)) {
            $toolbarConfig = $this->makeConfig($listConfig->toolbar);
            $toolbarConfig->alias = $widget->alias . 'Toolbar';
            $toolbarWidget = $this->makeWidget(\Backend\Widgets\Toolbar::class, $toolbarConfig);
            $toolbarWidget->bindToController();
            $toolbarWidget->cssClasses[] = 'list-header';




            if ($searchWidget = $toolbarWidget->getSearchWidget()) {
                $searchWidget->bindEvent('search.submit', function () use ($widget, $searchWidget) {
                    $widget->setSearchTerm($searchWidget->getActiveTerm(), true);
                    return $widget->onRefresh();
                });

                $widget->setSearchOptions([
                    'mode' => $searchWidget->mode,
                    'scope' => $searchWidget->scope,
                ]);


                $widget->setSearchTerm($searchWidget->getActiveTerm());
            }

            $this->toolbarWidgets[$definition] = $toolbarWidget;
        }




        if (isset($listConfig->filter)) {
            $filterConfig = $this->makeConfig($listConfig->filter);

            $widget->cssClasses[] = 'list-flush';

            $filterConfig->alias = $widget->alias . 'Filter';
            $filterWidget = $this->makeWidget(\Backend\Widgets\Filter::class, $filterConfig);
            $filterWidget->bindToController();




            $filterWidget->bindEvent('filter.update', function () use ($widget, $filterWidget) {
                return $widget->onFilter();
            });




            $filterWidget->bindEvent('filter.extendScopes', function () use ($filterWidget) {
                $this->controller->listFilterExtendScopes($filterWidget);
            });




            $filterWidget->bindEvent('filter.extendQuery', function ($query, $scope) {
                $this->controller->listFilterExtendQuery($query, $scope);
            });


            $widget->addFilter([$filterWidget, 'applyAllScopesToQuery']);

            $this->filterWidgets[$definition] = $filterWidget;
        }

        return $widget;
    }





    public function index()
    {
        $this->controller->pageTitle = $this->controller->pageTitle ?: Lang::get($this->getConfig(
            'title',
            'backend::lang.list.default_title'
        ));
        $this->controller->bodyClass = 'slim-container';
        $this->makeLists();
    }






    public function index_onDelete()
    {
        if (method_exists($this->controller, 'onDelete')) {
            return call_user_func_array([$this->controller, 'onDelete'], func_get_args());
        }




        $definition = post('definition', $this->primaryDefinition);

        if (!isset($this->listDefinitions[$definition])) {
            throw new ApplicationException(Lang::get('backend::lang.list.missing_parent_definition', compact('definition')));
        }

        $listConfig = $this->controller->listGetConfig($definition);




        $checkedIds = post('checked');

        if (!$checkedIds || !is_array($checkedIds) || !count($checkedIds)) {
            Flash::error(Lang::get(
                (!empty($listConfig->noRecordsDeletedMessage))
                    ? $listConfig->noRecordsDeletedMessage
                    : 'backend::lang.list.delete_selected_empty'
            ));
            return $this->controller->listRefresh();
        }




        $class = $listConfig->modelClass;
        $model = new $class;
        $model = $this->controller->listExtendModel($model, $definition);




        $query = $model->newQuery();
        $this->controller->listExtendQueryBefore($query, $definition);

        $query->whereIn($model->getKeyName(), $checkedIds);
        $this->controller->listExtendQuery($query, $definition);




        $records = $query->get();

        if ($records->count()) {
            foreach ($records as $record) {
                $record->delete();
            }

            Flash::success(Lang::get(
                (!empty($listConfig->deleteMessage))
                    ? $listConfig->deleteMessage
                    : 'backend::lang.list.delete_selected_success'
            ));
        }
        else {
            Flash::error(Lang::get(
                (!empty($listConfig->noRecordsDeletedMessage))
                    ? $listConfig->noRecordsDeletedMessage
                    : 'backend::lang.list.delete_selected_empty'
            ));
        }

        return $this->controller->listRefresh($definition);
    }







    public function listRender($definition = null)
    {
        if (!count($this->listWidgets)) {
            throw new ApplicationException(Lang::get('backend::lang.list.behavior_not_ready'));
        }

        if (!$definition || !isset($this->listDefinitions[$definition])) {
            $definition = $this->primaryDefinition;
        }

        $vars = [
            'toolbar' => null,
            'filter' => null,
            'list' => null,
        ];

        if (isset($this->toolbarWidgets[$definition])) {
            $vars['toolbar'] = $this->toolbarWidgets[$definition];
        }

        if (isset($this->filterWidgets[$definition])) {
            $vars['filter'] = $this->filterWidgets[$definition];
        }

        $vars['list'] = $this->listWidgets[$definition];

        return $this->listMakePartial('container', $vars);
    }







    public function listMakePartial($partial, $params = [])
    {
        $contents = $this->controller->makePartial('list_'.$partial, $params + $this->vars, false);
        if (!$contents) {
            $contents = $this->makePartial($partial, $params);
        }

        return $contents;
    }






    public function listRefresh(?string $definition = null)
    {
        if (!count($this->listWidgets)) {
            $this->makeLists();
        }

        if (!$definition || !isset($this->listDefinitions[$definition])) {
            $definition = $this->primaryDefinition;
        }

        return $this->listWidgets[$definition]->onRefresh();
    }





    public function listGetWidget(?string $definition = null)
    {
        if (!$definition) {
            $definition = $this->primaryDefinition;
        }

        return array_get($this->listWidgets, $definition);
    }





    public function listGetConfig(?string $definition = null)
    {
        if (!$definition) {
            $definition = $this->primaryDefinition;
        }

        if (
            !($config = array_get($this->listDefinitions, $definition))
            || !is_object($config)
        ) {
            $config = $this->listDefinitions[$definition] = $this->makeConfig($this->listDefinitions[$definition], $this->requiredConfig);
        }

        return $config;
    }










    public function listExtendColumnsBefore($host)
    {
    }






    public function listExtendColumns($host)
    {
    }






    public function listFilterExtendScopes($host)
    {
    }







    public function listExtendModel($model, $definition = null)
    {
        return $model;
    }







    public function listExtendQueryBefore($query, $definition = null)
    {
    }







    public function listExtendQuery($query, $definition = null)
    {
    }







    public function listExtendRecords($records, $definition = null)
    {
    }







    public function listFilterExtendQuery($query, $scope)
    {
    }







    public function listInjectRowClass($record, $definition = null)
    {
    }








    public function listOverrideColumnValue($record, $columnName, $definition = null)
    {
    }







    public function listOverrideHeaderValue($columnName, $definition = null)
    {
    }






    public static function extendListColumns($callback)
    {
        $calledClass = self::getCalledExtensionClass();
        Event::listen('backend.list.extendColumns', function (\Backend\Widgets\Lists $widget) use ($calledClass, $callback) {
            if (!is_a($widget->getController(), $calledClass)) {
                return;
            }
            call_user_func_array($callback, [$widget, $widget->model]);
        });
    }






    public static function extendListFilterScopes($callback)
    {
        $calledClass = self::getCalledExtensionClass();
        Event::listen('backend.filter.extendScopes', function (\Backend\Widgets\Filter $widget) use ($calledClass, $callback) {
            if (!is_a($widget->getController(), $calledClass)) {
                return;
            }
            call_user_func_array($callback, [$widget]);
        });
    }
}
