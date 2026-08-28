<?php

namespace Backend\Widgets;

use Backend\Classes\ListColumn;
use Backend\Classes\WidgetBase;
use Backend\Facades\Backend;
use Backend\Facades\BackendAuth;
use Backend\Traits\PreferenceMaker;
use Carbon\Carbon;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Lang;
use System\Classes\ImageResizer;
use System\Classes\MediaLibrary;
use System\Classes\PluginManager;
use System\Helpers\DateTime as DateTimeHelper;
use Winter\Storm\Database\Model;
use Winter\Storm\Exception\ApplicationException;
use Winter\Storm\Html\Helper as HtmlHelper;
use Winter\Storm\Router\Helper as RouterHelper;
use Winter\Storm\Support\Facades\DB;
use Winter\Storm\Support\Facades\DbDongle;
use Winter\Storm\Support\Facades\Html;
use Winter\Storm\Support\Str;








class Lists extends WidgetBase
{
    use PreferenceMaker;








    public $columns;




    public $model;




    public $recordUrl;




    public $recordOnClick;




    public $noRecordsMessage = 'backend::lang.list.no_records';




    public $recordsPerPage;




    public $perPageOptions;




    public $showSorting = true;




    public $defaultSort;




    public $showCheckboxes = false;




    public $showSetup = false;




    public $showTree = false;




    public $treeExpanded = false;






    public $sortable = false;




    public $showPagination = 'auto';




    public $showPageNumbers = true;




    public $showTotals = true;




    public $customViewPath;








    protected $defaultAlias = 'list';





    protected $allColumns;




    protected $columnOverride;




    protected $visibleColumns;




    protected $records;




    protected $currentPageNumber;




    protected $searchTerm;







    protected $searchMode;




    protected $searchScope;




    protected $filterCallbacks = [];




    protected $sortableColumns;




    protected $sortColumn;




    protected $sortDirection;




    public $cssClasses = [];




    public function init()
    {
        $this->fillFromConfig([
            'columns',
            'model',
            'recordUrl',
            'recordOnClick',
            'noRecordsMessage',
            'showPageNumbers',
            'showTotals',
            'recordsPerPage',
            'perPageOptions',
            'showSorting',
            'defaultSort',
            'showCheckboxes',
            'showSetup',
            'showTree',
            'treeExpanded',
            'showPagination',
            'customViewPath',
            'sortable',
        ]);




        if ($this->showSetup) {
            $this->recordsPerPage = $this->getUserPreference('per_page', $this->recordsPerPage);
        }

        if ($this->showPagination == 'auto') {
            $this->showPagination = $this->recordsPerPage && $this->recordsPerPage > 0;
        }





        if ($this->sortable) {
            $this->showSorting = false;
            $this->showPagination = false;
        }

        if ($this->customViewPath) {
            $this->prependViewPath($this->customViewPath);
        }

        $this->validateModel();
        $this->validateTree();
    }




    protected function loadAssets()
    {
        $this->addJs('js/winter.list.js', 'core');


        if ($this->getConfig('sortable', false)) {
            $this->addJs('js/dist/winter.list.sortable.js', 'core');
            $this->addCss('css/winter.list.sortable.css', 'core');
        }
    }




    public function render()
    {
        $this->prepareVars();
        return $this->makePartial('list-container');
    }




    public function prepareVars()
    {
        $this->vars['cssClasses'] = implode(' ', $this->cssClasses);
        $this->vars['columns'] = $columns = $this->getVisibleColumns();
        $this->vars['columnTotal'] = $this->getTotalColumns();
        $this->vars['records'] = $records = $this->getRecords();
        $this->vars['noRecordsMessage'] = trans($this->noRecordsMessage);
        $this->vars['showCheckboxes'] = $this->showCheckboxes;
        $this->vars['showSetup'] = $this->showSetup;
        $this->vars['showPagination'] = $this->showPagination;
        $this->vars['showPageNumbers'] = $this->showPageNumbers;
        $this->vars['showSorting'] = $this->showSorting;
        $this->vars['sortColumn'] = $this->getSortColumn();
        $this->vars['sortDirection'] = $this->sortDirection;
        $this->vars['showTree'] = $this->showTree;
        $this->vars['treeLevel'] = 0;
        $this->vars['sortable'] = $this->sortable;
        $this->vars['reorderHandler'] = $this->sortable ? $this->getEventHandler('onReorder') : null;

        if ($this->showPagination) {
            $this->vars['pageCurrent'] = $records->currentPage();


            $this->putSession('lastVisitedPage', $this->vars['pageCurrent']);
            if ($this->showPageNumbers) {
                $this->vars['recordTotal'] = $records->total();
                $this->vars['pageLast'] = $records->lastPage();
                $this->vars['pageFrom'] = $records->firstItem();
                $this->vars['pageTo'] = $records->lastItem();
            } else {
                $this->vars['hasMorePages'] = $records->hasMorePages();
            }
        } else {
            $this->vars['recordTotal'] = $records->count();
            $this->vars['pageCurrent'] = 1;
        }


        if (!$records->count()) {
            $this->showTotals = false;
        }


        if ($this->showTotals) {
            $sums = [];
            $formats = [];
            $queryTotals = $this->calculateTotalSums($columns);

            foreach ($columns as $column) {
                if ($column->type === 'number' && $column->summable) {
                    $sums[$column->columnName] = 0;
                    $formats[$column->columnName] = $column->format ?? null;
                }
            }

            if (empty($sums)) {
                $this->showTotals = false;
            } else {

                foreach ($records as $record) {
                    foreach ($columns as $column) {
                        if ($column->type === 'number' && $column->summable) {
                            $value = $this->getColumnValueRaw($record, $column);
                            if (is_numeric($value)) {
                                $sums[$column->columnName] += $value;
                            }
                        }
                    }
                }


                $this->vars['sums'] = collect($sums)->mapWithKeys(function ($sum, $columnName) use ($queryTotals, $formats) {
                    return [
                        $columnName => [
                            'sum' => $sum,
                            'total' => $queryTotals[$columnName] ?? null,
                            'format' => $formats[$columnName] ?? null,
                        ],
                    ];
                })->toArray();
            }
        }
        $this->vars['showTotals'] = $this->showTotals;
    }




    public function onRefresh()
    {
        $this->prepareVars();
        return ['#'.$this->getId() => $this->makePartial('list')];
    }








    public function onReorder()
    {
        if (!$this->sortable) {
            throw new ApplicationException('Reordering is not enabled for this list.');
        }

        $ids = post('record_ids');

        if (!is_array($ids) || !count($ids)) {
            return;
        }





        $allowed = array_flip(array_map('strval', $this->prepareQuery()->pluck($this->model->getQualifiedKeyName())->all()));
        foreach ($ids as $id) {
            if (!isset($allowed[(string) $id])) {
                throw new ApplicationException('One or more records are not available for reordering.');
            }
        }





        $orders = range(1, count($ids));











        $this->fireSystemEvent('backend.list.reorder', [$ids, $orders]);

        return $this->onRefresh();
    }




    public function onPaginate()
    {
        $this->currentPageNumber = post('page');
        return $this->onRefresh();
    }




    public function onFilter()
    {
        $this->currentPageNumber = 1;
        return $this->onRefresh();
    }





    protected function validateModel()
    {
        if (!$this->model) {
            throw new ApplicationException(Lang::get(
                'backend::lang.list.missing_model',
                ['class'=>get_class($this->controller)]
            ));
        }

        if (!$this->model instanceof Model) {
            throw new ApplicationException(Lang::get(
                'backend::lang.model.invalid_class',
                ['model'=>get_class($this->model), 'class'=>get_class($this->controller)]
            ));
        }

        return $this->model;
    }







    protected function parseTableName($sql, $table)
    {
        return str_replace('@', $table.'.', $sql);
    }




    public function prepareQuery()
    {
        $query = $this->model->newQuery();
        $primaryTable = $this->model->getTable();
        $selects = [$primaryTable.'.*'];
        $joins = [];
        $withs = [];
        $bindings = [];


















        $this->fireSystemEvent('backend.list.extendQueryBefore', [$query]);




        $primarySearchable = [];
        $relationSearchable = [];
        if (
            strlen($this->searchTerm) !== 0
            && trim($this->searchTerm) !== ''
            && ($searchableColumns = $this->getSearchableColumns())
        ) {
            foreach ($searchableColumns as $column) {



                if ($this->isColumnRelated($column)) {
                    $table = $this->model->makeRelation($column->relation)->getTable();
                    $columnName = isset($column->sqlSelect)
                        ? DbDongle::raw($this->parseTableName($column->sqlSelect, $table))
                        : $table . '.' . $column->valueFrom;

                    $relationSearchable[$column->relation][] = $columnName;
                }



                else {
                    $columnName = isset($column->sqlSelect)
                        ? DbDongle::raw($this->parseTableName($column->sqlSelect, $primaryTable))
                        : DbDongle::cast(DB::getTablePrefix() . $primaryTable . '.' . $column->columnName, 'TEXT');

                    $primarySearchable[] = $columnName;
                }
            }
        }




        foreach ($this->getVisibleColumns() as $column) {

            if ($column->relation && ($column->config['useRelationCount'] ?? false)) {
                $query->withCount($column->relation);
            }

            if (!$this->isColumnRelated($column) || (!isset($column->sqlSelect) && !isset($column->valueFrom))) {
                continue;
            }

            if (isset($column->valueFrom)) {
                $withs[] = $column->relation;
            }

            $joins[] = $column->relation;
        }




        if ($withs) {
            $query->with(array_unique($withs));
        }




        $query->where(function ($innerQuery) use ($primarySearchable, $relationSearchable, $joins) {




            if (count($primarySearchable) > 0) {
                $this->applySearchToQuery($innerQuery, $primarySearchable, 'or');
            }




            if ($joins) {
                foreach (array_unique($joins) as $join) {




                    $columnsToSearch = array_get($relationSearchable, $join, []);

                    if (count($columnsToSearch) > 0) {
                        $innerQuery->orWhereHas($join, function ($_query) use ($columnsToSearch) {
                            $this->applySearchToQuery($_query, $columnsToSearch);
                        });
                    }
                }
            }
        });




        foreach ($this->getVisibleColumns() as $column) {
            if (!isset($column->sqlSelect)) {
                continue;
            }

            $alias = $query->getQuery()->getGrammar()->wrap($column->columnName);




            if (isset($column->relation)) {

                $relationType = $this->model->getRelationType($column->relation);
                if ($relationType == 'morphTo') {
                    throw new ApplicationException('The relationship morphTo is not supported for list columns.');
                }

                $table =  $this->model->makeRelation($column->relation)->getTable();
                $sqlSelect = $this->parseTableName($column->sqlSelect, $table);




                $relationObj = $this->model->{$column->relation}();
                $countQuery = $relationObj->getRelationExistenceQuery($relationObj->getRelated()->newQueryWithoutScopes(), $query);

                $limit = $column->config['limit'] ?? false;

                $joinSql = $this->isColumnRelated($column, true) && $limit !== 1
                    ? DbDongle::raw("group_concat(" . $sqlSelect . " separator ', ')")
                    : DbDongle::raw($sqlSelect);

                $joinQuery = $countQuery->select($joinSql);

                if (!empty($column->config['conditions'])) {
                    $joinQuery->whereRaw(DbDongle::parse($column->config['conditions']));
                }

                if ($limit) {
                    $joinQuery->limit($column->config['limit']);
                }

                $joinSql = $joinQuery->toSql();

                $selects[] = DB::raw("(" . $joinSql . ") as " . $alias);




                $bindings = array_merge($bindings, $countQuery->getBindings());
            }



            else {
                $sqlSelect = $this->parseTableName($column->sqlSelect, $primaryTable);
                $selects[] = DbDongle::raw($sqlSelect . ' as '. $alias);
            }
        }




        if (($sortColumn = $this->getSortColumn()) && !$this->showTree) {
            if (($column = array_get($this->allColumns, $sortColumn)) && $column->valueFrom) {
                $sortColumn = $this->isColumnPivot($column)
                    ? 'pivot_' . $column->valueFrom
                    : $column->valueFrom;
            }


            if (isset($column->relation) && ($column->config['useRelationCount'] ?? false)) {
                $sortColumn = Str::snake($column->relation) . '_count';
            }

            $query->orderBy($sortColumn, $this->sortDirection);
        }




        foreach ($this->filterCallbacks as $callback) {
            $callback($query);
        }




        $query->addSelect($selects);




        $query->addBinding($bindings, 'select');



















        if ($event = $this->fireSystemEvent('backend.list.extendQuery', [$query])) {
            return $event;
        }

        return $query;
    }




    protected function calculateTotalSums(array $columns): array
    {
        $sums = [];

        $query = $this->prepareQuery();


        $sumColumns = [];
        foreach ($columns as $column) {
            if ($column->type === 'number' && $column->summable) {
                $columnName = $column->columnName;
                $sumColumns[$columnName] = $column;
                $sums[$columnName] = 0;
            }
        }

        if (empty($sums)) {
            return [];
        }


        $query->getQuery()->columns = [];

        foreach ($sumColumns as $alias => $column) {

            if (isset($column->sqlSelect)) {
                $sqlSelect = $column->sqlSelect;
                $sumExpression = "SUM({$sqlSelect}) as {$alias}";
                $query->addSelect(DB::raw($sumExpression));
            } else {
                $columnName = $column->columnName;
                $sumExpression = "SUM({$columnName}) as {$alias}";
                $query->addSelect(DB::raw($sumExpression));
            }
        }


        $query->getQuery()->orders = null;


        try {
            $result = $query->first();
        } catch (QueryException $ex) {
            traceLog("Lists widget: showTotals query totals disabled due to SQL error", $ex);
            return [];
        }


        foreach ($sumColumns as $alias => $column) {
            $sums[$alias] = $result->$alias ?? 0;
        }

        return $sums;
    }

    public function prepareModel()
    {
        traceLog('Method ' . __METHOD__ . '() has been deprecated, please use the ' . __CLASS__ . '::prepareQuery() method instead.');
        return $this->prepareQuery();
    }





    protected function getRecords()
    {
        $query = $this->prepareQuery();

        if ($this->showTree) {
            $records = $query->getNested();
        }
        elseif ($this->showPagination) {
            $method            = $this->showPageNumbers ? 'paginate' : 'simplePaginate';
            $currentPageNumber = $this->getCurrentPageNumber($query);
            $records = $query->{$method}($this->recordsPerPage, $currentPageNumber);
        }
        else {
            $records = $query->get();
        }




















        if ($event = $this->fireSystemEvent('backend.list.extendRecords', [&$records])) {
            $records = $event;
        }

        return $this->records = $records;
    }









    protected function getCurrentPageNumber($query)
    {
        $currentPageNumber = $this->currentPageNumber;
        if (empty($currentPageNumber)) {
            $currentPageNumber = $this->getSession('lastVisitedPage');
        }

        $currentPageNumber = intval($currentPageNumber);

        if ($currentPageNumber > 1) {
            $count = $query->count();


            if ($count <= (($currentPageNumber - 1) * $this->recordsPerPage)) {
                $currentPageNumber = ceil($count / $this->recordsPerPage);
            }
        }

        return $currentPageNumber;
    }






    public function getRecordUrl($record)
    {
        if (isset($this->recordOnClick)) {
            return 'javascript:;';
        }

        if (!isset($this->recordUrl)) {
            return null;
        }

        $url = RouterHelper::replaceParameters($record, $this->recordUrl);


        if (!Str::startsWith($url, ['http', '/'])) {
            $url = Backend::url($url);
        }

        return $url;
    }






    public function getRecordOnClick($record)
    {
        if (!isset($this->recordOnClick)) {
            return null;
        }

        $recordOnClick = RouterHelper::replaceParameters($record, $this->recordOnClick);
        return Html::attributes(['onclick' => $recordOnClick]);
    }





    public function getColumns()
    {
        return $this->allColumns ?: $this->defineListColumns();
    }






    public function getColumn($column)
    {
        if (!isset($this->allColumns[$column])) {
            throw new ApplicationException('No definition for column ' . $column);
        }

        return $this->allColumns[$column];
    }




    public function getVisibleColumns()
    {
        $definitions = $this->defineListColumns();
        $columns = [];




        if ($this->showSetup && $this->columnOverride === null) {
            $this->columnOverride = $this->getUserPreference('visible', null);
        }

        if ($this->columnOverride && is_array($this->columnOverride)) {
            $invalidColumns = array_diff($this->columnOverride, array_keys($definitions));
            if (!count($definitions)) {
                throw new ApplicationException(Lang::get(
                    'backend::lang.list.missing_column',
                    ['columns'=>implode(',', $invalidColumns)]
                ));
            }

            $availableColumns = array_intersect($this->columnOverride, array_keys($definitions));
            foreach ($availableColumns as $columnName) {
                $definitions[$columnName]->invisible = false;
                $columns[$columnName] = $definitions[$columnName];
            }
        }



        else {
            foreach ($definitions as $columnName => $column) {
                if ($column->invisible) {
                    continue;
                }

                $columns[$columnName] = $definitions[$columnName];
            }
        }

        return $this->visibleColumns = $columns;
    }




    protected function defineListColumns()
    {
        if (!isset($this->columns) || !is_array($this->columns) || !count($this->columns)) {
            $class = get_class($this->model instanceof Model ? $this->model : $this->controller);
            throw new ApplicationException(Lang::get('backend::lang.list.missing_columns', compact('class')));
        }


















































        $this->fireSystemEvent('backend.list.extendColumnsBefore');

        $this->addColumns($this->columns);






















































        $this->fireSystemEvent('backend.list.extendColumns');




        if ($columnOrder = $this->getUserPreference('order', null)) {
            $orderedDefinitions = [];
            foreach ($columnOrder as $column) {
                if (isset($this->allColumns[$column])) {
                    $orderedDefinitions[$column] = $this->allColumns[$column];
                }
            }

            $this->allColumns = array_merge($orderedDefinitions, $this->allColumns);
        }







        if ($this->sortable) {
            foreach ($this->allColumns as $column) {
                $column->sortable = false;
            }
        }

        return $this->allColumns;
    }





    public function addColumns(array $columns)
    {



        foreach ($columns as $columnName => $config) {

            $permissions = array_get($config, 'permissions');
            if (!empty($permissions) && !BackendAuth::getUser()->hasAccess($permissions, false)) {
                continue;
            }

            $this->allColumns[$columnName] = $this->makeListColumn($columnName, $config);
        }
    }





    public function removeColumn($columnName)
    {
        if (isset($this->allColumns[$columnName])) {
            unset($this->allColumns[$columnName]);
        }
    }




    protected function makeListColumn($name, $config)
    {
        if (is_string($config)) {
            $label = $config;
        }
        elseif (isset($config['label'])) {
            $label = $config['label'];
        }
        else {
            $label = studly_case($name);
        }




        if (starts_with($name, 'pivot[') && strpos($name, ']') !== false) {
            $_name = HtmlHelper::nameToArray($name);
            $relationName = array_shift($_name);
            $valueFrom = array_shift($_name);

            if (count($_name) > 0) {
                $valueFrom  .= '['.implode('][', $_name).']';
            }

            $config['relation'] = $relationName;
            $config['valueFrom'] = $valueFrom;
            $config['searchable'] = false;
        }



        elseif (strpos($name, '[') !== false && strpos($name, ']') !== false) {
            $config['valueFrom'] = $name;
            $config['sortable'] = false;
            $config['searchable'] = false;
        }

        $columnType = $config['type'] ?? null;

        $column = new ListColumn($name, $label);
        $column->displayAs($columnType, $config);

        return $column;
    }





    protected function getTotalColumns()
    {
        $columns = $this->visibleColumns ?: $this->getVisibleColumns();
        $total = count($columns);

        if ($this->showCheckboxes) {
            $total++;
        }

        if ($this->showSetup) {
            $total++;
        }

        if ($this->showTree) {
            $total++;
        }

        if ($this->sortable) {
            $total++;
        }

        return $total;
    }




    public function getHeaderValue($column)
    {
        $value = Lang::get($column->label);



















        if ($response = $this->fireSystemEvent('backend.list.overrideHeaderValue', [$column, &$value])) {
            $value = $response;
        }

        return $value;
    }





    public function getColumnValueRaw($record, $column)
    {
        $columnName = $column->columnName;




        if ($column->valueFrom && $column->relation) {
            $columnName = $column->relation;

            if (!array_key_exists($columnName, $record->getRelations())) {
                $value = null;
            }
            elseif ($this->isColumnRelated($column, true)) {
                $value = $record->{$columnName}->lists($column->valueFrom);
            }
            elseif ($this->isColumnRelated($column) || $this->isColumnPivot($column)) {
                $value = $record->{$columnName}
                    ? $column->getValueFromData($record->{$columnName})
                    : null;
            }
            else {
                $value = null;
            }
        }



        elseif ($column->valueFrom) {
            $value = $column->getValueFromData($record);
        }





        else {
            if ($record->hasRelation($columnName) && array_key_exists($columnName, $record->attributes)) {
                $value = $record->attributes[$columnName];

            } elseif ($column->relation && ($column->config['useRelationCount'] ?? false)) {
                $relation = Str::snake($column->relation);
                $value = $record->{"{$relation}_count"};
            } else {
                $value = $record->{$columnName};
            }
        }

        if ($value instanceof \BackedEnum) {
            $value = $value->value;
        }



















        if ($response = $this->fireSystemEvent('backend.list.overrideColumnValueRaw', [$record, $column, &$value])) {
            $value = $response;
        }

        return $value;
    }





    public function getColumnValue($record, $column)
    {
        $value = $this->getColumnValueRaw($record, $column);

        $customMethod = 'eval'. studly_case($column->type) .'TypeValue';
        if ($this->methodExists($customMethod)) {
            $value = $this->{$customMethod}($record, $column, $value);
        }
        else {
            $value = $this->evalCustomListType($column->type, $record, $column, $value);
        }




        if (($value === '' || is_null($value)) && !empty($column->defaults)) {
            $value = Lang::get($column->defaults);
        }



















        if ($response = $this->fireSystemEvent('backend.list.overrideColumnValue', [$record, $column, &$value])) {
            $value = $response;
        }

        return $value;
    }






    public function getRowClass($record)
    {
        $value = '';



















        if ($response = $this->fireSystemEvent('backend.list.injectRowClass', [$record, &$value])) {
            $value = $response;
        }

        return $value;
    }








    protected function evalCustomListType($type, $record, $column, $value)
    {
        $plugins = PluginManager::instance()->getRegistrationMethodValues('registerListColumnTypes');

        foreach ($plugins as $availableTypes) {
            if (!isset($availableTypes[$type])) {
                continue;
            }

            $callback = $availableTypes[$type];

            if (is_callable($callback)) {
                return call_user_func_array($callback, [$value, $column, $record]);
            }
        }

        $customMessage = '';
        if ($type === 'relation') {
            $customMessage = 'Type: relation is not supported, instead use the relation property to specify a relationship to pull the value from and set the type to the type of the value expected.';
        }

        throw new ApplicationException(sprintf('List column type "%s" could not be found. %s', $type, $customMessage));
    }





    protected function evalTextTypeValue($record, $column, $value)
    {
        if (is_array($value) && count($value) == count($value, COUNT_RECURSIVE)) {
            $value = implode(', ', $value);
        }

        if (is_string($column->format) && !empty($column->format)) {
            $value = sprintf($column->format, $value);
        }

        return htmlentities($value, ENT_QUOTES, 'UTF-8', false);
    }





    protected function evalImageTypeValue($record, $column, $value)
    {
        $image = null;
        $config = $column->config;


        $width = isset($config['width']) ? $config['width'] : 50;
        $height = isset($config['height']) ? $config['height'] : 50;
        $options = isset($config['options']) ? $config['options'] : [];
        $fallback = isset($config['default']) ? $config['default'] : null;


        if (isset($record->attachMany[$column->columnName])) {
            $image = $value->first();


        } elseif (isset($record->attachOne[$column->columnName])) {
            $image = $value;


        } elseif (str_contains($value, '://')) {
            $image = $value;


        } elseif (starts_with($value, 'data:image')) {
            $image = $value;


        } elseif (!empty($value)) {
            $image = MediaLibrary::url($value);
        }

        if (!$image && $fallback) {
            $image = $fallback;
        }

        if ($image) {
            $imageUrl = ImageResizer::filterGetUrl($image, $width, $height, $options);
            return "<img src='$imageUrl' width='$width' height='$height' />";
        }
    }





    protected function evalNumberTypeValue($record, $column, $value)
    {
        return $this->evalTextTypeValue($record, $column, $value);
    }




    protected function evalPartialTypeValue($record, $column, $value)
    {
        return $this->controller->makePartial($column->path ?: $column->columnName, [
            'listColumn' => $column,
            'listRecord' => $record,
            'listValue'  => $value,
            'column'     => $column,
            'record'     => $record,
            'value'      => $value
        ]);
    }




    protected function evalSwitchTypeValue($record, $column, $value)
    {
        $contents = '';

        if ($value) {
            $contents = Lang::get('backend::lang.list.column_switch_true');
        }
        else {
            $contents = Lang::get('backend::lang.list.column_switch_false');
        }

        return $contents;
    }




    protected function evalDatetimeTypeValue($record, $column, $value)
    {
        if ($value === null) {
            return null;
        }

        $dateTime = $this->validateDateTimeValue($value, $column);

        if ($column->format !== null) {
            $value = $dateTime->format($column->format);
        }
        else {
            $value = $dateTime->toDayDateTimeString();
        }

        $options = [
            'defaultValue' => $value,
            'format' => $column->format,
            'formatAlias' => 'dateTimeLongMin'
        ];

        if (!empty($column->config['ignoreTimezone'])) {
            $options['ignoreTimezone'] = true;
        }

        return Backend::dateTime($dateTime, $options);
    }




    protected function evalTimeTypeValue($record, $column, $value)
    {
        if ($value === null) {
            return null;
        }

        $dateTime = $this->validateDateTimeValue($value, $column);

        $format = $column->format ?? 'g:i A';

        $value = $dateTime->format($format);

        $options = [
            'defaultValue' => $value,
            'format' => $column->format,
            'formatAlias' => 'time'
        ];

        if (!empty($column->config['ignoreTimezone'])) {
            $options['ignoreTimezone'] = true;
        }

        return Backend::dateTime($dateTime, $options);
    }




    protected function evalDateTypeValue($record, $column, $value)
    {
        if ($value === null) {
            return null;
        }

        $dateTime = $this->validateDateTimeValue($value, $column);

        if ($column->format !== null) {
            $value = $dateTime->format($column->format);
        }
        else {
            $value = $dateTime->toFormattedDateString();
        }

        $options = [
            'defaultValue' => $value,
            'format' => $column->format,
            'formatAlias' => 'dateLongMin',
            'ignoreTimezone' => true,
        ];

        if (isset($column->config['ignoreTimezone'])) {
            $options['ignoreTimezone'] = $column->config['ignoreTimezone'];
        }

        return Backend::dateTime($dateTime, $options);
    }




    protected function evalTimesinceTypeValue($record, $column, $value)
    {
        if ($value === null) {
            return null;
        }

        $dateTime = $this->validateDateTimeValue($value, $column);

        $value = DateTimeHelper::timeSince($dateTime);

        $options = [
            'defaultValue' => $value,
            'timeSince' => true
        ];

        if (!empty($column->config['ignoreTimezone'])) {
            $options['ignoreTimezone'] = true;
        }

        return Backend::dateTime($dateTime, $options);
    }




    protected function evalTimetenseTypeValue($record, $column, $value)
    {
        if ($value === null) {
            return null;
        }

        $dateTime = $this->validateDateTimeValue($value, $column);

        $value = DateTimeHelper::timeTense($dateTime);

        $options = [
            'defaultValue' => $value,
            'timeTense' => true
        ];

        if (!empty($column->config['ignoreTimezone'])) {
            $options['ignoreTimezone'] = true;
        }

        return Backend::dateTime($dateTime, $options);
    }



    protected function evalColorPickerTypeValue($record, $column, $value)
    {
        return  '<span style="width:30px; height:30px; display:inline-block; background:'.e($value).'; padding:10px"><span>';
    }



    protected function validateDateTimeValue($value, $column)
    {
        $value = DateTimeHelper::makeCarbon($value, false);

        if (!$value instanceof Carbon) {
            throw new ApplicationException(Lang::get(
                'backend::lang.list.invalid_column_datetime',
                ['column' => $column->columnName]
            ));
        }

        return $value;
    }





    public function addFilter(callable $filter)
    {
        $this->filterCallbacks[] = $filter;
    }











    public function setSearchTerm($term, $resetPagination = false)
    {
        if (
            strlen($term) !== 0
            && trim($term) !== ''
        ) {
            if ($this->showTree === true) {

                $this->putSession('showTree', true);
            }
            $this->showTree = false;
        } else {
            if ($this->getSession('showTree')) {

                $this->showTree = true;
            }
        }

        if ($resetPagination) {
            $this->currentPageNumber = 1;
        }

        $this->searchTerm = $term;
    }





    public function setSearchOptions($options = [])
    {
        extract(array_merge([
            'mode' => null,
            'scope' => null
        ], $options));

        $this->searchMode = $mode;
        $this->searchScope = $scope;
    }





    protected function getSearchableColumns()
    {
        $columns = $this->getColumns();
        $searchable = [];

        foreach ($columns as $column) {
            if (!$column->searchable) {
                continue;
            }

            $searchable[] = $column;
        }

        return $searchable;
    }




    protected function applySearchToQuery($query, $columns, $boolean = 'and')
    {
        $term = $this->searchTerm;

        if ($scopeMethod = $this->searchScope) {
            $searchMethod = $boolean == 'and' ? 'where' : 'orWhere';
            $query->$searchMethod(function ($q) use ($term, $columns, $scopeMethod) {
                $q->$scopeMethod($term, $columns);
            });
        }
        else {
            $searchMethod = $boolean == 'and' ? 'searchWhere' : 'orSearchWhere';
            $query->$searchMethod($term, $columns, $this->searchMode);
        }
    }








    public function onSort()
    {
        if ($column = post('sortColumn')) {



            $sortOptions = ['column' => $this->getSortColumn(), 'direction' => $this->sortDirection];

            if ($column != $sortOptions['column'] || $sortOptions['direction'] == 'asc') {
                $this->sortDirection = $sortOptions['direction'] = 'desc';
            }
            else {
                $this->sortDirection = $sortOptions['direction'] = 'asc';
            }

            $this->sortColumn = $sortOptions['column'] = $column;




            $this->currentPageNumber = post('page');





            $result = $this->onRefresh();

            $this->putSession('sort', $sortOptions);

            return $result;
        }
    }





    public function setSort(string $column, string $direction = 'asc', bool $persist = true)
    {
        $this->sortColumn = $column;
        $this->sortDirection = $direction;
        if ($persist) {
            $this->putSession('sort', [
                'column' => $this->sortColumn,
                'direction' => $this->sortDirection,
            ]);
        }
    }




    public function getSortColumn()
    {
        if (!$this->isSortable()) {
            return false;
        }

        if ($this->sortColumn !== null && $this->isSortable($this->sortColumn)) {
            return $this->sortColumn;
        }




        if ($this->showSorting && ($sortOptions = $this->getSession('sort'))) {
            $this->sortColumn = $sortOptions['column'];
            $this->sortDirection = $sortOptions['direction'];
        }




        else {
            if (is_string($this->defaultSort)) {
                $this->sortColumn = $this->defaultSort;
                $this->sortDirection = 'desc';
            }
            elseif (is_array($this->defaultSort) && isset($this->defaultSort['column'])) {
                $this->sortColumn = $this->defaultSort['column'];
                $this->sortDirection = $this->defaultSort['direction'] ?? 'desc';
            }
        }




        if ($this->sortColumn === null || !$this->isSortable($this->sortColumn)) {
            $columns = $this->visibleColumns ?: $this->getVisibleColumns();
            $columns = array_filter($columns, function ($column) {
                return $column->sortable;
            });
            $this->sortColumn = key($columns);
            $this->sortDirection = 'desc';
        }

        return $this->sortColumn;
    }




    public function getSortDirection()
    {
        return $this->sortDirection ?? 'asc';
    }




    protected function isSortable($column = null)
    {
        if ($column === null) {
            return (count($this->getSortableColumns()) > 0);
        }

        return array_key_exists($column, $this->getSortableColumns());
    }




    protected function getSortableColumns()
    {
        if ($this->sortableColumns !== null) {
            return $this->sortableColumns;
        }

        $columns = $this->getColumns();
        $sortable = array_filter($columns, function ($column) {
            return $column->sortable;
        });

        return $this->sortableColumns = $sortable;
    }








    public function onLoadSetup()
    {
        $this->vars['columns'] = $this->getSetupListColumns();
        $this->vars['perPageOptions'] = $this->getSetupPerPageOptions();
        $this->vars['recordsPerPage'] = $this->recordsPerPage;
        return $this->makePartial('setup_form');
    }




    public function onApplySetup()
    {
        if (($visibleColumns = post('visible_columns')) && is_array($visibleColumns)) {
            $this->columnOverride = $visibleColumns;
            $this->putUserPreference('visible', $this->columnOverride);
        }

        $this->recordsPerPage = post('records_per_page', $this->recordsPerPage);
        $this->putUserPreference('order', post('column_order'));
        $this->putUserPreference('per_page', $this->recordsPerPage);
        return $this->onRefresh();
    }




    public function onResetSetup()
    {
        $this->clearUserPreference('order');
        $this->clearUserPreference('visible');
        $this->clearUserPreference('per_page');
        return $this->onRefresh();
    }




    protected function getSetupPerPageOptions()
    {
        $perPageOptions = is_array($this->perPageOptions) ? $this->perPageOptions : [20, 40, 80, 100, 120];
        if (!in_array($this->recordsPerPage, $perPageOptions)) {
            $perPageOptions[] = $this->recordsPerPage;
        }

        sort($perPageOptions);
        return $perPageOptions;
    }




    protected function getSetupListColumns()
    {



        $columns = $this->defineListColumns();
        foreach ($columns as $column) {
            $column->invisible = true;
        }

        return array_merge($columns, $this->getVisibleColumns());
    }









    public function validateTree()
    {
        if (!$this->showTree) {
            return;
        }

        $this->showSorting = $this->showPagination = false;

        if (!$this->model->methodExists('getChildren')) {
            throw new ApplicationException(
                'To display list as a tree, the specified model must have a method "getChildren"'
            );
        }

        if (!$this->model->methodExists('getChildCount')) {
            throw new ApplicationException(
                'To display list as a tree, the specified model must have a method "getChildCount"'
            );
        }
    }






    public function isTreeNodeExpanded($node)
    {
        return $this->getSession('tree_node_status_' . $node->getKey(), $this->treeExpanded);
    }






    public function onToggleTreeNode()
    {
        $this->putSession('tree_node_status_' . post('node_id'), post('status') ? 0 : 1);
        return $this->onRefresh();
    }










    protected function isColumnRelated(ListColumn $column, bool $multi = false): bool
    {
        if (!isset($column->relation) || $this->isColumnPivot($column)) {
            return false;
        }

        if (!$this->model->hasRelation($column->relation)) {
            throw new ApplicationException(Lang::get(
                'backend::lang.model.missing_relation',
                ['class'=>get_class($this->model), 'relation'=>$column->relation]
            ));
        }

        if (!$multi) {
            return true;
        }

        $relationType = $this->model->getRelationType($column->relation);

        return in_array($relationType, [
            'hasMany',
            'belongsToMany',
            'morphToMany',
            'morphedByMany',
            'morphMany',
            'attachMany',
            'hasManyThrough'
        ]);
    }






    protected function isColumnPivot($column)
    {
        if (!isset($column->relation) || $column->relation != 'pivot') {
            return false;
        }

        return true;
    }
}
