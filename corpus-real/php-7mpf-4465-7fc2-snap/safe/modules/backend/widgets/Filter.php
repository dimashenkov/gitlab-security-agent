<?php

namespace Backend\Widgets;

use Backend\Classes\FilterScope;
use Backend\Classes\WidgetBase;
use Backend\Facades\Backend;
use Backend\Facades\BackendAuth;
use Carbon\Carbon;
use Illuminate\Support\Facades\Lang;
use Winter\Storm\Exception\ApplicationException;
use Winter\Storm\Support\Facades\DB;
use Winter\Storm\Support\Facades\DbDongle;
use Winter\Storm\Support\Str;








class Filter extends WidgetBase
{







    public $scopes;





    public $context;








    protected $defaultAlias = 'filter';




    protected $scopesDefined = false;




    protected $allScopes = [];




    protected $scopeModels = [];




    public $cssClasses = [];




    public function init()
    {
        $this->fillFromConfig([
            'scopes',
            'context',
        ]);
    }




    public function render()
    {
        $this->prepareVars();
        return $this->makePartial('filter');
    }




    public function prepareVars()
    {
        $this->defineFilterScopes();
        $this->vars['cssClasses'] = implode(' ', $this->cssClasses);
        $this->vars['scopes'] = $this->allScopes;
    }




    public function renderScopeElement($scope)
    {
        $params = ['scope' => $scope];

        switch ($scope->type) {
            case 'date':
                if ($scope->value && $scope->value instanceof Carbon) {
                    $params['dateStr'] = Backend::dateTime($scope->value, ['formatAlias' => 'dateMin']);
                    $params['date']    = $scope->value->format('Y-m-d H:i:s');
                }

                break;
            case 'daterange':
                if ($scope->value && is_array($scope->value) && count($scope->value) === 2 &&
                    $scope->value[0] && $scope->value[0] instanceof Carbon &&
                    $scope->value[1] && $scope->value[1] instanceof Carbon
                ) {
                    $after = $scope->value[0]->format('Y-m-d H:i:s');
                    $before = $scope->value[1]->format('Y-m-d H:i:s');

                    if (strcasecmp($after, '0000-01-01 00:00:00') > 0) {
                        $params['afterStr'] = Backend::dateTime($scope->value[0], ['formatAlias' => 'dateMin']);
                        $params['after']    = $after;
                    }
                    else {
                        $params['afterStr'] = '-∞';
                        $params['after']    = null;
                    }

                    if (strcasecmp($before, '2999-12-31 23:59:59') < 0) {
                        $params['beforeStr'] = Backend::dateTime($scope->value[1], ['formatAlias' => 'dateMin']);
                        $params['before']    = $before;
                    }
                    else {
                        $params['beforeStr'] = '∞';
                        $params['before']    = null;
                    }
                }

                break;

            case 'number':
            case 'numberrange':
                if ($minInput = array_get($scope->config, 'min')) {
                    $params['minValue'] = is_numeric($minInput) ? $minInput : null;
                }

                if ($maxInput = array_get($scope->config, 'max')) {
                    $params['maxValue'] = is_numeric($maxInput) ? $maxInput : null;
                }

                if ($step = array_get($scope->config, 'step')) {
                    $params['step'] = is_numeric($step) ? $step : null;
                }


            case 'number':
                if (is_numeric($scope->value)) {
                    $params['number'] = $scope->value;
                }

                break;

            case 'numberrange':
                if (
                    $scope->value
                    && (is_array($scope->value) && count($scope->value) === 2)
                    && (isset($scope->value[0]) || isset($scope->value[1]))
                ) {
                    $min = $scope->value[0];
                    $max = $scope->value[1];

                    $params['minStr'] = $min ?? '-∞';
                    $params['min'] = $min ?? null;

                    $params['maxStr'] = $max ?? '∞';
                    $params['max'] = $max ?? null;
                }

                break;

            case 'text':
                $params['value'] = $scope->value;
                $params['size'] = array_get($scope->config, 'size', 10);

                break;

            case 'button-group':
            case 'dropdown':
                $params['value'] = $scope->value;
                if (is_array($options = $this->getOptionsFromArray($scope))) {
                    $scope->options = $options;
                }

                break;
        }

        return $this->makePartial('scope_'.$scope->type, $params);
    }






    protected function getScopeDepends($scope)
    {
        if (!$scope->dependsOn) {
            return '';
        }

        $dependsOn = is_array($scope->dependsOn) ? $scope->dependsOn : [$scope->dependsOn];
        $dependsOn = htmlspecialchars(json_encode($dependsOn), ENT_QUOTES, 'UTF-8');
        return $dependsOn;
    }









    public function onFilterUpdate()
    {
        $this->defineFilterScopes();

        if (!$scope = post('scopeName')) {
            return;
        }

        $scope = $this->getScope($scope);

        switch ($scope->type) {
            case 'group':
                $data = json_decode(post('options'), true);
                $active = $this->optionsFromAjax($data ?: null);
                $this->setScopeValue($scope, $active);
                break;

            case 'button-group':
            case 'dropdown':
                $this->setScopeValue($scope, post('value') ?: null);
                break;

            case 'checkbox':
                $checked = post('value') == 'true';
                $this->setScopeValue($scope, $checked);
                break;

            case 'switch':
                $value = post('value');
                $this->setScopeValue($scope, $value);
                break;

            case 'date':
                $data = json_decode(post('options'), true);
                $dates = $this->datesFromAjax($data['dates'] ?? null);

                if (!empty($dates)) {
                    list($date) = $dates;
                }
                else {
                    $date = null;
                }

                $this->setScopeValue($scope, $date);
                break;

            case 'daterange':
                $data = json_decode(post('options'), true);
                $dates = $this->datesFromAjax($data['dates'] ?? null);

                if (!empty($dates)) {
                    list($after, $before) = $dates;

                    $dates = [$after, $before];
                }
                else {
                    $dates = null;
                }

                $this->setScopeValue($scope, $dates);
                break;

            case 'number':
                $data = json_decode(post('options'), true);
                $numbers = $this->numbersFromAjax($data['numbers'] ?? null);

                if (!empty($numbers)) {
                    list($number) = $numbers;
                }
                else {
                    $number = null;
                }

                $this->setScopeValue($scope, $number);
                break;

            case 'numberrange':
                $data = json_decode(post('options'), true);
                $numbers = $this->numbersFromAjax($data['numbers'] ?? null);

                if (!empty($numbers)) {
                    list($min, $max) = $numbers;

                    $numbers = [$min, $max];
                }
                else {
                    $numbers = null;
                }

                $this->setScopeValue($scope, $numbers);
                break;

            case 'text':
                $value = post('options.value.' . $scope->scopeName) ?: null;
                $this->setScopeValue($scope, $value);
                break;
        }




        $params = func_get_args();

        $result = $this->fireEvent('filter.update', [$params]);

        if ($result && is_array($result)) {
            return call_user_func_array('array_merge', $result);
        }
    }





    public function onFilterGetOptions()
    {
        $this->defineFilterScopes();

        $searchQuery = post('search');
        if (!$scopeName = post('scopeName')) {
            return;
        }

        $scope = $this->getScope($scopeName);
        $activeKeys = $scope->value ? array_keys($scope->value) : [];
        $available = $this->getAvailableOptions($scope, $searchQuery);
        $active = $searchQuery ? [] : $this->filterActiveOptions($activeKeys, $available);

        return [
            'scopeName' => $scopeName,
            'options' => [
                'available' => $this->optionsToAjax($available),
                'active'    => $this->optionsToAjax($active),
            ]
        ];
    }













    protected function getAvailableOptions($scope, $searchQuery = null)
    {
        if ($scope->options) {
            return $this->getOptionsFromArray($scope, $searchQuery);
        }

        $available = [];
        $nameColumn = $this->getScopeNameFrom($scope);
        $options = $this->getOptionsFromModel($scope, $searchQuery);
        foreach ($options as $option) {
            $available[$option->getKey()] = $option->{$nameColumn};
        }

        return $available;
    }








    protected function filterActiveOptions(array $activeKeys, array &$availableOptions)
    {
        $active = [];
        foreach ($availableOptions as $id => $option) {
            if (!in_array($id, $activeKeys)) {
                continue;
            }

            $active[$id] = $option;
            unset($availableOptions[$id]);
        }

        return $active;
    }








    protected function getOptionsFromModel($scope, $searchQuery = null)
    {
        $model = $this->scopeModels[$scope->scopeName];

        $query = $model->newQuery();


        $query->limit(250);






















        $this->fireSystemEvent('backend.filter.extendQuery', [$query, $scope]);

        if (!$searchQuery) {

            if ($scope->value) {
                $modelIds = array_keys($scope->value);
                $activeOptions = $model::findMany($modelIds);
            }

            $modelOptions = isset($activeOptions)
                ? $query->get()->merge($activeOptions)
                : $query->get();

            return $modelOptions;
        }

        $searchFields = [$model->getKeyName(), $this->getScopeNameFrom($scope)];
        return $query->searchWhere($searchQuery, $searchFields)->get();
    }





    protected function getOptionsFromArray($scope, $searchQuery = null)
    {



        $options = $scope->options;

        if (is_scalar($options)) {
            $model = $this->scopeModels[$scope->scopeName];
            $methodName = $options;

            if (str_contains($methodName, '::')) {
                $options = Lang::get($methodName);
                if (!is_array($options)) {
                    $options = [];
                }
            } else {
                if (!$model->methodExists($methodName)) {
                    throw new ApplicationException(Lang::get('backend::lang.filter.options_method_not_exists', [
                        'model'  => get_class($model),
                        'method' => $methodName,
                        'filter' => $scope->scopeName
                    ]));
                }

                if (!empty($scope->dependsOn)) {
                    $options = $model->$methodName($this->getScopes());
                } else {
                    $options = $model->$methodName();
                }
            }
        }
        elseif (!is_array($options)) {
            $options = [];
        }




        $searchQuery = Str::lower($searchQuery);
        if (strlen($searchQuery)) {
            $options = $this->filterOptionsBySearch($options, $searchQuery);
        }

        return $options;
    }







    protected function filterOptionsBySearch($options, $query)
    {
        $filteredOptions = [];

        $optionMatchesSearch = function ($words, $option) {
            foreach ($words as $word) {
                $word = trim($word);
                if (!strlen($word)) {
                    continue;
                }

                if (!Str::contains(Str::lower($option), $word)) {
                    return false;
                }
            }

            return true;
        };




        foreach ($options as $index => $option) {
            if (Str::is(Str::lower($option), $query)) {
                $filteredOptions[$index] = $option;
                unset($options[$index]);
            }
        }




        $words = explode(' ', $query);
        foreach ($options as $index => $option) {
            if ($optionMatchesSearch($words, $option)) {
                $filteredOptions[$index] = $option;
            }
        }

        return $filteredOptions;
    }




    protected function defineFilterScopes()
    {
        if ($this->scopesDefined) {
            return;
        }


















        $this->fireSystemEvent('backend.filter.extendScopesBefore');




        if (!isset($this->scopes) || !is_array($this->scopes)) {
            $this->scopes = [];
        }

        $this->addScopes($this->scopes);






















        $this->fireSystemEvent('backend.filter.extendScopes');

        $this->scopesDefined = true;
    }




    public function addScopes(array $scopes)
    {
        foreach ($scopes as $name => $config) {



            $permissions = array_get($config, 'permissions');
            if (!empty($permissions) && !BackendAuth::getUser()->hasAccess($permissions, false)) {
                continue;
            }

            $scopeObj = $this->makeFilterScope($name, $config);




            if ($scopeObj->context !== null) {
                $context = is_array($scopeObj->context) ? $scopeObj->context : [$scopeObj->context];
                if (!in_array($this->getContext(), $context)) {
                    continue;
                }
            }




            if (isset($config['modelClass'])) {
                $class = $config['modelClass'];
                $model = new $class;
                $this->scopeModels[$name] = $model;
            }




            $scopeProperties = [];
            switch ($scopeObj->type) {
                case 'date':
                case 'daterange':
                    $scopeProperties = [
                        'minDate'   => '2000-01-01',
                        'maxDate'   => '2099-12-31',
                        'firstDay'  => 0,
                        'yearRange' => 10,
                        'ignoreTimezone' => false,
                    ];

                    break;
            }

            foreach ($scopeProperties as $property => $value) {
                if (isset($config[$property])) {
                    $value = $config[$property];
                }

                $scopeObj->{$property} = $value;
            }

            $this->allScopes[$name] = $scopeObj;
        }
    }





    public function removeScope($scopeName)
    {
        if (isset($this->allScopes[$scopeName])) {
            unset($this->allScopes[$scopeName]);
        }
    }




    protected function makeFilterScope($name, $config)
    {
        $label = $config['label'] ?? null;
        $scopeType = $config['type'] ?? null;

        $scope = new FilterScope($name, $label);
        $scope->displayAs($scopeType, $config);
        $scope->idPrefix = $this->alias;




        $scope->value = $this->getScopeValue($scope, @$config['default']);

        return $scope;
    }










    public function applyAllScopesToQuery($query)
    {
        $this->defineFilterScopes();

        foreach ($this->allScopes as $scope) {

            if ($scope->type === 'group') {
                $activeKeys = $scope->value ? array_keys($scope->value) : [];
                $available = $this->getAvailableOptions($scope);
                $active = $this->filterActiveOptions($activeKeys, $available);
                $value = !empty($active) ? $active : null;
                $this->setScopeValue($scope, $value);
            }

            $this->applyScopeToQuery($scope, $query);
        }

        return $query;
    }







    public function applyScopeToQuery($scope, $query)
    {
        if (is_string($scope)) {
            $scope = $this->getScope($scope);
        }

        if (!$scope->value) {
            return;
        }

        switch ($scope->type) {
            case 'date':
                if ($scope->value instanceof Carbon) {
                    $value = $scope->value;




                    if ($scopeConditions = $scope->conditions) {
                        [$sql, $bindings] = $this->processConditionBindings($scopeConditions, [
                            'filtered' => $value->format('Y-m-d'),
                            'after'    => $value->format('Y-m-d H:i:s'),
                            'before'   => $value->copy()->addDay()->addMinutes(-1)->format('Y-m-d H:i:s'),
                        ]);

                        $query->whereRaw(DbDongle::parse($sql), $bindings);
                    }



                    elseif ($scopeMethod = $scope->scope) {
                        $query->$scopeMethod($value);
                    }
                }

                break;

            case 'daterange':
                if (is_array($scope->value) && count($scope->value) > 1) {
                    list($after, $before) = array_values($scope->value);

                    if ($after && $after instanceof Carbon && $before && $before instanceof Carbon) {



                        if ($scopeConditions = $scope->conditions) {
                            [$sql, $bindings] = $this->processConditionBindings($scopeConditions, [
                                'afterDate'  => $after->format('Y-m-d'),
                                'after'      => $after->format('Y-m-d H:i:s'),
                                'beforeDate' => $before->format('Y-m-d'),
                                'before'     => $before->format('Y-m-d H:i:s'),
                            ]);

                            $query->whereRaw(DbDongle::parse($sql), $bindings);
                        }



                        elseif ($scopeMethod = $scope->scope) {
                            $query->$scopeMethod($after, $before);
                        }
                    }
                }

                break;

            case 'number':
                if (is_numeric($scope->value)) {



                    if ($scopeConditions = $scope->conditions) {
                        [$sql, $bindings] = $this->processConditionBindings($scopeConditions, [
                            'filtered' => (float) $scope->value,
                        ]);

                        $query->whereRaw(DbDongle::parse($sql), $bindings);
                    }



                    elseif ($scopeMethod = $scope->scope) {
                        $query->$scopeMethod($scope->value);
                    }
                }

                break;

            case 'numberrange':
                if (is_array($scope->value) && count($scope->value) > 1) {
                    list($min, $max) = array_values($scope->value);

                    if (isset($min) || isset($max)) {



                        if ($scopeConditions = $scope->conditions) {
                            [$sql, $bindings] = $this->processConditionBindings($scopeConditions, [
                                'min' => $min === null ? -2147483647 : (float) $min,
                                'max' => $max === null ? 2147483647 : (float) $max,
                            ]);

                            $query->whereRaw(DbDongle::parse($sql), $bindings);
                        }



                        elseif ($scopeMethod = $scope->scope) {
                            $query->$scopeMethod($min, $max);
                        }
                    }
                }

                break;

            case 'text':



                if ($scopeConditions = $scope->conditions) {
                    $query->whereRaw(DbDongle::parse(strtr($scopeConditions, [
                        ':value' => DB::getPdo()->quote($scope->value),
                    ])));
                }




                elseif ($scopeMethod = $scope->scope) {
                    $query->$scopeMethod($scope->value);
                }

                break;

            default:
                $value = is_array($scope->value) ? array_keys($scope->value) : $scope->value;

                if (empty($value)) {
                    break;
                }




                if ($scopeConditions = $scope->conditions) {



                    if (is_array($scopeConditions)) {
                        $conditionNum = is_array($value) ? 0 : $value - 1;
                        list($scopeConditions) = array_slice($scopeConditions, $conditionNum);
                    }

                    if (is_array($value)) {
                        $filtered = implode(',', array_build($value, function ($key, $_value) {
                            return [$key, DB::getPdo()->quote($_value)];
                        }));
                    }
                    else {
                        $filtered = DB::getPdo()->quote($value);
                    }

                    $query->whereRaw(DbDongle::parse(strtr($scopeConditions, [':filtered' => $filtered])));
                }



                elseif ($scopeMethod = $scope->scope) {
                    $query->$scopeMethod($value);
                }

                break;
        }

        return $query;
    }








    public function getScopeValue($scope, $default = null)
    {
        if (is_string($scope)) {
            $scope = $this->getScope($scope);
        }

        $cacheKey = 'scope-'.$scope->scopeName;
        return $this->getSession($cacheKey, $default);
    }




    public function setScopeValue($scope, $value)
    {
        if (is_string($scope)) {
            $scope = $this->getScope($scope);
        }

        $cacheKey = 'scope-'.$scope->scopeName;
        $this->putSession($cacheKey, $value);

        $scope->value = $value;
    }





    public function getScopes()
    {
        return $this->allScopes;
    }






    public function getScope($scope)
    {
        if (!isset($this->allScopes[$scope])) {
            throw new ApplicationException('No definition for scope ' . $scope);
        }

        return $this->allScopes[$scope];
    }






    public function getScopeNameFrom($scope)
    {
        if (is_string($scope)) {
            $scope = $this->getScope($scope);
        }

        return $scope->nameFrom;
    }





    public function getContext()
    {
        return $this->context;
    }










    protected function optionsToAjax($options)
    {
        $processed = [];
        foreach ($options as $id => $result) {
            $processed[] = ['id' => $id, 'name' => trans($result)];
        }
        return $processed;
    }






    protected function optionsFromAjax($options)
    {
        $processed = [];
        if (!is_array($options)) {
            return $processed;
        }

        foreach ($options as $option) {
            $id = array_get($option, 'id');
            if ($id === null) {
                continue;
            }
            $processed[$id] = array_get($option, 'name');
        }
        return $processed;
    }








    protected function datesFromAjax($ajaxDates)
    {
        $dates = [];
        $dateRegex = '/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/';

        if (null !== $ajaxDates) {
            if (!is_array($ajaxDates)) {
                if (preg_match($dateRegex, $ajaxDates)) {
                    $dates = [$ajaxDates];
                }
            } else {
                foreach ($ajaxDates as $i => $date) {
                    if (preg_match($dateRegex, $date)) {
                        $dates[] = Carbon::createFromFormat('Y-m-d H:i:s', $date);
                    } elseif (empty($date)) {
                        if ($i == 0) {
                            $dates[] = Carbon::createFromFormat('Y-m-d H:i:s', '0000-01-01 00:00:00');
                        } else {
                            $dates[] = Carbon::createFromFormat('Y-m-d H:i:s', '2999-12-31 23:59:59');
                        }
                    } else {
                        $dates = [];
                        break;
                    }
                }
            }
        }
        return $dates;
    }








    protected function numbersFromAjax($ajaxNumbers)
    {
        $numbers = [];

        if (!empty($ajaxNumbers)) {
            if (!is_array($ajaxNumbers)) {
                if (is_numeric($ajaxNumbers)) {
                    $numbers = [(float) $ajaxNumbers];
                }
            } else {
                foreach ($ajaxNumbers as $number) {
                    if (is_numeric($number)) {
                        $numbers[] = (float) $number;
                    } else {
                        $numbers[] = null;
                    }
                }
            }
        }

        return $numbers;
    }












    protected function processConditionBindings(string $conditions, array $namedBindings): array
    {
        $orderedBindings = [];





        $processedSql = preg_replace_callback("/(?:':(\\w+)'|:(\\w+))/", function ($matches) use ($namedBindings, &$orderedBindings) {
            $name = $matches[1] !== '' ? $matches[1] : $matches[2];
            if (array_key_exists($name, $namedBindings)) {
                $orderedBindings[] = $namedBindings[$name];
                return '?';
            }
            return $matches[0];
        }, $conditions);

        return [$processedSql, $orderedBindings];
    }






    protected function getFilterDateFormat($scope)
    {
        if (isset($scope->date_format)) {
            return $scope->date_format;
        }

        return trans('backend::lang.filter.date.format');
    }
}
