<?php namespace Backend\Widgets;

use Config;
use Backend;
use Lang;
use Input;
use Request;
use Backend\Classes\WidgetBase;
use Winter\Storm\Html\Helper as HtmlHelper;
use SystemException;









class Table extends WidgetBase
{



    protected $defaultAlias = 'table';




    protected $columns = [];




    protected $showHeader = true;




    protected $dataSource;




    protected $fieldName;




    protected $recordsKeyFrom;

    protected $dataSourceAliases = [
        'client' => '\Backend\Widgets\Table\ClientMemoryDataSource',
        'server' => '\Backend\Widgets\Table\ServerEventDataSource'
    ];




    public function init()
    {
        $this->columns = $this->getConfig('columns', []);

        $this->fieldName = $this->getConfig('fieldName', $this->alias);

        $this->recordsKeyFrom = $this->getConfig('keyFrom', 'id');

        $dataSourceClass = $this->getConfig('dataSource');
        if (!strlen($dataSourceClass)) {
            throw new SystemException('The Table widget data source is not specified in the configuration.');
        }

        if (array_key_exists($dataSourceClass, $this->dataSourceAliases)) {
            $dataSourceClass = $this->dataSourceAliases[$dataSourceClass];
        }

        if (!class_exists($dataSourceClass)) {
            throw new SystemException(sprintf('The Table widget data source class "%s" is could not be found.', $dataSourceClass));
        }

        $this->dataSource = new $dataSourceClass($this->recordsKeyFrom);

        if (Request::method() == 'POST' && $this->isClientDataSource()) {

            $requestDataField = implode('.', HtmlHelper::nameToArray($this->fieldName));

            if (Request::exists($requestDataField)) {

                $this->dataSource->purge();
                $this->dataSource->initRecords(Request::input($requestDataField));
            }
        }
    }





    public function getDataSource()
    {
        return $this->dataSource;
    }




    public function render()
    {
        $this->prepareVars();
        return $this->makePartial('table');
    }




    public function prepareVars()
    {
        $this->vars['columns'] = $this->prepareColumnsArray();
        $this->vars['recordsKeyFrom'] = $this->recordsKeyFrom;

        $this->vars['recordsPerPage'] = $this->getConfig('recordsPerPage', false) ?: 'false';
        $this->vars['postbackHandlerName'] = $this->getConfig('postbackHandlerName');
        $this->vars['searching'] = $this->getConfig('searching', false);
        $this->vars['adding'] = $this->getConfig('adding', true);
        $this->vars['deleting'] = $this->getConfig('deleting', true);
        $this->vars['toolbar'] = $this->getConfig('toolbar', true);
        $this->vars['height'] = $this->getConfig('height', false) ?: 'false';
        $this->vars['dynamicHeight'] = $this->getConfig('dynamicHeight', false) ?: 'false';

        $this->vars['btnAddRowLabel'] = Lang::get($this->getConfig('btnAddRowLabel', 'backend::lang.form.insert_row'));
        $this->vars['btnAddRowBelowLabel'] = Lang::get($this->getConfig('btnAddRowBelowLabel', 'backend::lang.form.insert_row_below'));
        $this->vars['btnDeleteRowLabel'] = Lang::get($this->getConfig('btnDeleteRowLabel', 'backend::lang.form.delete_row'));

        $isClientDataSource = $this->isClientDataSource();

        $this->vars['clientDataSourceClass'] = $isClientDataSource ? 'client' : 'server';
        $this->vars['data'] = json_encode(
            $isClientDataSource ? $this->dataSource->getAllRecords() : []
        );
    }








    protected function loadAssets()
    {
        $this->addCss('css/table.css', 'core');

        if (Config::get('develop.decompileBackendAssets', false)) {
            $scripts = Backend::decompileAsset($this->getAssetPath('js/build.js'));
            foreach ($scripts as $script) {
                $this->addJs($script, 'core');
            }
        } else {
            $this->addJs('js/build-min.js', 'core');
        }
    }








    protected function prepareColumnsArray()
    {
        $result = [];

        foreach ($this->columns as $key => $data) {
            $data['key'] = $key;

            if (isset($data['title'])) {
                $data['title'] = trans($data['title']);
            }

            if (isset($data['options'])) {
                foreach ($data['options'] as &$option) {
                    $option = trans($option);
                }
            }

            if (isset($data['validation'])) {
                foreach ($data['validation'] as &$validation) {
                    if (isset($validation['message'])) {
                        $validation['message'] = trans($validation['message']);
                    }
                }
            }

            $result[] = $data;
        }

        return $result;
    }

    protected function isClientDataSource()
    {
        return $this->dataSource instanceof \Backend\Widgets\Table\ClientMemoryDataSource;
    }





    public function onServerGetRecords()
    {

        $this->controller->flushAssets();

        if ($this->isClientDataSource()) {
            throw new SystemException('The Table widget is not configured to use the server data source.');
        }

        $count = post('count');


        if ($count === 'false') {
            $count = false;
        }

        return [
            'records' => $this->dataSource->getRecords(post('offset'), $count),
            'count' => $this->dataSource->getCount()
        ];
    }

    public function onServerSearchRecords()
    {

        $this->controller->flushAssets();

        if ($this->isClientDataSource()) {
            throw new SystemException('The Table widget is not configured to use the server data source.');
        }

        $count = post('count');


        if ($count === 'false') {
            $count = false;
        }

        return [
            'records' => $this->dataSource->searchRecords(post('query'), post('offset'), $count),
            'count' => $this->dataSource->getCount()
        ];
    }

    public function onServerCreateRecord()
    {
        if ($this->isClientDataSource()) {
            throw new SystemException('The Table widget is not configured to use the server data source.');
        }

        $this->dataSource->createRecord(
            post('recordData'),
            post('placement'),
            post('relativeToKey')
        );

        return $this->onServerGetRecords();
    }

    public function onServerUpdateRecord()
    {
        if ($this->isClientDataSource()) {
            throw new SystemException('The Table widget is not configured to use the server data source.');
        }

        $this->dataSource->updateRecord(post('key'), post('recordData'));
    }

    public function onServerDeleteRecord()
    {
        if ($this->isClientDataSource()) {
            throw new SystemException('The Table widget is not configured to use the server data source.');
        }

        $this->dataSource->deleteRecord(post('key'));

        return $this->onServerGetRecords();
    }

    public function onGetDropdownOptions()
    {
        $columnName = Input::get('column');
        $rowData = Input::get('rowData');

        $eventResults = $this->fireEvent('table.getDropdownOptions', [$columnName, $rowData]);

        $options = [];
        if (count($eventResults)) {
            $options = $eventResults[0];
        }

        return [
            'options' => $options
        ];
    }

    public function onGetAutocompleteOptions()
    {
        $columnName = Input::get('column');
        $rowData = Input::get('rowData');

        $eventResults = $this->fireEvent('table.getAutocompleteOptions', [$columnName, $rowData]);

        $options = [];
        if (count($eventResults)) {
            $options = $eventResults[0];
        }

        return [
            'options' => $options
        ];
    }
}
