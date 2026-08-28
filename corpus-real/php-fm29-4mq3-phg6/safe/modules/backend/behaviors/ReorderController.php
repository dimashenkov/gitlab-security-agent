<?php namespace Backend\Behaviors;

use Lang;
use Backend;
use ApplicationException;
use Backend\Classes\ControllerBehavior;



















class ReorderController extends ControllerBehavior
{



    protected $requiredConfig = ['modelClass'];




    protected $actions = ['reorder'];




    public $model;




    public $nameFrom = 'name';




    protected $showTree = false;






    protected $sortMode;




    protected $toolbarWidget;




    public $reorderConfig = 'config_reorder.yaml';





    public function __construct($controller)
    {
        parent::__construct($controller);




        $this->config = $this->makeConfig($controller->reorderConfig ?: $this->reorderConfig, $this->requiredConfig);




        if ($this->toolbarWidget = $this->makeToolbarWidget()) {
            $this->toolbarWidget->bindToController();
        }




        $this->nameFrom = $this->getConfig('nameFrom', $this->nameFrom);
    }





    public function reorder()
    {
        $this->addJs('js/winter.reorder.js', 'core');

        $this->controller->pageTitle = $this->controller->pageTitle
            ?: Lang::get($this->getConfig('title', 'backend::lang.reorder.default_title'));

        $this->validateModel();
        $this->prepareVars();
    }





    public function onReorder()
    {
        $model = $this->validateModel();




        if ($this->sortMode == 'simple') {
            if (
                (!$ids = post('record_ids')) ||
                (!$orders = post('sort_orders'))
            ) {
                return;
            }

            $model->setSortableOrder($ids, $orders);
        }



        elseif ($this->sortMode == 'nested') {
            $sourceNode = $model->find(post('sourceNode'));
            $targetNode = post('targetNode') ? $model->find(post('targetNode')) : null;

            if ($sourceNode == $targetNode) {
                return;
            }

            switch (post('position')) {
                case 'before':
                    $sourceNode->moveBefore($targetNode);
                    break;

                case 'after':
                    $sourceNode->moveAfter($targetNode);
                    break;

                case 'child':
                    $sourceNode->makeChildOf($targetNode);
                    break;

                default:
                    $sourceNode->makeRoot();
                    break;
            }
        }
    }








    protected function prepareVars()
    {
        $this->vars['reorderRecords'] = $this->getRecords();
        $this->vars['reorderModel'] = $this->model;
        $this->vars['reorderSortMode'] = $this->sortMode;
        $this->vars['reorderShowTree'] = $this->showTree;
        $this->vars['reorderToolbarWidget'] = $this->toolbarWidget;
    }

    public function reorderRender()
    {
        return $this->reorderMakePartial('container');
    }

    public function reorderGetModel()
    {
        if ($this->model !== null) {
            return $this->model;
        }

        $modelClass = $this->getConfig('modelClass');

        if (!$modelClass) {
            throw new ApplicationException('Please specify the modelClass property for reordering');
        }

        return $this->model = new $modelClass;
    }





    public function reorderGetRecordName($record)
    {
        return $record->{$this->nameFrom};
    }





    protected function validateModel()
    {
        $model = $this->controller->reorderGetModel();
        $modelTraits = class_uses($model);

        if (
            isset($modelTraits[\Winter\Storm\Database\Traits\Sortable::class]) ||
            $model->isClassExtendedWith(\Winter\Storm\Database\Behaviors\Sortable::class) ||
            isset($modelTraits[\October\Rain\Database\Traits\Sortable::class]) ||
            $model->isClassExtendedWith(\October\Rain\Database\Behaviors\Sortable::class)
        ) {
            $this->sortMode = 'simple';
        }
        elseif (
            isset($modelTraits[\Winter\Storm\Database\Traits\NestedTree::class]) ||
            isset($modelTraits[\October\Rain\Database\Traits\NestedTree::class])
        ) {
            $this->sortMode = 'nested';
            $this->showTree = true;
        }
        else {
            throw new ApplicationException('The model must implement the Sortable trait/behavior or the NestedTree trait.');
        }

        return $model;
    }





    protected function getRecords()
    {
        $records = null;
        $model = $this->controller->reorderGetModel();
        $query = $model->newQuery();

        $this->controller->reorderExtendQuery($query);

        if ($this->sortMode == 'simple') {
            $records = $query
                ->orderBy($model->getSortOrderColumn())
                ->get()
            ;
        }
        elseif ($this->sortMode == 'nested') {
            $records = $query->getNested();
        }

        return $records;
    }







    public function reorderExtendQuery($query)
    {
    }





    protected function makeToolbarWidget()
    {
        if ($toolbarConfig = $this->getConfig('toolbar')) {
            $toolbarConfig = $this->makeConfig($toolbarConfig);
            $toolbarWidget = $this->makeWidget('Backend\Widgets\Toolbar', $toolbarConfig);
        }
        else {
            $toolbarWidget = null;
        }

        return $toolbarWidget;
    }











    public function reorderMakePartial($partial, $params = [])
    {
        $contents = $this->controller->makePartial(
            'reorder_' . $partial,
            $params + $this->vars,
            false
        );

        if (!$contents) {
            $contents = $this->makePartial($partial, $params);
        }

        return $contents;
    }
}
