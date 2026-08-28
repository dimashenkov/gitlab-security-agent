<?php namespace Backend\Widgets;

use Backend\Classes\WidgetBase;








class Toolbar extends WidgetBase
{







    public $buttons;




    public $search;








    protected $defaultAlias = 'toolbar';




    protected $searchWidget;




    public $cssClasses = [];




    public function init()
    {
        $this->fillFromConfig([
            'buttons',
            'search',
        ]);




        if (isset($this->search)) {
            if (is_string($this->search)) {
                $searchConfig = $this->makeConfig(['partial' => $this->search]);
            }
            else {
                $searchConfig = $this->makeConfig($this->search);
            }

            $searchConfig->alias = $this->alias . 'Search';
            $this->searchWidget = $this->makeWidget('Backend\Widgets\Search', $searchConfig);
            $this->searchWidget->bindToController();
        }
    }




    public function render()
    {
        $this->prepareVars();
        return $this->makePartial('toolbar');
    }




    public function prepareVars()
    {
        $this->vars['search'] = $this->searchWidget ? $this->searchWidget->render() : '';
        $this->vars['cssClasses'] = implode(' ', $this->cssClasses);
        $this->vars['controlPanel'] = $this->makeControlPanel();
    }

    public function getSearchWidget()
    {
        return $this->searchWidget;
    }

    public function makeControlPanel()
    {
        if (!isset($this->buttons)) {
            return false;
        }

        return $this->controller->makePartial($this->buttons, $this->vars);
    }
}
