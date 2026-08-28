<?php namespace Backend\Widgets;

use Lang;
use Backend\Classes\WidgetBase;








class Search extends WidgetBase
{







    public $prompt;




    public $growable = true;




    public $partial;




    public $mode;




    public $scope;




    public $searchOnEnter = false;








    protected $defaultAlias = 'search';




    protected $activeTerm;




    public $cssClasses = [];




    public function init()
    {
        $this->fillFromConfig([
            'prompt',
            'partial',
            'growable',
            'scope',
            'mode',
            'searchOnEnter',
        ]);




        $this->cssClasses[] = 'icon search';

        if ($this->growable) {
            $this->cssClasses[] = 'growable';
        }
    }




    public function render()
    {
        $this->prepareVars();

        if ($this->partial) {
            return $this->controller->makePartial($this->partial);
        }

        return $this->makePartial('search');
    }




    public function prepareVars()
    {
        $this->vars['cssClasses'] = implode(' ', $this->cssClasses);
        $this->vars['placeholder'] = Lang::get($this->prompt);
        $this->vars['value'] = $this->getActiveTerm();
        $this->vars['searchOnEnter'] = $this->searchOnEnter;
    }




    public function onSubmit()
    {



        $this->setActiveTerm(post($this->getName()));




        $params = func_get_args();
        try {
            $result = $this->fireEvent('search.submit', [$params]);
        } catch (\Throwable $e) {

            $this->setActiveTerm('');
            throw $e;
        }

        if ($result && is_array($result)) {
            return call_user_func_array('array_merge', $result);
        }
    }




    public function getActiveTerm()
    {
        return $this->activeTerm = $this->getSession('term', '');
    }




    public function setActiveTerm($term)
    {
        if (strlen($term)) {
            $this->putSession('term', $term);
        } else {
            $this->resetSession();
        }

        $this->activeTerm = $term;
    }





    public function getName()
    {
        return $this->alias . '[term]';
    }
}
