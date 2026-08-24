<?php namespace Backend\Classes;








class ReportWidgetBase extends WidgetBase
{
    use \System\Traits\PropertyContainer;

    public function __construct($controller, $properties = [])
    {
        $this->properties = $this->validateProperties($properties);





        if (!isset($this->alias)) {
            $this->alias = $properties['alias'] ?? $this->defaultAlias;
        }

        parent::__construct($controller);
    }
}
