<?php namespace Backend\Classes;






class QuickActionItem
{



    public $code;




    public $owner;




    public $label;




    public $icon;




    public $iconSvg;




    public $url;




    public $order = -1;




    public $attributes = [];




    public $permissions = [];





    public function addAttribute($attribute, $value)
    {
        $this->attributes[$attribute] = $value;
    }

    public function removeAttribute($attribute)
    {
        unset($this->attributes[$attribute]);
    }





    public function addPermission(string $permission, array $definition)
    {
        $this->permissions[$permission] = $definition;
    }





    public function removePermission(string $permission)
    {
        unset($this->permissions[$permission]);
    }





    public static function createFromArray(array $data)
    {
        $instance = new static();
        $instance->code = $data['code'];
        $instance->owner = $data['owner'];
        $instance->label = $data['label'];
        $instance->url = $data['url'];
        $instance->icon = $data['icon'] ?? null;
        $instance->iconSvg = $data['iconSvg'] ?? null;
        $instance->attributes = $data['attributes'] ?? $instance->attributes;
        $instance->permissions = $data['permissions'] ?? $instance->permissions;
        $instance->order = (!empty($data['order']) || @$data['order'] === 0) ? (int) $data['order'] : $instance->order;
        return $instance;
    }
}
