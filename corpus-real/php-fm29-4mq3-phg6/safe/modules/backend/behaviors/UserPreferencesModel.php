<?php namespace Backend\Behaviors;

use System\Behaviors\SettingsModel;
use Backend\Models\UserPreference;
use Winter\Storm\Database\Model;












class UserPreferencesModel extends SettingsModel
{



    private static $instances = [];




    public function __construct($model)
    {
        parent::__construct($model);

        $this->model->setTable('backend_user_preferences');
    }




    public function instance()
    {
        if (isset(self::$instances[$this->recordCode])) {
            return self::$instances[$this->recordCode];
        }

        if (!$item = $this->getSettingsRecord()) {
            $this->model->initSettingsData();
            $item = $this->model;
        }

        return self::$instances[$this->recordCode] = $item;
    }




    public function isConfigured(): bool
    {
        return $this->getSettingsRecord() !== null;
    }




    public function getSettingsRecord(): ?Model
    {
        $item = UserPreference::forUser();
        $record = $item
            ->scopeApplyKeyAndUser($this->model, $this->recordCode, $item->userContext)
            ->remember(1440, $this->getCacheKey())
            ->first();

        return $record ?: null;
    }





    public function beforeModelSave()
    {
        $preferences = UserPreference::forUser();
        list($namespace, $group, $item) = $preferences->parseKey($this->recordCode);
        $this->model->item = $item;
        $this->model->group = $group;
        $this->model->namespace = $namespace;
        $this->model->user_id = $preferences->userContext->id;

        if ($this->fieldValues) {
            $this->model->value = $this->fieldValues;
        }
    }





    protected function isKeyAllowed($key)
    {



        if ($key == 'namespace' || $key == 'group') {
            return true;
        }

        return parent::isKeyAllowed($key);
    }




    protected function getCacheKey()
    {
        $item = UserPreference::forUser();
        $userId = $item->userContext ? $item->userContext->id : 0;
        return $this->recordCode.'-userpreference-'.$userId;
    }
}
