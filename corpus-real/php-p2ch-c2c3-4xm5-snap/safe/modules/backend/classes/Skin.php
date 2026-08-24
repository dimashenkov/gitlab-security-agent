<?php namespace Backend\Classes;

use File;
use Config;
use Winter\Storm\Router\Helper as RouterHelper;








abstract class Skin
{



    abstract public function skinDetails();




    public $skinPath;




    public $publicSkinPath;




    public $defaultSkinPath;




    public $defaultPublicSkinPath;




    private static $skinCache;




    public function __construct()
    {
        $this->defaultSkinPath = base_path() . '/modules/backend';




        $class = get_called_class();
        $classFolder = strtolower(class_basename($class));
        $classFile = realpath(dirname(File::fromClass($class)));
        $this->skinPath = $classFile
            ? $classFile . '/' . $classFolder
            : $this->defaultSkinPath;

        $this->publicSkinPath = File::localToPublic($this->skinPath);
        $this->defaultPublicSkinPath = File::localToPublic($this->defaultSkinPath);
    }







    public function getPath($path = null, $isPublic = false)
    {
        $path = RouterHelper::normalizeUrl($path);
        $assetFile = $this->skinPath . $path;

        if (File::isFile($assetFile)) {
            return $isPublic
                ? $this->publicSkinPath . $path
                : $this->skinPath . $path;
        }

        return $isPublic
            ? $this->defaultPublicSkinPath . $path
            : $this->defaultSkinPath . $path;
    }





    public function getLayoutPaths()
    {
        return [$this->skinPath.'/layouts', $this->defaultSkinPath.'/layouts'];
    }




    public static function getActive()
    {
        if (self::$skinCache !== null) {
            return self::$skinCache;
        }

        $skinClass = Config::get('cms.backendSkin');
        $skinObject = new $skinClass();
        return self::$skinCache = $skinObject;
    }
}
