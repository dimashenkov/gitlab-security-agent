<?php

namespace Backend\Classes;

use Backend\Facades\BackendAuth;
use Closure;
use Illuminate\Routing\Controller as ControllerBase;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\View;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use System\Classes\PluginManager;
use Winter\Storm\Router\Helper as RouterHelper;
use Winter\Storm\Support\Facades\Config;
use Winter\Storm\Support\Facades\Event;
use Winter\Storm\Support\Facades\File;
use Winter\Storm\Support\Str;














class BackendController extends ControllerBase
{
    use \Winter\Storm\Extension\ExtendableTrait;




    public $implement;




    public static $action;




    public static $params;




    protected $cmsHandling = false;






    protected $requestedController;




    public function __construct()
    {
        $this->middleware(function ($request, $next) {


            $response = $next($request);


            $pathParts = explode('/', str_replace(Request::root() . '/', '', Request::url()));
            if (count($pathParts)) {

                if (!empty(Config::get('cms.backendUri', 'backend'))) {
                    array_shift($pathParts);
                }
                $path = implode('/', $pathParts);

                $requestedController = $this->getRequestedController($path);
                if (
                    !is_null($requestedController)
                    && is_array($requestedController)
                    && count($requestedController['controller']->getMiddleware())
                ) {
                    $action = $requestedController['action'];


                    $controllerMiddleware = collect($requestedController['controller']->getMiddleware())
                        ->reject(function ($data) use ($action) {
                            return static::methodExcludedByOptions($action, $data['options']);
                        })
                        ->pluck('middleware');

                    foreach ($controllerMiddleware as $middleware) {
                        $middleware->call($requestedController['controller'], $request, $response);
                    }
                }
            }

            return $response;
        });

        $this->extendableConstruct();
    }




    public function callAction($method, $parameters)
    {
        return parent::callAction($method, array_values($parameters));
    }







    protected function passToCmsController($url)
    {
        if (
            in_array('Cms', Config::get('cms.loadModules', [])) &&
            class_exists('\Cms\Classes\Controller')
        ) {
            $this->cmsHandling = true;
            $response = App::make('Cms\Classes\Controller')->run($url);
            if ($response->getStatusCode() !== 404 || !BackendAuth::check()) {
                return $response;
            }
        }

        return Response::make(View::make('backend::404'), 404);
    }









    public function run($url = null)
    {

        Event::listen('exception.beforeRender', function ($exception, $httpCode, $request) {
            if ($this->cmsHandling) {
                return;
            }

            if ($exception instanceof NotFoundHttpException) {
                return View::make('backend::404');
            } elseif (
                $exception instanceof HttpException
                && $exception->getStatusCode() === 403
            ) {
                return View::make('backend::access_denied');
            }
        }, 1);




        if (!App::hasDatabase()) {
            return Config::get('app.debug', false)
                ? Response::make(View::make('backend::no_database'), 200)
                : $this->passToCmsController($url);
        }

        $controllerRequest = $this->getRequestedController($url);
        if (!is_null($controllerRequest)) {
            return $controllerRequest['controller']->run(
                $controllerRequest['action'],
                $controllerRequest['params']
            );
        }




        return $this->passToCmsController($url);
    }











    protected function getRequestedController($url)
    {
        $params = RouterHelper::segmentizeUrl($url);




        $module = $params[0] ?? 'backend';
        $controller = $params[1] ?? 'index';
        self::$action = $action = isset($params[2]) ? $this->parseAction($params[2]) : 'index';
        self::$params = $controllerParams = array_slice($params, 3);
        $controllerClass = '\\'.$module.'\Controllers\\'.$controller;
        if ($controllerObj = $this->findController(
            $controllerClass,
            $action,
            base_path().'/modules'
        )) {
            return [
                'controller' => $controllerObj,
                'action' => $action,
                'params' => $controllerParams
            ];
        }




        if (count($params) >= 2) {
            list($author, $plugin) = $params;

            $pluginCode = ucfirst($author) . '.' . ucfirst($plugin);
            if (PluginManager::instance()->isDisabled($pluginCode)) {
                return Response::make(View::make('backend::404'), 404);
            }

            $controller = $params[2] ?? 'index';
            self::$action = $action = isset($params[3]) ? $this->parseAction($params[3]) : 'index';
            self::$params = $controllerParams = array_slice($params, 4);
            $controllerClass = '\\'.$author.'\\'.$plugin.'\Controllers\\'.$controller;
            if ($controllerObj = $this->findController(
                $controllerClass,
                $action,
                plugins_path()
            )) {
                return [
                    'controller' => $controllerObj,
                    'action' => $action,
                    'params' => $controllerParams
                ];
            }
        }

        return null;
    }









    protected function findController($controller, $action, $inPath)
    {
        if (isset($this->requestedController)) {
            return $this->requestedController;
        }




        if (!class_exists($controller)) {
            $controller = Str::normalizeClassName($controller);
            $controllerFile = $inPath.strtolower(str_replace('\\', '/', $controller)) . '.php';
            if ($controllerFile = File::existsInsensitive($controllerFile)) {
                include_once $controllerFile;
            }
        }

        if (!class_exists($controller)) {
            return $this->requestedController = null;
        }

        $controllerObj = App::make($controller);

        if ($controllerObj->actionExists($action)) {
            return $this->requestedController = $controllerObj;
        }

        return $this->requestedController = null;
    }






    protected function parseAction($actionName)
    {
        if (strpos($actionName, '-') !== false) {
            return camel_case($actionName);
        }

        return $actionName;
    }








    protected static function methodExcludedByOptions($method, array $options)
    {
        return (isset($options['only']) && !in_array($method, (array) $options['only'])) ||
            (!empty($options['except']) && in_array($method, (array) $options['except']));
    }

    public function __call($name, $params)
    {
        if ($name === 'extend') {
            if (empty($params[0]) || !is_callable($params[0])) {
                throw new \InvalidArgumentException('The extend() method requires a callback parameter or closure.');
            }
            if ($params[0] instanceof Closure) {
                return $params[0]->call($this, $params[1] ?? $this);
            }
            return Closure::fromCallable($params[0])->call($this, $params[1] ?? $this);
        }

        return $this->extendableCall($name, $params);
    }

    public static function __callStatic($name, $params)
    {
        if ($name === 'extend') {
            if (empty($params[0])) {
                throw new \InvalidArgumentException('The extend() method requires a callback parameter or closure.');
            }
            self::extendableExtendCallback($params[0], $params[1] ?? false, $params[2] ?? null);
            return;
        }

        return self::extendableCallStatic($name, $params);
    }
}
