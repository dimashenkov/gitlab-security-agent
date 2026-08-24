<?php

namespace Backend\Classes;

use Backend\Facades\Backend;
use Backend\Facades\BackendAuth;
use Backend\Facades\BackendMenu;
use Backend\Models\Preference as BackendPreference;
use Backend\Models\UserPreference;
use Backend\Widgets\MediaManager;
use Exception;
use Illuminate\Database\Eloquent\MassAssignmentException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Routing\Controller as ControllerBase;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\View;
use Winter\Storm\Exception\AjaxException;
use Winter\Storm\Exception\ApplicationException;
use Winter\Storm\Exception\SystemException;
use Winter\Storm\Exception\ValidationException;
use Winter\Storm\Support\Facades\Config;
use Winter\Storm\Support\Facades\Flash;








class Controller extends ControllerBase
{
    use \System\Traits\ViewMaker;
    use \System\Traits\AssetMaker;
    use \System\Traits\ConfigMaker;
    use \System\Traits\EventEmitter;
    use \System\Traits\ResponseMaker;
    use \System\Traits\SecurityController;
    use \Backend\Traits\ErrorMaker;
    use \Backend\Traits\WidgetMaker;
    use \Winter\Storm\Extension\ExtendableTrait;




    public $implement;




    protected $user;




    public $widget;




    public $suppressView = false;




    protected $params;




    protected $action;




    protected $publicActions = [];




    protected $requiredPermissions = [];




    public $pageTitle;




    public $pageTitleTemplate;




    public $bodyClass = '';




    public $hiddenActions = [
        'run',
        'actionExists',
        'pageAction',
        'getId',
        'setStatusCode',
        'handleError',
        'makeHintPartial'
    ];




    protected $guarded = [];




    public function __construct()
    {



        $this->action = BackendController::$action;
        $this->params = BackendController::$params;




        $this->hiddenActions = array_merge($this->hiddenActions, $this->guarded);




        $this->layout = $this->layout ?: 'default';
        $this->layoutPath = Skin::getActive()->getLayoutPaths();
        $this->viewPath = $this->configPath = $this->guessViewPath();




        $relativePath = dirname(dirname(strtolower(str_replace('\\', '/', get_called_class()))));
        $this->layoutPath[] = '~/modules/' . $relativePath . '/layouts';
        $this->layoutPath[] = '~/plugins/' . $relativePath . '/layouts';




        $this->user = BackendAuth::getUser();




        if ($this->user && $this->user->hasAccess('media.*')) {
            $manager = new MediaManager($this, 'ocmediamanager');
            $manager->bindToController();
        }

        $this->extendableConstruct();
    }

    public function __get($name)
    {
        return $this->extendableGet($name);
    }

    public function __set($name, $value)
    {
        $this->extendableSet($name, $value);
    }

    public function __call($name, $params)
    {
        if ($name === 'extend') {
            if (empty($params[0]) || !is_callable($params[0])) {
                throw new \InvalidArgumentException('The extend() method requires a callback parameter or closure.');
            }
            if ($params[0] instanceof \Closure) {
                return $params[0]->call($this, $params[1] ?? $this);
            }
            return \Closure::fromCallable($params[0])->call($this, $params[1] ?? $this);
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




    protected function setNavigationContext(?string $action = null, array $params = []): void
    {
        $context = BackendMenu::getContext();


        $currentClass = explode('\\', get_class($this));
        $author = $currentClass[0];
        $plugin = $currentClass[1];
        $controller = $currentClass[count($currentClass) - 1];

        $owner = $context->owner ?? "$author.$plugin";
        $mainMenuCode = $context->mainMenuCode ?? strtolower($plugin);
        $sideMenuCode = $context->sideMenuCode ?? strtolower($controller);

        BackendMenu::setContext($owner, $mainMenuCode, $sideMenuCode);
    }







    public function run($action = null, $params = [])
    {
        $this->action = $action;
        $this->params = $params;





        if (!in_array(Request::method(), ['HEAD', 'GET', 'OPTIONS']) && !$this->verifyCsrfToken()) {
            return Response::make(Lang::get('system::lang.page.invalid_token.label'), 403);
        }





        if (!$this->verifyForceSecure()) {
            return Redirect::secure(Request::path());
        }




        $isPublicAction = in_array($action, $this->publicActions);




        if (!$isPublicAction) {



            if (!BackendAuth::check()) {
                return Request::ajax()
                    ? Response::make(Lang::get('backend::lang.page.access_denied.label'), 403)
                    : Backend::redirectGuest('backend/auth');
            }




            if ($this->requiredPermissions && !$this->user->hasAnyAccess($this->requiredPermissions)) {
                abort(403);
            }
        }




















        if ($event = $this->fireSystemEvent('backend.page.beforeDisplay', [$action, $params])) {
            return $event;
        }




        BackendPreference::setAppLocale();
        BackendPreference::setAppFallbackLocale();




        $this->setNavigationContext($action, $params);




        if ($ajaxResponse = $this->execAjaxHandlers()) {
            $result = $ajaxResponse;
        }




        elseif (
            ($handler = post('_handler')) &&
            $this->verifyCsrfToken()
        ) {
            $this->validateHandlerName($handler);

            if (
                ($handlerResponse = $this->runAjaxHandler($handler)) &&
                $handlerResponse !== true
            ) {
                $result = $handlerResponse;
            }
        }




        else {
            $result = $this->execPageAction($action, $params);
        }





        return $this->makeResponse($result);
    }









    public function actionExists($name, $internal = false)
    {
        if (!strlen($name) || substr($name, 0, 1) == '_' || !$this->methodExists($name)) {
            return false;
        }

        foreach ($this->hiddenActions as $method) {
            if (strtolower($name) == strtolower($method)) {
                return false;
            }
        }

        $ownMethod = method_exists($this, $name);

        if ($ownMethod) {
            $methodInfo = new \ReflectionMethod($this, $name);
            $public = $methodInfo->isPublic();
            if ($public) {
                return true;
            }
        }

        if ($internal && (($ownMethod && $methodInfo->isProtected()) || !$ownMethod)) {
            return true;
        }

        if (!$ownMethod) {
            return true;
        }

        return false;
    }




    public function actionUrl($action = null, $path = null)
    {
        if ($action === null) {
            $action = $this->action;
        }

        $class = get_called_class();
        $uriPath = dirname(dirname(strtolower(str_replace('\\', '/', $class))));
        $controllerName = strtolower(class_basename($class));

        $url = $uriPath.'/'.$controllerName.'/'.$action;
        if ($path) {
            $url .= '/'.$path;
        }

        return Backend::url($url);
    }





    public function pageAction()
    {
        if (!$this->action) {
            return;
        }

        $this->suppressView = true;
        $this->execPageAction($this->action, $this->params);
    }







    protected function execPageAction($actionName, $parameters)
    {
        $result = null;

        if (!$this->actionExists($actionName)) {
            if (Config::get('app.debug', false)) {
                throw new SystemException(sprintf(
                    "Action %s is not found in the controller %s",
                    $actionName,
                    get_class($this)
                ));
            } else {
                Response::make(View::make('backend::404'), 404);
            }
        }


        $result = call_user_func_array([$this, $actionName], $parameters);


        if ($result instanceof \Symfony\Component\HttpFoundation\Response) {
            return $result;
        }


        if (!$this->pageTitle) {
            $this->pageTitle = 'backend::lang.page.untitled';
        }


        if (!$this->suppressView && $result === null) {
            return $this->makeView($actionName);
        }

        return $this->makeViewContent((string) $result);
    }





    public function getAjaxHandler()
    {
        if (!Request::ajax() || Request::method() != 'POST') {
            return null;
        }

        if ($handler = Request::header('X_WINTER_REQUEST_HANDLER')) {
            return trim($handler);
        }

        return null;
    }






    protected function validateHandlerName(string $handler): void
    {
        if (!preg_match('/^(?:\w+\:{2})?on[A-Z]{1}[\w+]*$/', $handler)) {
            throw new SystemException(Lang::get('backend::lang.ajax_handler.invalid_name', ['name' => $handler]));
        }
    }





    protected function execAjaxHandlers()
    {
        if ($handler = $this->getAjaxHandler()) {
            try {



                $this->validateHandlerName($handler);




                if ($partialList = trim(Request::header('X_WINTER_REQUEST_PARTIALS'))) {
                    $partialList = explode('&', $partialList);

                    foreach ($partialList as $partial) {
                        if (!preg_match('/^(?!.*\/\/)[a-z0-9\_][a-z0-9\_\-\/]*$/i', $partial)) {
                            throw new SystemException(Lang::get('backend::lang.partial.invalid_name', ['name'=>$partial]));
                        }
                    }
                }
                else {
                    $partialList = [];
                }

                $responseContents = [];




                if (!$result = $this->runAjaxHandler($handler)) {
                    throw new SystemException(Lang::get('backend::lang.ajax_handler.not_found', ['name'=>$handler]));
                }




                foreach ($partialList as $partial) {
                    $responseContents[$partial] = $this->makePartial($partial);
                }





                if ($result instanceof RedirectResponse) {
                    $responseContents['X_WINTER_REDIRECT'] = $result->getTargetUrl();
                    $result = null;
                }



                elseif (Flash::check()) {
                    $responseContents['#layout-flash-messages'] = $this->makeLayoutPartial('flash_messages');
                }




                if ($this->hasAssetsDefined()) {
                    $responseContents['X_WINTER_ASSETS'] = $this->getAssetPaths();
                }






                if (is_array($result)) {
                    $responseContents = array_merge($responseContents, $result);
                }
                elseif (is_string($result)) {
                    $responseContents['result'] = $result;
                }
                elseif (is_object($result)) {
                    return $result;
                }

                return Response::make()->setContent($responseContents);
            }
            catch (ValidationException $ex) {



                Flash::error($ex->getMessage());
                $responseContents = [];
                $responseContents['#layout-flash-messages'] = $this->makeLayoutPartial('flash_messages');
                $responseContents['X_WINTER_ERROR_FIELDS'] = $ex->getFields();
                throw new AjaxException($responseContents);
            }
            catch (MassAssignmentException $ex) {
                throw new ApplicationException(Lang::get('backend::lang.model.mass_assignment_failed', ['attribute' => $ex->getMessage()]));
            }
            catch (Exception $ex) {
                throw $ex;
            }
        }

        return null;
    }






    protected function runAjaxHandler($handler)
    {





























        if ($event = $this->fireSystemEvent('backend.ajax.beforeRunHandler', [$handler])) {
            return $event;
        }




        if (strpos($handler, '::')) {
            list($widgetName, $handlerName) = explode('::', $handler);




            $this->pageAction();

            if ($this->fatalError) {
                throw new SystemException($this->fatalError);
            }

            if (!isset($this->widget->{$widgetName})) {
                throw new SystemException(Lang::get('backend::lang.widget.not_bound', ['name'=>$widgetName]));
            }

            if (($widget = $this->widget->{$widgetName}) && $widget->methodExists($handlerName)) {
                $result = $this->runAjaxHandlerForWidget($widget, $handlerName);
                return $result ?: true;
            }
        }
        else {



            $pageHandler = $this->action . '_' . $handler;

            if ($this->methodExists($pageHandler)) {
                $result = call_user_func_array([$this, $pageHandler], array_values($this->params));
                return $result ?: true;
            }




            if ($this->methodExists($handler)) {
                $result = call_user_func_array([$this, $handler], array_values($this->params));
                return $result ?: true;
            }




            $this->suppressView = true;
            $this->execPageAction($this->action, $this->params);

            foreach ((array) $this->widget as $widget) {
                if ($widget->methodExists($handler)) {
                    $result = $this->runAjaxHandlerForWidget($widget, $handler);
                    return $result ?: true;
                }
            }
        }




        if ($handler == 'onAjax') {
            return true;
        }

        return false;
    }






    protected function runAjaxHandlerForWidget($widget, $handler)
    {
        $this->prependViewPath($widget->getViewPaths());

        $result = call_user_func_array([$widget, $handler], array_values($this->params));

        $this->vars = $widget->vars + $this->vars;

        return $result;
    }




    public function getPublicActions()
    {
        return $this->publicActions;
    }




    public function getId($suffix = null)
    {
        $id = class_basename(get_called_class()) . '-' . $this->action;
        if ($suffix !== null) {
            $id .= '-' . $suffix;
        }

        return $id;
    }














    public function makeHintPartial($name, $partial = null, $params = [])
    {
        if (is_array($partial)) {
            $params = $partial;
            $partial = null;
        }

        if (!$partial) {
            $partial = array_get($params, 'partial', $name);
        }

        return $this->makeLayoutPartial('hint', [
            'hintName'    => $name,
            'hintPartial' => $partial,
            'hintContent' => array_get($params, 'content'),
            'hintParams'  => $params
        ] + $params);
    }






    public function onHideBackendHint()
    {
        if (!$name = post('name')) {
            throw new ApplicationException('Missing a hint name.');
        }

        $preferences = UserPreference::forUser();
        $hiddenHints = $preferences->get('backend::hints.hidden', []);
        $hiddenHints[$name] = 1;

        $preferences->set('backend::hints.hidden', $hiddenHints);
    }






    public function isBackendHintHidden($name)
    {
        $hiddenHints = UserPreference::forUser()->get('backend::hints.hidden', []);
        return array_key_exists($name, $hiddenHints);
    }
}
