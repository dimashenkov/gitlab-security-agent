<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

final class PluginController extends AbstractAdministrationController
{





    #[Route(path: '/plugins')]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::CONFIGURATION_EDIT);

        $pluginManager = $this->container->get(id: 'phpmyfaq.plugin.plugin-manager');
        $pluginManager->loadPlugins();

        return $this->render('@admin/configuration/plugins.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'pluginList' => $pluginManager->getPlugins(),
            'incompatiblePlugins' => $pluginManager->getIncompatiblePlugins(),
        ]);
    }
}
