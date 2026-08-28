<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use phpMyFAQ\Enums\ReleaseType;
use phpMyFAQ\Session\Token;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

final class UpdateController extends AbstractAdministrationController
{





    #[Route(path: '/update', name: 'admin.update', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::CONFIGURATION_EDIT);

        $session = $this->container->get(id: 'session');

        $isOnNightlies = $this->configuration->get(item: 'upgrade.releaseEnvironment') === ReleaseType::NIGHTLY->value;

        return $this->render('@admin/configuration/upgrade.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'csrfActivateMaintenanceMode' => Token::getInstance($session)->getTokenString('activate-maintenance-mode'),
            'isOnNightlies' => $isOnNightlies,
            'releaseEnvironment' => ucfirst((string) $this->configuration->get(item: 'upgrade.releaseEnvironment')),
            'dateLastChecked' => $this->configuration->get(item: 'upgrade.dateLastChecked'),
            'versionCurrent' => $this->configuration->get(item: 'main.currentVersion'),
        ]);
    }
}
