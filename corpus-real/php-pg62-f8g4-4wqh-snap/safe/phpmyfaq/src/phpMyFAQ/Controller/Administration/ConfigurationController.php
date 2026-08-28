<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use phpMyFAQ\Session\Token;
use phpMyFAQ\Translation;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

final class ConfigurationController extends AbstractAdministrationController
{





    #[Route(path: '/configuration', name: 'admin.instances', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::CONFIGURATION_EDIT);

        return $this->render('@admin/configuration/main.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'adminHeaderConfiguration' => Translation::get(key: 'ad_config_edit'),
            'csrfToken' => Token::getInstance($this->container->get(id: 'session'))->getTokenString('configuration'),
            'language' => $this->configuration->getLanguage()->getLanguage(),
            'adminConfigurationButtonReset' => Translation::get(key: 'ad_config_reset'),
            'adminConfigurationButtonSave' => Translation::get(key: 'ad_config_save'),
        ]);
    }
}
