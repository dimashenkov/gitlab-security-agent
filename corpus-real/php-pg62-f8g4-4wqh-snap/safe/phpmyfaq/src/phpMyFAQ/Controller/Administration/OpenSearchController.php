<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

final class OpenSearchController extends AbstractAdministrationController
{




    #[Route(path: '/opensearch', name: 'admin.opensearch', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::CONFIGURATION_EDIT);

        if (!$this->configuration->get(item: 'search.enableOpenSearch')) {
            throw new UnauthorizedHttpException('You are not allowed to access this page.');
        }

        return $this->render('@admin/configuration/opensearch.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
        ]);
    }
}
