<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use phpMyFAQ\Session\Token;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

final class ReportController extends AbstractAdministrationController
{





    #[Route(path: '/statistics/report', name: 'admin.statistics.report', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::REPORTS);

        $session = $this->container->get(id: 'session');

        return $this->render('@admin/statistics/report.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'csrfTokenInput' => Token::getInstance($session)->getTokenInput('create-report'),
        ]);
    }
}
