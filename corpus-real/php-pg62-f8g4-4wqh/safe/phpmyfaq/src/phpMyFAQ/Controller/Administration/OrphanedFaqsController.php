<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

final class OrphanedFaqsController extends AbstractAdministrationController
{





    #[Route(path: '/orphaned-faqs', name: 'admin.content.orphaned-faqs', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::FAQ_EDIT);

        $faq = $this->container->get(id: 'phpmyfaq.admin.faq');

        return $this->render('@admin/content/orphaned-faqs.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'orphanedFaqs' => $faq->getOrphanedFaqs(),
        ]);
    }
}
