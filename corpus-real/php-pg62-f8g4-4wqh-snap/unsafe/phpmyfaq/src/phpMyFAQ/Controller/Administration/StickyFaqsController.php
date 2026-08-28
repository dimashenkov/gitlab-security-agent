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

final class StickyFaqsController extends AbstractAdministrationController
{





    #[Route(path: '/sticky-faqs')]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::FAQ_EDIT);

        $customOrdering = $this->configuration->get(item: 'records.orderStickyFaqsCustom');

        return $this->render('@admin/content/sticky-faqs.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'stickyFAQsHeader' => Translation::get(key: 'stickyRecordsHeader'),
            'stickyData' => $this->container->get(id: 'phpmyfaq.faq')->getStickyFaqsData(),
            'sortableDisabled' => $customOrdering === false ? 'sortable-disabled' : '',
            'orderingStickyFaqsActivated' => $this->configuration->get(item: 'records.orderStickyFaqsCustom'),
            'alertMessageStickyFaqsDeactivated' => Translation::get(key: 'msgOrderStickyFaqsCustomDeactivated'),
            'alertMessageNoStickyRecords' => Translation::get(key: 'msgNoStickyFaqs'),
            'csrfToken' => Token::getInstance($this->container->get(id: 'session'))->getTokenString('order-stickyfaqs'),
        ]);
    }
}
