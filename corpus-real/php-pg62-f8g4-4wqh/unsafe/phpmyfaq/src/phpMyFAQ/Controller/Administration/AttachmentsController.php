<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use phpMyFAQ\Filter;
use phpMyFAQ\Pagination;
use phpMyFAQ\Session\Token;
use phpMyFAQ\Translation;
use phpMyFAQ\Twig\Extensions\FormatBytesTwigExtension;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;
use Twig\Extension\AttributeExtension;

final class AttachmentsController extends AbstractAdministrationController
{





    #[Route(path: '/attachments', name: 'admin.attachments', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::ATTACHMENT_DELETE);

        $page = Filter::filterVar($request->query->get('page'), FILTER_VALIDATE_INT);
        $page = max(1, $page);

        $session = $this->container->get(id: 'session');
        $collection = $this->container->get(id: 'phpmyfaq.attachment-collection');

        $itemsPerPage = 24;
        $allCrumbs = $collection->getBreadcrumbs();

        $crumbs = array_slice($allCrumbs, ($page - 1) * $itemsPerPage, $itemsPerPage);

        $baseUrl = sprintf('%sadmin/attachments?page=%d', $this->configuration->getDefaultUrl(), $page);

        $pagination = new Pagination([
            'baseUrl' => $baseUrl,
            'total' => is_countable($allCrumbs) ? count($allCrumbs) : 0,
            'perPage' => $itemsPerPage,
        ]);

        $this->addExtension(new AttributeExtension(FormatBytesTwigExtension::class));
        return $this->render('@admin/content/attachments.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'adminHeaderAttachments' => Translation::get(key: 'ad_menu_attachment_admin'),
            'adminMsgAttachmentsFilename' => Translation::get(key: 'msgAttachmentsFilename'),
            'adminMsgTransToolLanguage' => Translation::get(key: 'msgTransToolLanguage'),
            'adminMsgAttachmentsFilesize' => Translation::get(key: 'msgAttachmentsFilesize'),
            'adminMsgAttachmentsMimeType' => Translation::get(key: 'msgAttachmentsMimeType'),
            'csrfTokenDeletion' => Token::getInstance($session)->getTokenString('delete-attachment'),
            'csrfTokenRefresh' => Token::getInstance($session)->getTokenString('refresh-attachment'),
            'attachments' => $crumbs,
            'adminMsgButtonDelete' => Translation::get(key: 'ad_gen_delete'),
            'adminMsgFaqTitle' => Translation::get(key: 'ad_entry_faq_record'),
            'adminAttachmentPagination' => $pagination->render(),
        ]);
    }
}
