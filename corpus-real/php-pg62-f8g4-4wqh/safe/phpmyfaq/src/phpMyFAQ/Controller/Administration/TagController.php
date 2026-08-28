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

final class TagController extends AbstractAdministrationController
{





    #[Route(path: '/tags', name: 'admin.tags', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::FAQ_EDIT);

        $tagData = $this->container->get(id: 'phpmyfaq.tags')->setBypassPermissionCheck()->getAllTags();

        return $this->render('@admin/content/tags.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'adminHeaderTags' => Translation::get(key: 'msgTags'),
            'csrfToken' => Token::getInstance($this->container->get(id: 'session'))->getTokenInput('tags'),
            'tags' => $tagData,
            'noTags' => Translation::get(key: 'ad_news_nodata'),
            'buttonEdit' => Translation::get(key: 'ad_user_edit'),
            'msgConfirm' => Translation::get(key: 'ad_user_del_3'),
            'buttonDelete' => Translation::get(key: 'msgDelete'),
        ]);
    }
}
