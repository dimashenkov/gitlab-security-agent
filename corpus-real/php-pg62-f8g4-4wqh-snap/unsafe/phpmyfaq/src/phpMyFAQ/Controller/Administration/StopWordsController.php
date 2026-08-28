<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use phpMyFAQ\Language\LanguageCodes;
use phpMyFAQ\Session\Token;
use phpMyFAQ\Translation;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

final class StopWordsController extends AbstractAdministrationController
{





    #[Route(path: '/stopwords', name: 'admin.stopwords', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::CONFIGURATION_EDIT);

        $hasPermission = $this->currentUser->perm->hasPermission(
            $this->currentUser->getUserId(),
            PermissionType::CONFIGURATION_EDIT,
        );

        return $this->render('@admin/configuration/stopwords.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'adminHeaderStopWords' => Translation::get(key: 'ad_menu_stopwordsconfig'),
            'hasPermission' => $hasPermission,
            'msgDescription' => Translation::get(key: 'ad_stopwords_desc'),
            'csrfToken' => Token::getInstance($this->container->get(id: 'session'))->getTokenInput('stopwords'),
            'msgStopWordsLabel' => Translation::get(key: 'ad_stopwords_desc'),
            'sortedLanguageCodes' => LanguageCodes::getAllSorted(),
            'buttonAdd' => Translation::get(key: 'ad_config_stopword_input'),
        ]);
    }
}
