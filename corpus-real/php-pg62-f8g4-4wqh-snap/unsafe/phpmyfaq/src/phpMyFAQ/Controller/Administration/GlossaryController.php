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

final class GlossaryController extends AbstractAdministrationController
{





    #[Route(path: '/glossary')]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::GLOSSARY_ADD);
        $this->userHasPermission(PermissionType::GLOSSARY_EDIT);
        $this->userHasPermission(PermissionType::GLOSSARY_DELETE);

        $session = $this->container->get(id: 'session');
        $glossary = $this->container->get(id: 'phpmyfaq.glossary');
        $glossary->setLanguage($this->configuration->getLanguage()->getLanguage());

        return $this->render('@admin/content/glossary.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'adminHeaderGlossary' => Translation::get(key: 'ad_menu_glossary'),
            'msgAddGlossary' => Translation::get(key: 'ad_glossary_add'),
            'msgGlossaryItem' => Translation::get(key: 'ad_glossary_item'),
            'msgGlossaryDefinition' => Translation::get(key: 'ad_glossary_definition'),
            'glossaryItems' => $glossary->fetchAll(),
            'buttonDelete' => Translation::get(key: 'msgDelete'),
            'csrfTokenDelete' => Token::getInstance($session)->getTokenString('delete-glossary'),
            'currentLanguage' => $this->configuration->getLanguage()->getLanguage(),
            'addGlossaryTitle' => Translation::get(key: 'ad_glossary_add'),
            'addGlossaryCsrfTokenInput' => Token::getInstance($session)->getTokenInput('add-glossary'),
            'closeModal' => Translation::get(key: 'ad_att_close'),
            'saveModal' => Translation::get(key: 'ad_gen_save'),
            'updateGlossaryTitle' => Translation::get(key: 'ad_glossary_edit'),
            'updateGlossaryCsrfToken' => Token::getInstance($session)->getTokenString('update-glossary'),
        ]);
    }
}
