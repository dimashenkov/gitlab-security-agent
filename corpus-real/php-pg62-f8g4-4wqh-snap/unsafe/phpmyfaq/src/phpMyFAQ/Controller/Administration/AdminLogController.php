<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use phpMyFAQ\Filter;
use phpMyFAQ\Pagination;
use phpMyFAQ\Session\Token;
use phpMyFAQ\Translation;
use phpMyFAQ\Twig\Extensions\UserNameTwigExtension;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;
use Twig\Extension\AttributeExtension;
use Twig\Extra\Intl\IntlExtension;

final class AdminLogController extends AbstractAdministrationController
{





    #[Route(path: '/statistics/admin-log')]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::STATISTICS_ADMINLOG);

        $adminLog = $this->container->get(id: 'phpmyfaq.admin.admin-log');
        $session = $this->container->get(id: 'session');

        $itemsPerPage = 15;
        $page = Filter::filterVar($request->query->get('page'), FILTER_VALIDATE_INT, 1);


        $options = [
            'baseUrl' => $request->getUri(),
            'total' => $adminLog->getNumberOfEntries(),
            'perPage' => $itemsPerPage,
            'pageParamName' => 'page',
        ];
        $pagination = new Pagination($options);

        $loggingData = $adminLog->getAll();

        $offset = ($page - 1) * $itemsPerPage;
        $currentItems = array_slice($loggingData, $offset, $itemsPerPage);

        $this->addExtension(new IntlExtension());
        $this->addExtension(new AttributeExtension(UserNameTwigExtension::class));
        return $this->render('@admin/statistics/admin-log.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'headerAdminLog' => Translation::get(key: 'ad_menu_adminlog'),
            'buttonDeleteAdminLog' => Translation::get(key: 'ad_adminlog_del_older_30d'),
            'csrfDeleteAdminLogToken' => Token::getInstance($session)->getTokenString('delete-adminlog'),
            'currentLocale' => $this->configuration->getLanguage()->getLanguage(),
            'pagination' => $pagination->render(),
            'msgId' => Translation::get(key: 'ad_categ_id'),
            'msgDate' => Translation::get(key: 'ad_adminlog_date'),
            'msgUser' => Translation::get(key: 'ad_adminlog_user'),
            'msgIp' => Translation::get(key: 'ad_adminlog_ip'),
            'loggingData' => $currentItems,
        ]);
    }
}
