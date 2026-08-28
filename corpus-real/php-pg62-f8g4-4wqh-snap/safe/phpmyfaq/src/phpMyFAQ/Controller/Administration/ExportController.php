<?php
















declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Category;
use phpMyFAQ\Core\Exception;
use phpMyFAQ\Database;
use phpMyFAQ\Enums\PermissionType;
use phpMyFAQ\Translation;
use phpMyFAQ\User\CurrentUser;
use Symfony\Component\HttpFoundation\HeaderUtils;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

final class ExportController extends AbstractAdministrationController
{




    #[Route(path: '/export', name: 'admin.export', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::EXPORT);

        [$currentUser, $currentGroups] = CurrentUser::getCurrentUserGroupId($this->currentUser);

        $category = new Category($this->configuration, [], false);
        $category->setUser($currentUser);
        $category->setGroups($currentGroups);
        $category->buildCategoryTree();

        $categoryHelper = $this->container->get(id: 'phpmyfaq.helper.category-helper');
        $categoryHelper->setCategory($category);

        return $this->render('@admin/import-export/export.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'adminHeaderExport' => Translation::get(key: 'ad_menu_export'),
            'hasNoFaqs' => Database::checkOnEmptyTable('faqdata'),
            'errorMessageNoFaqs' => Translation::get(key: 'msgErrorNoRecords'),
            'hasCategories' => !Database::checkOnEmptyTable('faqcategories'),
            'headerCategories' => Translation::get(key: 'ad_export_which_cat'),
            'msgCategory' => Translation::get(key: 'msgCategory'),
            'msgAllCategories' => Translation::get(key: 'msgShowAllCategories'),
            'categoryOptions' => $categoryHelper->renderOptions(0),
            'msgWithSubCategories' => Translation::get(key: 'ad_export_cat_downwards'),
            'headerExportType' => Translation::get(key: 'ad_export_type'),
            'msgChooseExportType' => Translation::get(key: 'ad_export_type_choose'),
            'msgViewType' => Translation::get(key: 'ad_export_download_view'),
            'msgDownloadType' => HeaderUtils::DISPOSITION_ATTACHMENT,
            'msgDownload' => Translation::get(key: 'ad_export_download'),
            'msgInlineType' => HeaderUtils::DISPOSITION_INLINE,
            'msgInline' => Translation::get(key: 'ad_export_view'),
            'buttonReset' => Translation::get(key: 'ad_config_reset'),
            'buttonExport' => Translation::get(key: 'ad_menu_export'),
        ]);
    }
}
