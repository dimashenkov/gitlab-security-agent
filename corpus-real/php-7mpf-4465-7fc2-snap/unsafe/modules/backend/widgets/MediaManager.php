<?php namespace Backend\Widgets;

use Str;
use Lang;
use Input;
use Event;
use Config;
use Backend;
use ApplicationException;
use Backend\Classes\WidgetBase;
use System\Classes\ImageResizer;
use System\Classes\MediaLibrary;
use System\Classes\MediaLibraryItem;







class MediaManager extends WidgetBase
{
    use \Backend\Traits\UploadableWidget;
    use \Backend\Traits\PreferenceMaker;

    const FOLDER_ROOT = '/';

    const VIEW_MODE_GRID = 'grid';
    const VIEW_MODE_LIST = 'list';
    const VIEW_MODE_TILES = 'tiles';

    const SELECTION_MODE_NORMAL = 'normal';
    const SELECTION_MODE_FIXED_RATIO = 'fixed-ratio';
    const SELECTION_MODE_FIXED_SIZE = 'fixed-size';

    const FILTER_ALL = 'all';




    public $readOnly = false;




    public $bottomToolbar = false;




    public $cropAndInsertButton = false;




    public bool $filterDisplay = true;




    public function __construct($controller, $alias, $readOnly = false)
    {
        $this->alias = $alias;
        $this->readOnly = $readOnly;

        parent::__construct($controller, []);
    }






    protected function loadAssets()
    {
        $this->addCss('css/mediamanager.css', 'core');

        if (Config::get('develop.decompileBackendAssets', false)) {
            $scripts = Backend::decompileAsset($this->getAssetPath('js/mediamanager-browser.js'));
            foreach ($scripts as $script) {
                $this->addJs($script, 'core');
            }
        } else {
            $this->addJs('js/mediamanager-browser-min.js', 'core');
        }
    }




    protected function abortIfReadOnly(): void
    {
        if ($this->readOnly) {
            abort(403);
        }
    }




    public function render(): string
    {
        $this->prepareVars();

        return $this->makePartial('body');
    }








    public function onSearch(): array
    {
        $this->setSearchTerm(Input::get('search'));

        $this->prepareVars();

        return [
            '#' . $this->getId('item-list') => $this->makePartial('item-list'),
            '#' . $this->getId('folder-path') => $this->makePartial('folder-path')
        ];
    }




    public function onGoToFolder(): array
    {
        $path = Input::get('path');

        if (Input::get('clearCache')) {
            MediaLibrary::instance()->resetCache();
        }

        if (Input::get('resetSearch')) {
            $this->setSearchTerm(null);
        }

        $this->setCurrentFolder($path);
        $this->prepareVars();

        return [
            '#' . $this->getId('item-list') => $this->makePartial('item-list'),
            '#' . $this->getId('folder-path') => $this->makePartial('folder-path')
        ];
    }




    public function onGenerateThumbnails(): array
    {
        $batch = Input::get('batch');
        if (!is_array($batch)) {
            return [];
        }

        $result = [];
        foreach ($batch as $thumbnailInfo) {
            $result[] = $this->generateThumbnail($thumbnailInfo);
        }

        return [
            'generatedThumbnails' => $result
        ];
    }






    public function onGetSidebarThumbnail(): array
    {
        $path = MediaLibrary::validatePath(Input::get('path'));
        $lastModified = Input::get('lastModified');

        if (!is_numeric($lastModified)) {
            throw new ApplicationException('Invalid input data');
        }

        $thumbnailParams = $this->getThumbnailParams();
        $thumbnailParams['width'] = 300;
        $thumbnailParams['height'] = 255;
        $thumbnailParams['mode'] = 'auto';

        $thumbnailInfo = $thumbnailParams;
        $thumbnailInfo['path'] = $path;
        $thumbnailInfo['lastModified'] = $lastModified;
        $thumbnailInfo['id'] = 'sidebar-thumbnail';

        return $this->generateThumbnail($thumbnailInfo, $thumbnailParams);
    }




    public function onChangeView(): array
    {
        $viewMode = Input::get('view');
        $path = Input::get('path');

        $this->setViewMode($viewMode);
        $this->setCurrentFolder($path);

        $this->prepareVars();

        return [
            '#' . $this->getId('item-list') => $this->makePartial('item-list'),
            '#' . $this->getId('folder-path') => $this->makePartial('folder-path'),
            '#' . $this->getId('view-mode-buttons') => $this->makePartial('view-mode-buttons')
        ];
    }




    public function onSetFilter(): array
    {
        $filter = Input::get('filter');
        $path = Input::get('path');

        $this->setFilter($filter);
        $this->setCurrentFolder($path);

        $this->prepareVars();

        return [
            '#' . $this->getId('item-list') => $this->makePartial('item-list'),
            '#' . $this->getId('folder-path') => $this->makePartial('folder-path'),
            '#' . $this->getId('filters') => $this->makePartial('filters')
        ];
    }




    public function onSetSorting(): array
    {
        $sortBy = Input::get('sortBy', $this->getSortBy());
        $sortDirection = Input::get('sortDirection', $this->getSortDirection());
        $path = Input::get('path');

        $this->setSortBy($sortBy);
        $this->setSortDirection($sortDirection);
        $this->setCurrentFolder($path);

        $this->prepareVars();

        return [
            '#' . $this->getId('item-list') => $this->makePartial('item-list'),
            '#' . $this->getId('folder-path') => $this->makePartial('folder-path')
        ];
    }







    public function onDeleteItem(): array
    {
        $this->abortIfReadOnly();

        $paths = Input::get('paths');

        if (!is_array($paths)) {
            throw new ApplicationException('Invalid input data');
        }

        $library = MediaLibrary::instance();

        $filesToDelete = [];
        foreach ($paths as $pathInfo) {
            $path = array_get($pathInfo, 'path');
            $type = array_get($pathInfo, 'type');

            if (!$path || !$type) {
                throw new ApplicationException('Invalid input data');
            }

            if ($type === MediaLibraryItem::TYPE_FILE) {



                $filesToDelete[] = $path;
            } elseif ($type === MediaLibraryItem::TYPE_FOLDER) {



                $library->deleteFolder($path);


















                $this->fireSystemEvent('media.folder.delete', [$path]);
            }
        }

        if (count($filesToDelete) > 0) {



            $library->deleteFiles($filesToDelete);




            foreach ($filesToDelete as $path) {

















                $this->fireSystemEvent('media.file.delete', [$path]);
            }
        }

        $library->resetCache();
        $this->prepareVars();

        return [
            '#' . $this->getId('item-list') => $this->makePartial('item-list')
        ];
    }




    public function onLoadRenamePopup(): string
    {
        $this->abortIfReadOnly();

        $path = Input::get('path');
        $path = MediaLibrary::validatePath($path);

        $this->vars['originalPath'] = $path;
        $this->vars['name'] = basename($path);
        $this->vars['listId'] = Input::get('listId');
        $this->vars['type'] = Input::get('type');

        return $this->makePartial('rename-form');
    }







    public function onApplyName(): void
    {
        $this->abortIfReadOnly();

        $newName = trim(Input::get('name'));
        if (!strlen($newName)) {
            throw new ApplicationException(Lang::get('cms::lang.asset.name_cant_be_empty'));
        }

        if (!$this->validateFileName($newName)) {
            throw new ApplicationException(Lang::get('cms::lang.asset.invalid_name'));
        }

        $originalPath = Input::get('originalPath');
        $originalPath = MediaLibrary::validatePath($originalPath);
        $newPath = dirname($originalPath) . '/' . $newName;
        $type = Input::get('type');

        if ($type == MediaLibraryItem::TYPE_FILE) {



            if (!$this->validateFileType($newName)) {
                throw new ApplicationException(Lang::get('backend::lang.media.type_blocked'));
            }




            MediaLibrary::instance()->moveFile($originalPath, $newPath);


















            $this->fireSystemEvent('media.file.rename', [$originalPath, $newPath]);
        } else {



            MediaLibrary::instance()->moveFolder($originalPath, $newPath);


















            $this->fireSystemEvent('media.folder.rename', [$originalPath, $newPath]);
        }

        MediaLibrary::instance()->resetCache();
    }






    public function onCreateFolder(): array
    {
        $this->abortIfReadOnly();

        $name = trim(Input::get('name'));
        if (!strlen($name)) {
            throw new ApplicationException(Lang::get('cms::lang.asset.name_cant_be_empty'));
        }

        if (!$this->validateFileName($name)) {
            throw new ApplicationException(Lang::get('cms::lang.asset.invalid_name'));
        }

        $path = Input::get('path');
        $path = MediaLibrary::validatePath($path);

        $newFolderPath = $path . '/' . $name;

        $library = MediaLibrary::instance();

        if ($library->folderExists($newFolderPath)) {
            throw new ApplicationException(Lang::get('backend::lang.media.folder_or_file_exist'));
        }




        if (!$library->makeFolder($newFolderPath)) {
            throw new ApplicationException(Lang::get('backend::lang.media.error_creating_folder'));
        }


















        $this->fireSystemEvent('media.folder.create', [$newFolderPath]);

        $library->resetCache();

        $this->prepareVars();

        return [
            '#' . $this->getId('item-list') => $this->makePartial('item-list')
        ];
    }






    public function onLoadMovePopup(): string
    {
        $this->abortIfReadOnly();

        $exclude = Input::get('exclude', []);
        if (!is_array($exclude)) {
            throw new ApplicationException('Invalid input data');
        }

        $folders = MediaLibrary::instance()->listAllDirectories($exclude);

        $folderList = [];
        foreach ($folders as $folder) {
            $path = $folder;

            if ($folder == '/') {
                $name = Lang::get('backend::lang.media.library');
            } else {
                $segments = explode('/', $folder);
                $name = str_repeat('&nbsp;', (count($segments) - 1) * 4) . basename($folder);
            }

            $folderList[$path] = $name;
        }

        $this->vars['folders'] = $folderList;
        $this->vars['originalPath'] = Input::get('path');

        return $this->makePartial('move-form');
    }






    public function onMoveItems(): array
    {
        $this->abortIfReadOnly();

        $dest = trim(Input::get('dest'));
        if (!strlen($dest)) {
            throw new ApplicationException(Lang::get('backend::lang.media.please_select_move_dest'));
        }

        $dest = MediaLibrary::validatePath($dest);
        if ($dest == Input::get('originalPath')) {
            throw new ApplicationException(Lang::get('backend::lang.media.move_dest_src_match'));
        }

        $files = Input::get('files', []);
        if (!is_array($files)) {
            throw new ApplicationException('Invalid input data');
        }

        $folders = Input::get('folders', []);
        if (!is_array($folders)) {
            throw new ApplicationException('Invalid input data');
        }

        $library = MediaLibrary::instance();

        foreach ($files as $path) {



            $library->moveFile($path, $dest . '/' . basename($path));


















            $this->fireSystemEvent('media.file.move', [$path, $dest]);
        }

        foreach ($folders as $path) {



            $library->moveFolder($path, $dest . '/' . basename($path));


















            $this->fireSystemEvent('media.folder.move', [$path, $dest]);
        }

        $library->resetCache();

        $this->prepareVars();

        return [
            '#' . $this->getId('item-list') => $this->makePartial('item-list')
        ];
    }




    public function onSetSidebarVisible(): void
    {
        $visible = (bool) Input::get('visible');

        $this->setSidebarVisible($visible);
    }




    public function onLoadPopup(): string
    {
        $this->bottomToolbar = Input::get('bottomToolbar', $this->bottomToolbar);

        $this->cropAndInsertButton = Input::get('cropAndInsertButton', $this->cropAndInsertButton);

        if ($mode = Input::get('mode')) {
            $this->setFilter($mode);
            if ($mode !== static::FILTER_ALL) {
                $this->setFilterDisplay(false);
            }
        }

        return $this->makePartial('popup-body');
    }




    public function onLoadImageCropPopup(): string
    {
        $this->abortIfReadOnly();

        $path = Input::get('path');
        $path = MediaLibrary::validatePath($path);
        $selectionParams = $this->getSelectionParams();
        $url = MediaLibrary::url($path);


        if (Str::startsWith($url, '/')) {
            $localPath = base_path(implode("/", array_map("rawurldecode", explode("/", $url))));
            $dimensions = getimagesize($localPath);
        } else {
            $dimensions = getimagesize($url);
        }

        $width = $dimensions[0];
        $height = $dimensions[1] ?: 1;

        $this->vars['currentSelectionMode'] = $selectionParams['mode'];
        $this->vars['currentSelectionWidth'] = $selectionParams['width'];
        $this->vars['currentSelectionHeight'] = $selectionParams['height'];
        $this->vars['imageUrl'] = $url;
        $this->vars['dimensions'] = $dimensions;
        $this->vars['originalRatio'] = round($width / $height, 5);
        $this->vars['path'] = $path;

        return $this->makePartial('image-crop-popup-body');
    }






    public function onCropImage(): array
    {
        $this->abortIfReadOnly();

        $selectionData = Input::get('selection');
        $sourceImageUrl = Input::get('img');
        $mediaItemPath = Input::get('path');

        if (!is_array($selectionData)) {
            throw new ApplicationException('Invalid input data');
        }

        foreach (['x', 'y', 'w', 'h'] as $key) {
            if (!isset($selectionData[$key]) || !is_numeric($selectionData[$key])) {
                throw new ApplicationException('Invalid selection data.');
            }

            $selectionData[$key] = (int) $selectionData[$key];
        }

        if ($selectionData['h'] === 0 || $selectionData['w'] === 0) {
            throw new ApplicationException('You must define a crop size before inserting');
        }


        $resizer = new ImageResizer(
            $sourceImageUrl,
            $selectionData['w'],
            $selectionData['h'],
            [
                'mode' => 'exact',
                'offset' => [
                    $selectionData['x'],
                    $selectionData['y'],
                ],
            ],
        );


        $resizer->crop();


        $croppedPath = $resizer->getPathToResizedImage();


        $targetPath = $this->deduplicatePath($mediaItemPath, '_cropped');


        MediaLibrary::instance()->put(
            $targetPath,
            ImageResizer::getDefaultDisk()->get($croppedPath)
        );

        $result = [
            'publicUrl' => MediaLibrary::url($targetPath),
            'documentType' => MediaLibraryItem::FILE_TYPE_IMAGE,
            'itemType' => MediaLibraryItem::TYPE_FILE,
            'path' => $targetPath,
            'title' => basename($targetPath),
            'folder' => dirname($targetPath),
        ];

        $selectionMode = Input::get('selectionMode');
        $selectionWidth = Input::get('selectionWidth');
        $selectionHeight = Input::get('selectionHeight');

        $this->setSelectionParams($selectionMode, $selectionWidth, $selectionHeight);

        return $result;
    }








    public function onResizeImage(): array
    {
        $this->abortIfReadOnly();

        $width = trim(Input::get('width'));
        if (!strlen($width) || !ctype_digit($width)) {
            throw new ApplicationException('Invalid input data');
        }

        $height = trim(Input::get('height'));
        if (!strlen($height) || !ctype_digit($height)) {
            throw new ApplicationException('Invalid input data');
        }

        $path = Input::get('path');
        $path = MediaLibrary::validatePath($path);


        $resizer = new ImageResizer(
            MediaLibrary::url($path),
            $width,
            $height,
            [
                'mode' => 'exact',
            ],
        );


        $resizer->resize();


        $resizedUrl = $resizer->getResizedUrl();

        return [
            'url' => $resizedUrl,
            'dimensions' => [$width, $height]
        ];
    }








    protected function prepareVars()
    {
        clearstatcache();

        $folder = $this->getCurrentFolder();
        $viewMode = $this->getViewMode();
        $filter = $this->getFilter();
        $sortBy = $this->getSortBy();
        $sortDirection = $this->getSortDirection();
        $searchTerm = $this->getSearchTerm();
        $searchMode = strlen($searchTerm) > 0;

        if (!$searchMode) {
            $this->vars['items'] = $this->listFolderItems($folder, $filter, ['by' => $sortBy, 'direction' => $sortDirection]);
        }
        else {
            $this->vars['items'] = $this->findFiles($searchTerm, $filter, ['by' => $sortBy, 'direction' => $sortDirection]);
        }

        $this->vars['currentFolder'] = $folder;
        $this->vars['isRootFolder'] = $folder == self::FOLDER_ROOT;
        $this->vars['pathSegments'] = $this->splitPathToSegments($folder);
        $this->vars['viewMode'] = $viewMode;
        $this->vars['thumbnailParams'] = $this->getThumbnailParams($viewMode);
        $this->vars['currentFilter'] = $filter;
        $this->vars['sortBy'] = $sortBy;
        $this->vars['sortDirection'] = $sortDirection;
        $this->vars['searchMode'] = $searchMode;
        $this->vars['searchTerm'] = $searchTerm;
        $this->vars['sidebarVisible'] = $this->getSidebarVisible();
    }









    protected function listFolderItems($folder, $filter, $sortBy)
    {
        $filter = $filter !== self::FILTER_ALL ? $filter : null;

        return MediaLibrary::instance()->listFolderContents($folder, $sortBy, $filter);
    }










    protected function findFiles($searchTerm, $filter, $sortBy)
    {
        $filter = $filter !== self::FILTER_ALL ? $filter : null;

        return MediaLibrary::instance()->findFiles($searchTerm, $sortBy, $filter);
    }




    protected function setCurrentFolder(string $path): void
    {
        $path = MediaLibrary::validatePath($path);

        $this->putSession('media_folder', $path);
    }




    protected function getCurrentFolder(): string
    {
        return $this->getSession('media_folder', self::FOLDER_ROOT);
    }




    protected function setFilter(string $filter): void
    {
        if (!in_array($filter, [
            self::FILTER_ALL,
            MediaLibraryItem::FILE_TYPE_IMAGE,
            MediaLibraryItem::FILE_TYPE_AUDIO,
            MediaLibraryItem::FILE_TYPE_DOCUMENT,
            MediaLibraryItem::FILE_TYPE_VIDEO
        ])) {
            throw new ApplicationException('Invalid input data');
        }

        $this->putSession('media_filter', $filter);
    }




    protected function setFilterDisplay(bool $status): void
    {
        $this->filterDisplay = $status;
    }




    protected function getFilterDisplay(): bool
    {
        return $this->filterDisplay;
    }






    protected function getFilter()
    {
        return $this->getSession('media_filter', self::FILTER_ALL);
    }






    protected function setSearchTerm($searchTerm): void
    {
        $this->putSession('media_search', trim($searchTerm));
    }




    protected function getSearchTerm(): ?string
    {
        return $this->getSession('media_search', null);
    }




    protected function setSortBy(string $sortBy): void
    {
        if (!in_array($sortBy, [
            MediaLibrary::SORT_BY_TITLE,
            MediaLibrary::SORT_BY_SIZE,
            MediaLibrary::SORT_BY_MODIFIED
        ])) {
            throw new ApplicationException('Invalid input data');
        }

        $key = 'media_sort_by';
        $this->putUserPreference($key, $sortBy);
        $this->putSession($key, $sortBy);
    }




    protected function getSortBy(): string
    {
        $key = 'media_sort_by';
        return $this->getSession($key, $this->getUserPreference($key, MediaLibrary::SORT_BY_TITLE));
    }






    protected function setSortDirection($sortDirection): void
    {
        if (!in_array($sortDirection, [
            MediaLibrary::SORT_DIRECTION_ASC,
            MediaLibrary::SORT_DIRECTION_DESC
        ])) {
            throw new ApplicationException('Invalid input data');
        }

        $key = 'media_sort_direction';
        $this->putUserPreference($key, $sortDirection);
        $this->putSession($key, $sortDirection);
    }




    protected function getSortDirection(): string
    {
        $key = 'media_sort_direction';
        return $this->getSession($key, $this->getUserPreference($key, MediaLibrary::SORT_DIRECTION_ASC));
    }




    protected function getSelectionParams(): array
    {
        $result = $this->getSession('media_crop_selection_params');

        if ($result) {
            if (!isset($result['mode'])) {
                $result['mode'] = self::SELECTION_MODE_NORMAL;
            }

            if (!isset($result['width'])) {
                $result['width'] = null;
            }

            if (!isset($result['height'])) {
                $result['height'] = null;
            }

            return $result;
        }

        return [
            'mode'   => self::SELECTION_MODE_NORMAL,
            'width'  => null,
            'height' => null
        ];
    }








    protected function setSelectionParams($selectionMode, $selectionWidth, $selectionHeight): void
    {
        if (!in_array($selectionMode, [
            self::SELECTION_MODE_NORMAL,
            self::SELECTION_MODE_FIXED_RATIO,
            self::SELECTION_MODE_FIXED_SIZE
        ])) {
            throw new ApplicationException('Invalid input data');
        }

        if (strlen($selectionWidth) && !ctype_digit($selectionWidth)) {
            throw new ApplicationException('Invalid input data');
        }

        if (strlen($selectionHeight) && !ctype_digit($selectionHeight)) {
            throw new ApplicationException('Invalid input data');
        }

        $this->putSession('media_crop_selection_params', [
            'mode'   => $selectionMode,
            'width'  => $selectionWidth,
            'height' => $selectionHeight
        ]);
    }




    protected function setSidebarVisible(bool $visible): void
    {
        $this->putSession('sidebar_visible', $visible);
    }




    protected function getSidebarVisible(): bool
    {
        return $this->getSession('sidebar_visible', true);
    }




    protected function itemTypeToIconClass(?MediaLibraryItem $item, ?string $itemType): string
    {
        if ($item->type == MediaLibraryItem::TYPE_FOLDER) {
            return 'icon-folder';
        }

        switch ($itemType) {
            case MediaLibraryItem::FILE_TYPE_IMAGE:
                return "icon-picture-o";
            case MediaLibraryItem::FILE_TYPE_VIDEO:
                return "icon-video-camera";
            case MediaLibraryItem::FILE_TYPE_AUDIO:
                return "icon-volume-up";
            default:
                return "icon-file";
        }
    }






    protected function splitPathToSegments($path): array
    {
        $path = MediaLibrary::validatePath($path, true);
        $path = explode('/', ltrim($path, '/'));

        $result = [];
        while (count($path) > 0) {
            $folder = array_pop($path);

            $result[$folder] = implode('/', $path).'/'.$folder;
            if (substr($result[$folder], 0, 1) != '/') {
                $result[$folder] = '/'.$result[$folder];
            }
        }

        return array_reverse($result, true);
    }






    protected function setViewMode(string $viewMode): void
    {
        if (!in_array($viewMode, [
            self::VIEW_MODE_GRID,
            self::VIEW_MODE_LIST,
            self::VIEW_MODE_TILES
        ])) {
            throw new ApplicationException('Invalid input data');
        }

        $key = 'view_mode';
        $this->putUserPreference($key, $viewMode);
        $this->putSession($key, $viewMode);
    }




    protected function getViewMode(): string
    {
        $key = 'view_mode';
        return $this->getSession($key, $this->getUserPreference($key, self::VIEW_MODE_GRID));
    }




    protected function getThumbnailParams(?string $viewMode = null): array
    {
        $result = [
            'mode' => 'crop'
        ];

        if (!$viewMode) {
            return $result;
        }

        if ($viewMode === self::VIEW_MODE_LIST) {
            return array_merge($result, [
                'width' => 75,
                'height' => 75
            ]);
        }

        return array_merge($result, [
            'width' => 165,
            'height' => 165
        ]);
    }







    protected function getPlaceholderId($item)
    {
        return 'placeholder'.md5($item->path.'-'.$item->lastModified.uniqid(microtime()));
    }







    protected function generateThumbnail($thumbnailInfo, $thumbnailParams = null): array
    {
        $markup = null;

        $path = $thumbnailInfo['path'];

        if ($this->isVector($path) && ($id = $thumbnailInfo['id'])) {
            return [
                'id' => $id,
                'markup' => $this->makePartial('thumbnail-image', [
                    'imageUrl' => MediaLibrary::url($thumbnailInfo['path']),
                ]),
            ];
        }

        try {



            $width = $thumbnailInfo['width'];
            $height = $thumbnailInfo['height'];
            $lastModified = $thumbnailInfo['lastModified'];

            if (!is_numeric($width) || !is_numeric($height) || !is_numeric($lastModified)) {
                throw new ApplicationException('Invalid input data');
            }

            if (!$thumbnailParams) {
                $thumbnailParams = $this->getThumbnailParams();
                $thumbnailParams['width'] = $width;
                $thumbnailParams['height'] = $height;
            }




            $thumbnailUrl = $this->getResizedImageUrl($path, $thumbnailParams);




            $markup = $this->makePartial('thumbnail-image', [
                'imageUrl' => $thumbnailUrl,
            ]);
        } catch (\Throwable $ex) {
            $markup = $this->makePartial('thumbnail-image', [
                'imageUrl' => false,
            ]);

            traceLog($ex->getMessage());
        }

        if ($markup && ($id = $thumbnailInfo['id'])) {
            return [
                'id' => $id,
                'markup' => $markup,
            ];
        }

        return [];
    }




    protected function getResizedImageUrl(string $path, array $params): string
    {
        return ImageResizer::filterGetUrl(
            MediaLibrary::url($path),
            $params['width'],
            $params['height'],
            array_merge(
                ['mode' => 'exact'],
                $params
            )
        );
    }







    protected function deduplicatePath(string $path, ?string $suffix = null): string
    {
        $parts = pathinfo($path);
        $i = 1;



        $parts['dirname'] = rtrim($parts['dirname'], DIRECTORY_SEPARATOR);


        if (!empty($suffix)) {
            $parts['filename'] = preg_replace(

                '/' . preg_quote($suffix, '/') . '(_\d)?/',
                '',
                $parts['filename']
            ) . $suffix;


            $path = sprintf(
                '%s%s%s.%s',
                $parts['dirname'],
                DIRECTORY_SEPARATOR,
                $parts['filename'],
                $parts['extension']
            );
        }

        while (MediaLibrary::instance()->exists($path)) {
            $path = sprintf(
                '%s%s%s_%d.%s',
                $parts['dirname'],
                DIRECTORY_SEPARATOR,
                $parts['filename'],
                $i++,
                $parts['extension']
            );
        }

        return $path;
    }




    protected function isVector(string $path): bool
    {
        return (pathinfo($path, PATHINFO_EXTENSION) == 'svg');
    }






    protected function getPreferenceKey()
    {

        return "backend::widgets.media_manager." . strtolower($this->getId());
    }
}
