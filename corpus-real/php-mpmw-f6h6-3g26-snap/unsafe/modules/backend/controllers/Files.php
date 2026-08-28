<?php namespace Backend\Controllers;

use View;
use Cache;
use Config;
use Backend;
use Response;
use System\Models\File as FileModel;
use Backend\Classes\Controller;
use ApplicationException;
use Exception;
use RuntimeException;











class Files extends Controller
{



    public function get($code = null)
    {
        try {
            return $this->findFileObject($code)->output('inline', true);
        }
        catch (Exception $ex) {
        }

        return Response::make(View::make('backend::404'), 404);
    }




    public function thumb($code = null, $width = 100, $height = 100, $mode = 'auto', $extension = 'auto')
    {
        try {
            return $this->findFileObject($code)->outputThumb(
                $width,
                $height,
                compact('mode', 'extension'),
                true
            );
        }
        catch (Exception $ex) {
        }

        return Response::make(View::make('backend::404'), 404);
    }








    protected static function getTemporaryUrl($file, $path = null)
    {

        $disk = $file->getDisk();

        if (empty($path)) {
            $path = $file->getDiskPath();
        }


        $pathKey = 'backend.file:' . $path;
        $url = Cache::get($pathKey, null);

        if (is_null($url) && $disk->exists($path)) {
            $expires = now()->addSeconds(Config::get('cms.storage.uploads.temporaryUrlTTL', 3600));
            $url = Cache::remember($pathKey, $expires, function () use ($disk, $path, $expires) {


                try {
                    return $disk->temporaryUrl($path, $expires);
                } catch (RuntimeException $ex) {
                    return false;
                }
            });
        }


        if (!is_string($url) || empty($url)) {
            $url = null;
        }

        return $url;
    }






    public static function getDownloadUrl($file)
    {
        $url = static::getTemporaryUrl($file);

        if (!empty($url)) {
            return $url;
        } else {
            return Backend::url('backend/files/get/' . self::getUniqueCode($file));
        }
    }









    public static function getThumbUrl($file, $width, $height, $options)
    {
        $url = static::getTemporaryUrl($file, $file->getDiskPath($file->getThumbFilename($width, $height, $options)));

        if (!empty($url)) {
            return $url;
        } else {
            return Backend::url('backend/files/thumb/' . self::getUniqueCode($file)) . '/' . $width . '/' . $height . '/' . $options['mode'] . '/' . $options['extension'];
        }
    }






    public static function getUniqueCode($file)
    {
        if (!$file) {
            return null;
        }

        $hash = md5($file->file_name . '!' . $file->disk_name);
        return base64_encode($file->id . '!' . $hash);
    }






    protected function findFileObject($code)
    {
        if (!$code) {
            throw new ApplicationException('Missing code');
        }

        $parts = explode('!', base64_decode($code));
        if (count($parts) < 2) {
            throw new ApplicationException('Invalid code');
        }

        list($id, $hash) = $parts;

        if (!$file = FileModel::find((int) $id)) {
            throw new ApplicationException('Unable to find file');
        }





        if ($file->attachment) {
            $fileModel = $file->attachment->{$file->field}()->getRelated();






            if (get_class($file) !== get_class($fileModel)) {
                $file = $fileModel->find($file->id);
            }
        }

        $verifyCode = self::getUniqueCode($file);
        if ($code != $verifyCode) {
            throw new ApplicationException('Invalid hash');
        }

        return $file;
    }
}
