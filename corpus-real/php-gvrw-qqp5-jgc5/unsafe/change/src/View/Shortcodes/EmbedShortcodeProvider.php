<?php

namespace SilverStripe\View\Shortcodes;

use Embed\Http\NetworkException;
use Embed\Http\RequestException;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;
use RuntimeException;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Model\List\ArrayList;
use SilverStripe\ORM\FieldType\DBField;
use SilverStripe\Model\ArrayData;
use SilverStripe\View\Embed\Embeddable;
use SilverStripe\View\HTML;
use SilverStripe\View\Parsers\ShortcodeHandler;
use SilverStripe\View\Parsers\ShortcodeParser;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\View\Embed\EmbedContainer;






class EmbedShortcodeProvider implements ShortcodeHandler
{
    use Configurable;







    private static array $domains_excluded_from_sandboxing = [];







    private static array $sandboxed_iframe_attributes = [];








    private static string $extractorUrl = '';






    public static function get_shortcodes()
    {
        return ['embed'];
    }













    public static function handle_shortcode($arguments, $content, $parser, $shortcode, $extra = [])
    {

        if (!empty($content)) {
            $serviceURL = $content;
        } elseif (!empty($arguments['url'])) {
            $serviceURL = $arguments['url'];
        } else {
            return '';
        }

        $class = $arguments['class'] ?? '';
        $width = $arguments['width'] ?? '';
        $height = $arguments['height'] ?? '';


        $cache = static::getCache();
        $key = static::deriveCacheKey($serviceURL, $class, $width, $height);
        try {
            if ($cache->has($key)) {
                return $cache->get($key);
            }
        } catch (InvalidArgumentException $e) {
        }


        $serviceArguments = [];
        if (!empty($arguments['width'])) {
            $serviceArguments['min_image_width'] = $arguments['width'];
        }
        if (!empty($arguments['height'])) {
            $serviceArguments['min_image_height'] = $arguments['height'];
        }


        $embeddable = Injector::inst()->create(Embeddable::class, $serviceURL);


        if (!($embeddable instanceof EmbedContainer)) {
            throw new \RuntimeException('Emeddable must extend EmbedContainer');
        }

        if (!empty($serviceArguments)) {
            $embeddable->setOptions(array_merge($serviceArguments, (array) $embeddable->getOptions()));
        }


        try {

            $embeddable->getExtractor();
        } catch (NetworkException | RequestException $e) {
            $message = (Director::isDev())
                ? $e->getMessage()
                : _t(__CLASS__ . '.INVALID_URL', 'There was a problem loading the media.');

            $attr = [
                'class' => 'ss-media-exception embed'
            ];

            $result = HTML::createTag(
                'div',
                $attr,
                HTML::createTag('p', [], $message)
            );
            return $result;
        }


        $html = static::embeddableToHtml($embeddable, $arguments);

        if (!$html) {
            $result = static::linkEmbed($arguments, $serviceURL, $serviceURL);
        }

        if ($html) {
            try {
                $cache->set($key, $html);
            } catch (InvalidArgumentException $e) {
            }
        }
        return $html;
    }

    public static function embeddableToHtml(Embeddable $embeddable, array $arguments): string
    {

        if (!($embeddable instanceof EmbedContainer)) {
            return '';
        }
        $extractor = $embeddable->getExtractor();
        EmbedShortcodeProvider::$extractorUrl = (string) $extractor->url;
        $type = $embeddable->getType();
        if ($type === 'video' || $type === 'rich') {

            if (empty($arguments['width']) && $embeddable->getWidth()) {
                $arguments['width'] = $embeddable->getWidth();
            }
            return static::videoEmbed($arguments, $extractor->code->html);
        }
        if ($type === 'photo') {
            return static::photoEmbed($arguments, (string) $extractor->url);
        }
        if ($type === 'link') {
            return static::linkEmbed($arguments, (string) $extractor->url, $extractor->title);
        }
        return '';
    }








    protected static function videoEmbed($arguments, $content)
    {

        if (!empty($arguments['width'])) {
            $arguments['style'] = 'width: ' . intval($arguments['width']) . 'px;';
        }

        if (!empty($arguments['caption'])) {
            $arguments['caption'] = htmlentities($arguments['caption'], ENT_QUOTES, 'UTF-8', false);
        }


        foreach (['width', 'height'] as $attr) {
            if (!($value = $arguments[$attr] ?? false)) {
                continue;
            }
            foreach (['"', "'"] as $quote) {
                $rx = "/(<iframe .*?)$attr=$quote([0-9]+)$quote([^>]+>)/";
                $content = preg_replace($rx ?? '', "$1{$attr}={$quote}{$value}{$quote}$3", $content ?? '');
            }
        }

        $attributes = static::buildAttributeListFromArguments($arguments, ['width', 'height', 'url', 'caption']);
        if (array_key_exists('style', $arguments)) {
            $attributes->push(ArrayData::create([
                'Name' => 'style',
                'Value' => Convert::raw2att($arguments['style']),
            ]));
        }

        $content = EmbedShortcodeProvider::sandboxHtml($content, $arguments);
        $data = [
            'Arguments' => $arguments,
            'Attributes' => $attributes,
            'Content' => DBField::create_field('HTMLFragment', $content)
        ];

        return ArrayData::create($data)->renderWith(EmbedShortcodeProvider::class . '_video')->forTemplate();
    }









    protected static function linkEmbed($arguments, $href, $title)
    {
        $data = [
            'Arguments' => $arguments,
            'Attributes' => static::buildAttributeListFromArguments($arguments, ['width', 'height', 'url', 'caption']),
            'Href' => $href,
            'Title' => !empty($arguments['caption']) ? ($arguments['caption']) : $title
        ];

        return ArrayData::create($data)->renderWith(EmbedShortcodeProvider::class . '_link')->forTemplate();
    }








    protected static function photoEmbed($arguments, $src)
    {
        $data = [
            'Arguments' => $arguments,
            'Attributes' => static::buildAttributeListFromArguments($arguments, ['url']),
            'Src' => $src
        ];

        return ArrayData::create($data)->renderWith(EmbedShortcodeProvider::class . '_photo')->forTemplate();
    }








    private static function buildAttributeListFromArguments(array $arguments, array $exclude = []): ArrayList
    {


        $whitelist = [
            'url',
            'thumbnail',
            'class',
            'width',
            'height',
            'caption'
        ];

        $arguments = array_filter($arguments, function ($value, $key) use ($whitelist) {
            return in_array($key, $whitelist) && strlen(trim($value ?? ''));
        }, ARRAY_FILTER_USE_BOTH);

        $attributes = ArrayList::create();
        foreach ($arguments as $key => $value) {
            if (in_array($key, $exclude ?? [])) {
                continue;
            }

            $attributes->push(ArrayData::create([
                'Name' => $key,
                'Value' => Convert::raw2att($value)
            ]));
        }

        return $attributes;
    }





    public static function flushCachedShortcodes(ShortcodeParser $parser, string $content): void
    {
        $cache = static::getCache();
        $tags = $parser->extractTags($content);
        foreach ($tags as $tag) {
            if (!isset($tag['open']) || $tag['open'] != 'embed') {
                continue;
            }
            $url = $tag['content'] ?? $tag['attrs']['url'] ?? '';
            $class = $tag['attrs']['class'] ?? '';
            $width = $tag['attrs']['width'] ?? '';
            $height = $tag['attrs']['height'] ?? '';
            if (!$url) {
                continue;
            }
            $key = static::deriveCacheKey($url, $class, $width, $height);
            try {
                if (!$cache->has($key)) {
                    continue;
                }
                $cache->delete($key);
            } catch (InvalidArgumentException $e) {
                continue;
            }
        }
    }




    private static function getCache(): CacheInterface
    {
        return Injector::inst()->get(CacheInterface::class . '.EmbedShortcodeProvider');
    }





    private static function deriveCacheKey(string $url, string $class, string $width, string $height): string
    {
        return implode('-', array_filter([
            'embed-shortcode',
            EmbedShortcodeProvider::cleanKeySegment($url),
            EmbedShortcodeProvider::cleanKeySegment($class),
            EmbedShortcodeProvider::cleanKeySegment($width),
            EmbedShortcodeProvider::cleanKeySegment($height)
        ]));
    }





    private static function cleanKeySegment(string $str): string
    {
        return preg_replace('/[^a-zA-Z0-9\-]/', '', $str ?? '');
    }






    private static function sandboxHtml(string $html, array $arguments)
    {

        if (EmbedShortcodeProvider::domainIsExcludedFromSandboxing()) {
            return $html;
        }

        if (preg_match('#^<iframe[^>]*>#', $html) && preg_match('#</iframe\s*>$#', $html)) {



            if (substr_count($html, '<') <= 2) {
                return $html;
            }
        }

        $style = '';
        if (!empty($arguments['width'])) {
            $style .= 'width:' . intval($arguments['width']) . 'px;';
        }
        if (!empty($arguments['height'])) {
            $style .= 'height:' . intval($arguments['height']) . 'px;';
        }
        $attrs = array_merge([
            'frameborder' => '0',
        ], static::config()->get('sandboxed_iframe_attributes'));
        $attrs['src'] = 'data:text/html;charset=utf-8,' . rawurlencode($html);
        if (array_key_exists('style', $attrs)) {
            $attrs['style'] .= ";$style";
            $attrs['style'] = ltrim($attrs['style'], ';');
        } else {
            $attrs['style'] = $style;
        }
        $html = HTML::createTag('iframe', $attrs);
        return $html;
    }




    private static function domainIsExcludedFromSandboxing(): bool
    {
        $domain = (string) parse_url(EmbedShortcodeProvider::$extractorUrl, PHP_URL_HOST);
        $config = static::config()->get('domains_excluded_from_sandboxing');
        foreach ($config as $excluded) {
            if (!is_string($excluded)) {
                throw new RuntimeException('domains_excluded_from_sandboxing must be an array of strings');
            }
            $excludedDomain = parse_url($excluded, PHP_URL_HOST);
            if (!$excludedDomain) {

                $excludedDomain = parse_url('http://' . $excluded, PHP_URL_HOST);
            }
            if (!$excludedDomain) {
                throw new RuntimeException('Not a valid domain: ' . $excluded);
            }
            if (str_ends_with($domain, $excludedDomain)) {
                return true;
            }
        }
        return false;
    }
}
