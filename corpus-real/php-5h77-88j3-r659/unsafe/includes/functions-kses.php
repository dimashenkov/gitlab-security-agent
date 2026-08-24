<?php












































yourls_add_action( 'plugins_loaded', 'yourls_kses_init' );







function yourls_kses_init() {
    global $yourls_allowedentitynames, $yourls_allowedprotocols;

    if( ! $yourls_allowedentitynames ) {
        $yourls_allowedentitynames = yourls_apply_filter( 'kses_allowed_entities', yourls_kses_allowed_entities() );
    }

    if( ! $yourls_allowedprotocols ) {
        $yourls_allowedprotocols   = yourls_apply_filter( 'kses_allowed_protocols', yourls_kses_allowed_protocols() );
    }






















}











function yourls_kses_allowed_tags_all() {
    return array(
        'address' => array(),
        'a' => array(
            'href' => true,
            'rel' => true,
            'rev' => true,
            'name' => true,
            'target' => true,
        ),
        'abbr' => array(),
        'acronym' => array(),
        'area' => array(
            'alt' => true,
            'coords' => true,
            'href' => true,
            'nohref' => true,
            'shape' => true,
            'target' => true,
        ),
        'article' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'aside' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'b' => array(),
        'big' => array(),
        'blockquote' => array(
            'cite' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'br' => array(),
        'button' => array(
            'disabled' => true,
            'name' => true,
            'type' => true,
            'value' => true,
        ),
        'caption' => array(
            'align' => true,
        ),
        'cite' => array(
            'dir' => true,
            'lang' => true,
        ),
        'code' => array(),
        'col' => array(
            'align' => true,
            'char' => true,
            'charoff' => true,
            'span' => true,
            'dir' => true,
            'valign' => true,
            'width' => true,
        ),
        'del' => array(
            'datetime' => true,
        ),
        'dd' => array(),
        'details' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'open' => true,
            'xml:lang' => true,
        ),
        'div' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'dl' => array(),
        'dt' => array(),
        'em' => array(),
        'fieldset' => array(),
        'figure' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'figcaption' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'font' => array(
            'color' => true,
            'face' => true,
            'size' => true,
        ),
        'footer' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'form' => array(
            'action' => true,
            'accept' => true,
            'accept-charset' => true,
            'enctype' => true,
            'method' => true,
            'name' => true,
            'target' => true,
        ),
        'h1' => array(
            'align' => true,
        ),
        'h2' => array(
            'align' => true,
        ),
        'h3' => array(
            'align' => true,
        ),
        'h4' => array(
            'align' => true,
        ),
        'h5' => array(
            'align' => true,
        ),
        'h6' => array(
            'align' => true,
        ),
        'header' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'hgroup' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'hr' => array(
            'align' => true,
            'noshade' => true,
            'size' => true,
            'width' => true,
        ),
        'i' => array(),
        'img' => array(
            'alt' => true,
            'align' => true,
            'border' => true,
            'height' => true,
            'hspace' => true,
            'longdesc' => true,
            'vspace' => true,
            'src' => true,
            'usemap' => true,
            'width' => true,
        ),
        'ins' => array(
            'datetime' => true,
            'cite' => true,
        ),
        'kbd' => array(),
        'label' => array(
            'for' => true,
        ),
        'legend' => array(
            'align' => true,
        ),
        'li' => array(
            'align' => true,
        ),
        'map' => array(
            'name' => true,
        ),
        'menu' => array(
            'type' => true,
        ),
        'nav' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'p' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'pre' => array(
            'width' => true,
        ),
        'q' => array(
            'cite' => true,
        ),
        's' => array(),
        'span' => array(
            'dir' => true,
            'align' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'section' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'small' => array(),
        'strike' => array(),
        'strong' => array(),
        'sub' => array(),
        'summary' => array(
            'align' => true,
            'dir' => true,
            'lang' => true,
            'xml:lang' => true,
        ),
        'sup' => array(),
        'table' => array(
            'align' => true,
            'bgcolor' => true,
            'border' => true,
            'cellpadding' => true,
            'cellspacing' => true,
            'dir' => true,
            'rules' => true,
            'summary' => true,
            'width' => true,
        ),
        'tbody' => array(
            'align' => true,
            'char' => true,
            'charoff' => true,
            'valign' => true,
        ),
        'td' => array(
            'abbr' => true,
            'align' => true,
            'axis' => true,
            'bgcolor' => true,
            'char' => true,
            'charoff' => true,
            'colspan' => true,
            'dir' => true,
            'headers' => true,
            'height' => true,
            'nowrap' => true,
            'rowspan' => true,
            'scope' => true,
            'valign' => true,
            'width' => true,
        ),
        'textarea' => array(
            'cols' => true,
            'rows' => true,
            'disabled' => true,
            'name' => true,
            'readonly' => true,
        ),
        'tfoot' => array(
            'align' => true,
            'char' => true,
            'charoff' => true,
            'valign' => true,
        ),
        'th' => array(
            'abbr' => true,
            'align' => true,
            'axis' => true,
            'bgcolor' => true,
            'char' => true,
            'charoff' => true,
            'colspan' => true,
            'headers' => true,
            'height' => true,
            'nowrap' => true,
            'rowspan' => true,
            'scope' => true,
            'valign' => true,
            'width' => true,
        ),
        'thead' => array(
            'align' => true,
            'char' => true,
            'charoff' => true,
            'valign' => true,
        ),
        'title' => array(),
        'tr' => array(
            'align' => true,
            'bgcolor' => true,
            'char' => true,
            'charoff' => true,
            'valign' => true,
        ),
        'tt' => array(),
        'u' => array(),
        'ul' => array(
            'type' => true,
        ),
        'ol' => array(
            'start' => true,
            'type' => true,
        ),
        'var' => array(),
    );
}










function yourls_kses_allowed_tags() {
    return array(
        'a' => array(
            'href' => true,
            'title' => true,
        ),
        'abbr' => array(
            'title' => true,
        ),
        'acronym' => array(
            'title' => true,
        ),
        'b' => array(),
        'blockquote' => array(
            'cite' => true,
        ),
        'cite' => array(),
        'code' => array(),
        'del' => array(
            'datetime' => true,
        ),
        'em' => array(),
        'i' => array(),
        'q' => array(
            'cite' => true,
        ),
        'strike' => array(),
        'strong' => array(),
    );
}








function yourls_kses_allowed_entities() {
    return array(
        'nbsp',    'iexcl',  'cent',    'pound',  'curren', 'yen',
        'brvbar',  'sect',   'uml',     'copy',   'ordf',   'laquo',
        'not',     'shy',    'reg',     'macr',   'deg',    'plusmn',
        'acute',   'micro',  'para',    'middot', 'cedil',  'ordm',
        'raquo',   'iquest', 'Agrave',  'Aacute', 'Acirc',  'Atilde',
        'Auml',    'Aring',  'AElig',   'Ccedil', 'Egrave', 'Eacute',
        'Ecirc',   'Euml',   'Igrave',  'Iacute', 'Icirc',  'Iuml',
        'ETH',     'Ntilde', 'Ograve',  'Oacute', 'Ocirc',  'Otilde',
        'Ouml',    'times',  'Oslash',  'Ugrave', 'Uacute', 'Ucirc',
        'Uuml',    'Yacute', 'THORN',   'szlig',  'agrave', 'aacute',
        'acirc',   'atilde', 'auml',    'aring',  'aelig',  'ccedil',
        'egrave',  'eacute', 'ecirc',   'euml',   'igrave', 'iacute',
        'icirc',   'iuml',   'eth',     'ntilde', 'ograve', 'oacute',
        'ocirc',   'otilde', 'ouml',    'divide', 'oslash', 'ugrave',
        'uacute',  'ucirc',  'uuml',    'yacute', 'thorn',  'yuml',
        'quot',    'amp',    'lt',      'gt',     'apos',   'OElig',
        'oelig',   'Scaron', 'scaron',  'Yuml',   'circ',   'tilde',
        'ensp',    'emsp',   'thinsp',  'zwnj',   'zwj',    'lrm',
        'rlm',     'ndash',  'mdash',   'lsquo',  'rsquo',  'sbquo',
        'ldquo',   'rdquo',  'bdquo',   'dagger', 'Dagger', 'permil',
        'lsaquo',  'rsaquo', 'euro',    'fnof',   'Alpha',  'Beta',
        'Gamma',   'Delta',  'Epsilon', 'Zeta',   'Eta',    'Theta',
        'Iota',    'Kappa',  'Lambda',  'Mu',     'Nu',     'Xi',
        'Omicron', 'Pi',     'Rho',     'Sigma',  'Tau',    'Upsilon',
        'Phi',     'Chi',    'Psi',     'Omega',  'alpha',  'beta',
        'gamma',   'delta',  'epsilon', 'zeta',   'eta',    'theta',
        'iota',    'kappa',  'lambda',  'mu',     'nu',     'xi',
        'omicron', 'pi',     'rho',     'sigmaf', 'sigma',  'tau',
        'upsilon', 'phi',    'chi',     'psi',    'omega',  'thetasym',
        'upsih',   'piv',    'bull',    'hellip', 'prime',  'Prime',
        'oline',   'frasl',  'weierp',  'image',  'real',   'trade',
        'alefsym', 'larr',   'uarr',    'rarr',   'darr',   'harr',
        'crarr',   'lArr',   'uArr',    'rArr',   'dArr',   'hArr',
        'forall',  'part',   'exist',   'empty',  'nabla',  'isin',
        'notin',   'ni',     'prod',    'sum',    'minus',  'lowast',
        'radic',   'prop',   'infin',   'ang',    'and',    'or',
        'cap',     'cup',    'int',     'sim',    'cong',   'asymp',
        'ne',      'equiv',  'le',      'ge',     'sub',    'sup',
        'nsub',    'sube',   'supe',    'oplus',  'otimes', 'perp',
        'sdot',    'lceil',  'rceil',   'lfloor', 'rfloor', 'lang',
        'rang',    'loz',    'spades',  'clubs',  'hearts', 'diams',
    );
}








function yourls_kses_allowed_protocols() {

    return array(

        'http://', 'https://', 'ftp://',
        'file://', 'smb://',
        'sftp://',
        'feed:', 'feed://',
        'mailto:',
        'news:', 'nntp://',


        'gopher://', 'telnet://', 'finger://',
        'nntp://', 'worldwind://',


        'ssh://', 'svn://', 'svn+ssh://', 'git://', 'cvs://',
        'apt:',
        'market://',
        'view-source:',


        'ed2k://', 'magnet:', 'udp://',


        'mms://', 'lastfm://', 'spotify:', 'rtsp://',


        'aim:', 'facetime://', 'gtalk:', 'xmpp:',
        'irc://', 'ircs://', 'mumble://',
        'callto:', 'skype:', 'sip:',
        'teamspeak://', 'tel:', 'ventrilo://', 'xfire:',
        'ymsgr:', 'tg://', 'whatsapp://',


        'steam:', 'steam://',
        'bitcoin:',
        'ldap://', 'ldaps://',







    );
}













function yourls_kses_normalize_entities($string) {


    $string = str_replace('&', '&amp;', $string);



    $string = preg_replace_callback('/&amp;([A-Za-z]{2,8});/', 'yourls_kses_named_entities', $string);
    $string = preg_replace_callback('/&amp;#(0*[0-9]{1,7});/', 'yourls_kses_normalize_entities2', $string);
    $string = preg_replace_callback('/&amp;#[Xx](0*[0-9A-Fa-f]{1,6});/', 'yourls_kses_normalize_entities3', $string);

    return $string;
}












function yourls_kses_named_entities($matches) {
    global $yourls_allowedentitynames;

    if ( empty($matches[1]) )
        return '';

    $i = $matches[1];
    return ( ( ! in_array($i, $yourls_allowedentitynames) ) ? "&amp;$i;" : "&$i;" );
}













function yourls_kses_normalize_entities2($matches) {
    if ( empty($matches[1]) )
        return '';

    $i = $matches[1];
    if (yourls_valid_unicode($i)) {
        $i = str_pad(ltrim($i,'0'), 3, '0', STR_PAD_LEFT);
        $i = "&#$i;";
    } else {
        $i = "&amp;#$i;";
    }

    return $i;
}













function yourls_kses_normalize_entities3($matches) {
    if ( empty($matches[1]) )
        return '';

    $hexchars = $matches[1];
    return ( ( ! yourls_valid_unicode(hexdec($hexchars)) ) ? "&amp;#x$hexchars;" : '&#x'.ltrim($hexchars,'0').';' );
}










function _yourls_add_global_attributes( $value ) {
    $global_attributes = array(
        'class' => true,
        'id' => true,
        'style' => true,
        'title' => true,
    );

    if ( true === $value )
        $value = array();

    if ( is_array( $value ) )
        return array_merge( $value, $global_attributes );

    return $value;
}









function yourls_valid_unicode($i) {
    return ( $i == 0x9 || $i == 0xa || $i == 0xd ||
            ($i >= 0x20 && $i <= 0xd7ff) ||
            ($i >= 0xe000 && $i <= 0xfffd) ||
            ($i >= 0x10000 && $i <= 0x10ffff) );
}









function yourls_kses_array_lc($inarray) {
    $outarray = array ();

    foreach ( (array) $inarray as $inkey => $inval) {
        $outkey = strtolower($inkey);
        $outarray[$outkey] = array ();

        foreach ( (array) $inval as $inkey2 => $inval2) {
            $outkey2 = strtolower($inkey2);
            $outarray[$outkey][$outkey2] = $inval2;
        }
    }

    return $outarray;
}













function yourls_kses_decode_entities($string) {
    $string = preg_replace_callback('/&#([0-9]+);/', '_yourls_kses_decode_entities_chr', $string);
    $string = preg_replace_callback('/&#[Xx]([0-9A-Fa-f]+);/', '_yourls_kses_decode_entities_chr_hexdec', $string);

    return $string;
}









function _yourls_kses_decode_entities_chr( $match ) {
    return chr( $match[1] );
}









function _yourls_kses_decode_entities_chr_hexdec( $match ) {
    return chr( hexdec( $match[1] ) );
}









function yourls_kses_no_null($string) {
    $string = preg_replace( '/\0+/', '', $string );
    $string = preg_replace( '/(\\\\0)+/', '', $string );

    return $string;
}
