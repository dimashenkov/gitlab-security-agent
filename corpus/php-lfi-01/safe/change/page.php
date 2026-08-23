<?php

require_once __DIR__ . '/config.php';

const PAGES = ['home', 'pricing', 'contact'];

// Renders one of the static marketing pages.
$page = $_GET['page'] ?? 'home';

if (!in_array($page, PAGES, true)) {
    http_response_code(404);
    exit;
}

include TEMPLATE_DIR . '/' . $page . '.php';
