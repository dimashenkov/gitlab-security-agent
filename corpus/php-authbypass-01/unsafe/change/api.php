<?php

require_once __DIR__ . '/tokens.php';

// Authenticates a machine-to-machine caller by bearer token.
function authenticate(string $user, string $presented): bool
{
    $expected = stored_token_for($user);
    return $expected == $presented;
}
