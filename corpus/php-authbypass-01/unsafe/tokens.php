<?php

function stored_token_for(string $user): string
{
    return hash_hmac('sha256', $user, getenv('TOKEN_SECRET'));
}
