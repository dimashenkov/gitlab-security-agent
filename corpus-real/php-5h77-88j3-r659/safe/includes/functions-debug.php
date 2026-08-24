<?php















function yourls_debug_log(string $msg): string {
    if (yourls_get_debug_mode()) {
        yourls_do_action('debug_log', $msg);
        yourls_get_db('read-debug_log')->getProfiler()->getLogger()->log('debug', $msg);
    }
    return $msg;
}







function yourls_get_debug_log(): array {
    return yourls_get_db('read-get_debug_log')->getProfiler()->getLogger()->getMessages();
}






function yourls_get_num_queries(): int {
    return yourls_apply_filter( 'get_num_queries', yourls_get_db('read-get_num_queries')->get_num_queries() );
}








function yourls_debug_mode(bool $bool): void {

    yourls_get_db('read-debug_mode')->getProfiler()->setActive( (bool)$bool );


    $level = $bool ? -1 : ( E_ERROR | E_PARSE );
    error_reporting( $level );
}







function yourls_get_debug_mode(): bool {
    return yourls_get_db('read-debug_mode')->getProfiler()->isActive();
}
