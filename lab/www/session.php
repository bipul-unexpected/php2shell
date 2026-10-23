<?php
// Chain E producer: any endpoint that calls session_start() is enough.
// On the vulnerable build, decoding a large session can OOM inside
// php_var_unserialize and leave BG(unserialize) dirty for the next request.
session_start();

$count = count($_SESSION);
echo "session started\n";
echo "sid=" . session_id() . "\n";
echo "keys=" . $count . "\n";
