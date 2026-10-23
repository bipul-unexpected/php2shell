<?php
// Chain A sink: a deliberate, unauthenticated local file include.
// Session files live in /tmp/sess/sess_<sid>; including one executes any
// <?php block that the upload_progress handler wrote into the filename field.
$file = $_GET['file'] ?? '';
if ($file === '') {
    http_response_code(400);
    echo "usage: lfi.php?file=/path\n";
    exit;
}

if (!is_file($file)) {
    http_response_code(404);
    echo "not found\n";
    exit;
}

include($file);
