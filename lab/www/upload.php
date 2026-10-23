<?php
// Chain D/E consumer: no session_start() here on purpose.
// The rfc1867 upload_progress handler runs during SAPI startup, before this
// code, so stale worker state is consumed before the script executes.
header('Content-Type: text/plain');

if (!empty($_FILES)) {
    foreach ($_FILES as $name => $info) {
        echo "field={$name} name=" . ($info['name'] ?? '') . " size=" . ($info['size'] ?? 0) . "\n";
    }
} else {
    echo "no files\n";
}

echo "post_keys=" . implode(',', array_keys($_POST)) . "\n";
