<?php
// Lab landing page. Reports the runtime so the scanner has something to read.
header('X-Powered-By: PHP/' . PHP_VERSION);
?>
<!doctype html>
<title>php2shell lab</title>
<h1>php2shell lab</h1>
<p>PHP <?= PHP_VERSION ?> on <?= PHP_SAPI ?></p>
<ul>
  <li><a href="/lfi.php?file=/etc/hostname">lfi.php</a> &mdash; include() sink</li>
  <li><a href="/session.php">session.php</a> &mdash; session_start() producer</li>
  <li><a href="/upload.php">upload.php</a> &mdash; multipart endpoint</li>
</ul>
<p>Vulnerable by design. Loopback only.</p>
