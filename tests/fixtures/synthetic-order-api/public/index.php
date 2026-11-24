<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/bootstrap.php';

use AcmeBistro\OrderApi\Database\DatabaseManager;
use AcmeBistro\OrderApi\Http\Request;
use AcmeBistro\OrderApi\Kernel;

$sqlitePath = getenv('ACME_SQLITE_PATH');
if (is_string($sqlitePath) && $sqlitePath !== '') {
    $isNew = !is_file($sqlitePath);
    $db = new DatabaseManager('sqlite:' . $sqlitePath);
    if ($isNew) {
        $db->migrate();
        $db->seed();
    }
    $kernel = new Kernel($db);
} else {
    $kernel = Kernel::bootFresh();
}

$response = $kernel->handle(Request::fromGlobals());
$response->send();
