<?php

# mysql:host=xx;dbname=yyy
#
# pgsql:host=xx;dbname=yyy
#
# sqlite:////full/unix/path/to/file.db?mode=0666
#
#$DB_DSN="sqlite:////tmp/cluebringer.sqlite";
$DB_DSN="mysql:host=localhost;dbname=policyd";
$DB_USER="root";
#$DB_PASS="";
$DB_TABLE_PREFIX="";

$DB_POSTFIX_DSN="mysql:host=localhost;dbname=postfix";
$DB_POSTFIX_USER="root";
#$DB_POSTFIX_PASS="";

?>
