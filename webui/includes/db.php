<?php

require_once('includes/config.php');

require_once 'MDB2.php';


# Connect to DB
function connect_db()
{
	global $DB_DSN;
	global $DB_USER;
	global $DB_PASS;

	try {
		$dbh = new PDO($DB_DSN, $DB_USER, $DB_PASS, array(
			PDO::ATTR_PERSISTENT => false
		));

		$dbh->setAttribute(PDO::ATTR_CASE,PDO::CASE_LOWER);

	} catch (PDOException $e) {
		die("Error conneting to DB: " . $e->getMessage());
	}

	return $dbh;
}


# vim: ts=4
?>
