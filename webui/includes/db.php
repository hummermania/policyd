<?php

require_once('includes/config.php');


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
		die("Error connecting to Policyd v2 DB: " . $e->getMessage());
	}

	return $dbh;
}


# Connect to postfix DB
function connect_postfix_db()
{
	global $DB_POSTFIX_DSN;
	global $DB_POSTFIX_USER;
	global $DB_POSTFIX_PASS;

	try {
		$dbh = new PDO($DB_POSTFIX_DSN, $DB_POSTFIX_USER, $DB_POSTFIX_PASS, array(
			PDO::ATTR_PERSISTENT => false
		));

		$dbh->setAttribute(PDO::ATTR_CASE,PDO::CASE_LOWER);

	} catch (PDOException $e) {
		die("Error connecting to Postfix DB: " . $e->getMessage());
	}

	return $dbh;
}


# vim: ts=4
?>
