<?php

include_once("includes/header.php");
include_once("includes/footer.php");
include_once("includes/db.php");



$db = connect_db();



printHeader();


$policyID = $_GET['policy'];

?>
	<div id="centercontent">
		<h1>Policy ACLs</h1>
		<table class="results">
			<tr class="resultstitle">
				<td>Source</td>
				<td>Destination</td>
				<td>Disabled</td>
			</tr>
<?php
			$stmt = $db->prepare('SELECT Source, Destination, Disabled FROM policy_acls WHERE PolicyID = ?');
			$res = $stmt->execute(array($policyID));

			# Loop with rows
			while ($row = $stmt->fetch()) {
?>
				<tr>
					<td><?php echo is_null($row['Source']) ? 'any' : $row['Source'] ?></td>
					<td><?php echo is_null($row['Destination']) ? 'any' : $row['Destination'] ?></td>
					<td><?php echo $row['Disabled'] ? 'yes' : 'no' ?></td>
				</tr>
<?php
			}
?>
			<tr>
				<td colspan="4">
					<a href="policy-acl-add.php">Add ACL</a>
				</td>
			</tr>
		</table>
	</div>
<?php

printFooter();


# vim: ts=4
?>
