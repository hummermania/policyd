<?php

include_once("includes/header.php");
include_once("includes/footer.php");
include_once("includes/db.php");



$db = connect_db();



printHeader(array(
		'Add Group' => "policy-groups-add.php",
	)
	);

?>
	<div id="centercontent">
		<h1>Policy Groups</h1>

		<table border="1">
			<tr>
				<td>Name</td>
				<td>Disabled</td>
			</tr>
<?php
			$sql = 'SELECT Name, Disabled FROM policy_groups';
			foreach ($db->query($sql) as $row) {
?>
				<tr>
					<td><?php echo $row['Name'] ?></td>
					<td><?php echo $row['Disabled'] ? 'yes' : 'no' ?></td>
				</tr>
<?php
			}
?>
		</table>



	</div>
<?php

printFooter();

# vim: ts=4
?>
