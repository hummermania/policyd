<?php

include_once("includes/header.php");
include_once("includes/footer.php");
include_once("includes/db.php");



$db = connect_db();



printHeader();

?>
	<div id="centercontent">
		<h1>Add Policy</h1>

		<form method="post" action="policy-add.php">
			<table class="entry">
				<tr>
					<td class="entrytitle">Name</td>
					<td><input type="text" name="policy_name" /></td>
				</tr>
				<tr>
					<td class="entrytitle">Priority</td>
					<td><input type="text" size="4" name="policy_priority" /> (50-100: 50 lowest, 100 highest)</td>
				</tr>
				<tr>
					<td class="entrytitle">Description</td>
					<td><input type="text" name="policy_description" /></td>
				</tr>
				<tr>
					<td colspan="2">
						<input type="submit" />
					</td>
				</tr>
			</table>
		</form>
</div>


</div>
<?php

printFooter();


# vim: ts=4
?>
