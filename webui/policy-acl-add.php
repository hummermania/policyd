<?php

include_once("includes/header.php");
include_once("includes/footer.php");
include_once("includes/db.php");



$db = connect_db();



printHeader();

?>
	<div id="centercontent">
		<h1>Add ACL</h1>

		<form method="post" action="policy-acl-add.php">
			<table class="entry">
				<tr>
					<td class="entrytitle">Source</td>
					<td><input type="text" name="acl_source" /></td>
				</tr>
				<tr>
					<td class="entrytitle">Destination</td>
					<td><input type="text" name="acl_destination" /></td>
				</tr>
				<tr>
					<td class="entrytitle">Comment</td>
					<td><textarea name="acl_comment"></textarea></td>
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
