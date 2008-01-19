<?php

include_once("includes/header.php");
include_once("includes/footer.php");
include_once("includes/db.php");



$db = connect_db();



printHeader();


if (!isset($_POST['action'])) {
?>
	<div id="centercontent">
		<h1>Add Policy</h1>

		<form method="post" action="policy-add.php">
			<input type="hidden" name="action" value="add" />
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
					<td><textarea name="policy_description" cols="40" rows="5" /></textarea></td>
				</tr>
				<tr>
					<td colspan="2">
						<input type="submit" />
					</td>
				</tr>
			</table>
		</form>
	</div>

<?php

# Check we have all params
} elseif ($_POST['action'] == "add") {

	# Check name
	if (empty($_POST['policy_name'])) {
?>
		<div class="warning">Policy name cannot be empty</div>
<?php

	# Check priority
	} elseif (empty($_POST['policy_priority'])) {
?>
		<div class="warning">Policy priority cannot be empty</div>
<?php

	# Check description
	} elseif (empty($_POST['policy_description'])) {
?>
		<div class="warning">Policy description cannot be empty</div>
<?php

	} else {
		$stmt = $db->prepare("INSERT INTO policies (Name,Priority,Description,Disabled) VALUES (?,?,?,1)");

		$res = $stmt->execute(array(
			$_POST['policy_name'],
			$_POST['policy_priority'],
			$_POST['policy_description']
		));
		if ($res) {
?>
			<div class="notice">Policy created</div>
<?php
		} else {
?>
			<div class="warning">Failed to create policy</div>
<?php
		}

	}


} else {
?>
	<div class="warning">Unknown mode of operation</div>
<?php
}

printFooter();


# vim: ts=4
?>
