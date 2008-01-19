<?php

include_once("includes/header.php");
include_once("includes/footer.php");
include_once("includes/db.php");



$db = connect_db();



printHeader();

# If we have no action, display list
if (!isset($_POST['action']))
{
?>
	<h1>Policy List</h1>

	<form id="main_form" action="policy-main.php" method="post">

		<div class="textcenter">
		Action
		<select id="main_form_action" name="action" onChange="document.getElementById('main_form').submit();">
			 
			<option selected>select action</option>
			<option disabled> - - - - - - - - - - - </option>
			<option value="change">Change</option>
			<option value="delete">Delete (not implemented yet)</option>
			<option disabled> - - - - - - - - - - - </option>
			<option value="acls">View ACLs</option>
		</select> 

		| <a href="policy-add.php">Add Policy</a>
		</div>

		<p />

		<table class="results">
			<tr class="resultstitle">
				<td id="noborder"></td>
				<td class="textcenter">Name</td>
				<td class="textcenter">Priority</td>
				<td class="textcenter">Description</td>
				<td class="textcenter">Disabled</td>
			</tr>
<?php
			$sql = 'SELECT ID, Name, Priority, Description, Disabled FROM policies';
			$res = $db->query($sql);

			$i = 0;
			while ($row = $res->fetchObject()) {
?>
				<tr class="resultsitem">
					<td><input type="checkbox" name="policylist[<?php echo $i ?>]" value="<?php echo $row->id ?>" /></td>
					<td><?php echo $row->name ?></td>
					<td class="textcenter"><?php echo $row->priority ?></td>
					<td><?php echo $row->description ?></td>
					<td class="textcenter"><?php echo $row->disabled ? 'yes' : 'no' ?></td>
				</tr>
<?php
				$i++;
			}
?>
		</table>
	</form>
<?php


# Display change screen
} elseif ($_POST['action'] == "change") {

	# Check a policy was selected
	if (isset($_POST['policylist'])) {
		# Prepare statement
		$stmt = $db->prepare('SELECT ID, Name, Priority, Description, Disabled FROM policies WHERE ID = ?');
?>
		<h1>Update Policies</h1>

		<form action="policy-main.php" method="post">
			<input type="hidden" name="action" value="update" />
<?php

			# Loop with policy list
			foreach ($_POST['policylist'] as $policy) {
				$res = $stmt->execute(array($policy));

				$row = $stmt->fetchObject();
?>
				<table class="entry" style="width: 75%;">
					<tr>
						<td></td>
						<td class="entrytitle textcenter">Old Value</td>
						<td class="entrytitle textcenter">New Value</td>
					</tr>
					<tr>
						<td class="entrytitle">Name</td>
						<td class="oldval"><?php echo $row->name ?></td>
						<td><input type="text" name="policyUpdates[<?php echo $row->id ?>][name]" /></td>
					</tr>
					<tr>
						<td class="entrytitle">Priority</td>
						<td class="oldval"><?php echo $row->priority ?></td>
						<td><input type="text" name="policyUpdates[<?php echo $row->id ?>][priority]" /></td>
					</tr>
					<tr>
						<td class="entrytitle texttop">Description</td>
						<td class="oldval texttop"><?php echo $row->description ?></td>
						<td><textarea name="policyUpdates[<?php echo $row->id ?>][description]" cols="40" rows="5"></textarea></td>
					</tr>
					<tr>
						<td class="entrytitle">Disabled</td>
						<td class="oldval"><?php echo $row->disabled ? 'yes' : 'no' ?></td>
						<td>
							<select name="policyUpdates[<?php echo $row->id ?>][disabled]" />
								<option value="">--</option>
								<option value="0">No</option>
								<option value="1">Yes</option>
							</select>		
						</td>
					</tr>
				</table>
		
				<p />
<?php
			}
?>
			<div class="textcenter">
				<input type="submit" />
			</div>
		</form>
<?php
	} else {

?>
		<div class="warning">No policy selected</div>
<?php
	}


# Policy updates
} elseif ($_POST['action'] == "update") {

	# Check a policy was selected
	if (isset($_POST['policyUpdates'])) {
		
		# Loop with updates
		foreach ($_POST['policyUpdates'] as $id => $policy) {
			$updates = array();

			if (!empty($policy['name'])) {
				array_push($updates,"Name = ".$db->quote($policy['name']));
			}
			if (isset($policy['priority']) && !is_null($policy['priority'])) {
				array_push($updates,"Priority = ".$db->quote($policy['priority']));
			}
			if (!empty($policy['description'])) {
				array_push($updates,"Description = ".$db->quote($policy['description']));
			}
			if (isset($policy['disabled']) && !is_null($policy['disabled'])) {
				array_push($updates ,"Disabled = ".$db->quote($policy['disabled']));
			}
		}

		# Check if we have updates
		if (sizeof($updates) > 0) {
			$updateStr = implode(', ',$updates);

			$res = $db->exec("UPDATE policies SET $updateStr WHERE ID = ".$db->quote($id));
			if ($res) {
?>
				<div class="notice">Policy ID '<?php echo $id ?>' updated</div>
<?php
			} else {
?>
				<div class="warning">Policy ID '<?php echo $id ?>' NOT updated!</div>
<?php
			}

		} else {
?>
			<div class="warning">No changes made to policy ID '<?php echo $id ?>'</div>
<?php
		}


	# Warn
	} else {
?>
		<div class="warning">No policy updates</div>
<?php
	}

}


printFooter();


# vim: ts=4
?>
