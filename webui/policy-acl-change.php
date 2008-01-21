<?php
# Policy ACL change
# Copyright (C) 2008, LinuxRulz
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.



include_once("includes/header.php");
include_once("includes/footer.php");
include_once("includes/db.php");



$db = connect_db();



printHeader(array(
		"Tabs" => array(
			"Back to policies" => "policy-main.php",
			"Back to ACLs" => "policy-acl-main.php?policy_id=".$_REQUEST['policy_id'],
		),
));



# Display change screen
if ($_POST['action'] == "change") {

	# Check a policy was selected
	if (isset($_POST['policy_acl_id'])) {
		# Prepare statement
		$stmt = $db->prepare('SELECT ID, Source, Destination, Comment, Disabled FROM policy_acls WHERE ID = ?');
		$res = $stmt->execute(array($_POST['policy_acl_id']));
		$row = $stmt->fetchObject();
?>
		<h1>Update Policy ACL</h1>

		<form action="policy-acl-change.php" method="post">
			<input type="hidden" name="action" value="change2" />
			<input type="hidden" name="policy_id" value="<?php echo $_POST['policy_id']; ?>" />
			<input type="hidden" name="policy_acl_id" value="<?php echo $_POST['policy_acl_id']; ?>" />
			<table class="entry" style="width: 75%;">
				<tr>
					<td></td>
					<td class="entrytitle textcenter">Old Value</td>
					<td class="entrytitle textcenter">New Value</td>
				</tr>
				<tr>
					<td class="entrytitle texttop">Source</td>
					<td class="oldval texttop"><?php echo $row->source ?></td>
					<td><textarea name="policy_acl_source" cols="40" rows="5"></textarea></td>
				</tr>
				<tr>
					<td class="entrytitle texttop">Destination</td>
					<td class="oldval texttop"><?php echo $row->destination ?></td>
					<td><textarea name="policy_acl_destination" cols="40" rows="5"></textarea></td>
				</tr>
				<tr>
					<td class="entrytitle texttop">Comment</td>
					<td class="oldval texttop"><?php echo $row->comment ?></td>
					<td><textarea name="policy_acl_comment" cols="40" rows="5"></textarea></td>
				</tr>
				<tr>
					<td class="entrytitle">Disabled</td>
					<td class="oldval"><?php echo $row->disabled ? 'yes' : 'no' ?></td>
					<td>
						<select name="policy_acl_disabled" />
							<option value="">--</option>
							<option value="0">No</option>
							<option value="1">Yes</option>
						</select>		
					</td>
				</tr>
			</table>
	
			<p />
			
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
	
	
	
# SQL Updates
} elseif ($_POST['action'] == "change2") {
?>
	<h1>Policy Update Results</h1>
<?
	# Check a policy was selected
	if (isset($_POST['policy_acl_id'])) {
		
		$updates = array();

		if (!empty($_POST['policy_acl_source'])) {
			array_push($updates,"Source = ".$db->quote($_POST['policy_acl_source']));
		}
		if (isset($_POST['policy_acl_destination']) && $_POST['policy_acl_destination'] != "") {
			array_push($updates,"Destination = ".$db->quote($_POST['policy_acl_destination']));
		}
		if (!empty($_POST['policy_acl_comment'])) {
			array_push($updates,"Comment = ".$db->quote($_POST['policy_acl_comment']));
		}
		if (isset($_POST['policy_acl_disabled']) && $_POST['policy_acl_disabled'] != "") {
			array_push($updates ,"Disabled = ".$db->quote($_POST['policy_acl_disabled']));
		}

		# Check if we have updates
		if (sizeof($updates) > 0) {
			$updateStr = implode(', ',$updates);
	
			$res = $db->exec("UPDATE policy_acls SET $updateStr WHERE ID = ".$db->quote($_POST['policy_acl_id']));
			if ($res) {
?>
				<div class="notice">Policy ACL updated</div>
<?php
			} else {
?>
				<div class="warning">Error updating policy ACL!</div>
<?php
			}

		# Warn
		} else {
?>
			<div class="warning">No policy ACL updates</div>
<?php
		}

	# Warn
	} else {
?>
		<div class="error">No policy ACL data available</div>
<?php
	}


} else {
?>
	<div class="warning">Invalid invocation</div>
<?php
}


printFooter();


# vim: ts=4
?>

