<?php
# Module: CheckHelo (whitelist) change
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
			"Back to whitelist" => "checkhelo-whitelist-main.php"
		),
));



# Display change screen
if ($_POST['action'] == "change") {

	# Check a whitelist was selected
	if (isset($_POST['whitelist_id'])) {
		# Prepare statement
		$stmt = $db->prepare('
			SELECT 
				checkhelo_whitelist.ID, checkhelo_whitelist.Address, checkhelo_whitelist.Comment, 
				checkhelo_whitelist.Disabled
				
			FROM 
				checkhelo_whitelist

			WHERE 
				checkhelo_whitelist.ID = ?
			');
?>
		<h1>Update HELO/EHLO Whitelist</h1>

		<form action="checkhelo-whitelist-change.php" method="post">
			<div>
				<input type="hidden" name="action" value="change2" />
				<input type="hidden" name="whitelist_id" value="<?php echo $_POST['whitelist_id']; ?>" />
			</div>
<?php

			$res = $stmt->execute(array($_POST['whitelist_id']));

			$row = $stmt->fetchObject();
?>
			<table class="entry" style="width: 75%;">
				<tr>
					<td></td>
					<td class="entrytitle textcenter">Old Value</td>
					<td class="entrytitle textcenter">New Value</td>
				</tr>
				<tr>
					<td class="entrytitle">Address</td>
					<td class="oldval"><?php echo $row->address ?></td>
					<td><input type="text" name="whitelist_address" /></td>
				</tr>
				<tr>
					<td class="entrytitle texttop">Comment</td>
					<td class="oldval texttop"><?php echo $row->comment ?></td>
					<td><textarea name="whitelist_comment" cols="40" rows="5"></textarea></td>
				</tr>
				<tr>
					<td class="entrytitle">Disabled</td>
					<td class="oldval"><?php echo $row->disabled ? 'yes' : 'no' ?></td>
					<td>
						<select name="whitelist_disabled">
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
		<div class="warning">No whitelisting selected</div>
<?php
	}
	
	
	
# SQL Updates
} elseif ($_POST['action'] == "change2") {
?>
	<h1>HELO/EHLO Whitelisting Update Results</h1>
<?
	$updates = array();

	if (!empty($_POST['whitelist_address'])) {
		array_push($updates,"Address = ".$db->quote($_POST['whitelist_address']));
	}
	if (!empty($_POST['whitelist_comment'])) {
		array_push($updates,"Comment = ".$db->quote($_POST['whitelist_comment']));
	}
	if (isset($_POST['whitelist_disabled']) && $_POST['whitelist_disabled'] != "") {
		array_push($updates ,"Disabled = ".$db->quote($_POST['whitelist_disabled']));
	}

	# Check if we have updates
	if (sizeof($updates) > 0) {
		$updateStr = implode(', ',$updates);

		$res = $db->exec("UPDATE checkhelo_whitelist SET $updateStr WHERE ID = ".$db->quote($_POST['whitelist_id']));
		if ($res) {
?>
			<div class="notice">HELO/EHLO whitelisting updated</div>
<?php
		} else {
?>
			<div class="warning">Error updating HELO/EHLO whitelisting!</div>
<?php
		}

	} else {
?>
		<div class="warning">No changes made to HELO/EHLO whitelisting</div>
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
