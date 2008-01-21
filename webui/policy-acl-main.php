<?php
# Policy ACL main screen
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
			"Back to policies" => "policy-main.php"
		),
));


# Check a policy was selected
if (isset($_REQUEST['policy_id'])) {

?>
	<h1>Policy ACLs</h1>
	
<?php		

	$policy_stmt = $db->prepare('SELECT Name FROM policies WHERE ID = ?');
	$stmt = $db->prepare('SELECT ID, Source, Destination, Disabled FROM policy_acls WHERE PolicyID = ?');

	$policy_stmt->execute(array($_REQUEST['policy_id']));
	$row = $policy_stmt->fetchObject();
?>
	<form id="main_form" action="policy-acl-main.php" method="post">
		<input type="hidden" name="policy_id" value="<?php echo $_REQUEST['policy_id'] ?>" />
		<div class="textcenter">
			<div class="notice">Policy: <?php echo $row->name ?></div>

			Action
			<select id="main_form_action" name="action" 
					onChange="
						var myform = document.getElementById('main_form');
						var myobj = document.getElementById('main_form_action');

						if (myobj.selectedIndex == 2) {
							myform.action = 'policy-acl-add.php';
							myform.submit();
						} else if (myobj.selectedIndex == 4) {
							myform.action = 'policy-acl-change.php';
							myform.submit();
						} else if (myobj.selectedIndex == 5) {
							myform.action = 'policy-acl-delete.php';
							myform.submit();
						}
">
	 
				<option selected>select action</option>
				<option disabled> - - - - - - - - - - - </option>
				<option value="add">Add</option>
				<option disabled> - - - - - - - - - - - </option>
				<option value="change">Change</option>
				<option value="delete">Delete</option>
			</select> 
		</div>

		<p />

		<table class="results" style="width: 75%;">
			<tr class="resultstitle">
				<td id="noborder"></td>
				<td class="textcenter">Source</td>
				<td class="textcenter">Destination</td>
				<td class="textcenter">Disabled</td>
			</tr>
<?php

			$res = $stmt->execute(array($_REQUEST['policy_id']));

			$i = 0;

			# Loop with rows
			while ($row = $stmt->fetchObject()) {
?>
				<tr class="resultsitem">
					<td><input type="radio" name="policy_acl_id" value="<?php echo $row->id ?>" /></td>
					<td class="textcenter"><?php echo is_null($row->source) ? 'any' : $row->source ?></td>
					<td class="textcenter"><?php echo is_null($row->destination) ? 'any' : $row->destination ?></td>
					<td class="textcenter"><?php echo $row->disabled ? 'yes' : 'no' ?></td>
				</tr>
<?php
				}
?>
		</table>
	</form>
<?php
} else {
?>
	<div class="warning">Invalid invocation</div>
<?php
}


printFooter();


# vim: ts=4
?>
