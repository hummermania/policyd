<?php
# Module: Quotas limits add
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
			"Back to quotas" => "quotas-main.php",
			"Back to quota limits" => "quotas-limits-main.php?quota_id=".$_REQUEST['quota_id'],
		),
));


if ($_POST['action'] == "add")  {
?>
	<h1>Add Quota Limit</h1>
<?php
	if (!empty($_POST['quota_id'])) {
?>
		<form method="post" action="quotas-limits-add.php">
			<div>
				<input type="hidden" name="action" value="add2" />
				<input type="hidden" name="quota_id" value="<?php echo $_POST['quota_id'] ?>" />
			</div>
			<table class="entry">
				<tr>
					<td class="entrytitle">Type</td>
					<td>
						<select name="limit_type">
							<option value="MessageCount">Message Count</option>
							<option value="MessageCumulativeSize">Message Cumulative Size</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">Counter Limit</td>
					<td><input type="text" name="limit_counterlimit" /></td>
				</tr>
				<tr>
					<td class="entrytitle">Comment</td>
					<td><textarea name="limit_comment"></textarea></td>
				</tr>
				<tr>
					<td colspan="2">
						<input type="submit" />
					</td>
				</tr>
			</table>
		</form>
<?php
	} else {
?>
		<div class="warning">No policy ID, invalid invocation?</div>
<?php
	}
	
	
	
# Check we have all params
} elseif ($_POST['action'] == "add2") {
?>
	<h1>Quota Limit Add Results</h1>

<?php
	# Check we have a limit
	if (empty($_POST['limit_counterlimit'])) {
?>
		<div class="warning">Counter limit is required</div>
<?php


	} else {
		$stmt = $db->prepare("INSERT INTO quotas_limits (QuotasID,Type,CounterLimit,Comment,Disabled) VALUES (?,?,?,?,1)");
		
		$res = $stmt->execute(array(
			$_POST['quota_id'],
			$_POST['limit_type'],
			$_POST['limit_counterlimit'],
			$_POST['limit_comment']
		));
		if ($res) {
?>
			<div class="notice">Quota limit created</div>
<?php
		} else {
?>
			<div class="warning">Failed to create quota limit</div>
<?php
		}

	}


} else {
?>
	<div class="warning">Invalid invocation</div>
<?php
}


printFooter();


# vim: ts=4
?>