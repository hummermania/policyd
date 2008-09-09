<?php
# Module: Greylisting change
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
include_once("includes/tooltips.php");



$db = connect_db();



printHeader(array(
		"Tabs" => array(
			"Back to greylisting" => "greylisting-main.php"
		),
));



# Display change screen
if ($_POST['frmaction'] == "change") {

	# Check a greylisting was selected
	if (isset($_POST['greylisting_id'])) {
		# Prepare statement
		$stmt = $db->prepare('
			SELECT 
				greylisting.ID, greylisting.PolicyID, greylisting.Name, 
			
				greylisting.UseGreylisting, greylisting.GreylistPeriod, 

				greylisting.Track, greylisting.GreylistAuthValidity, greylisting.GreylistUnAuthValidity,

				greylisting.useAutoWhitelist, greylisting.AutoWhitelistPeriod, greylisting.AutoWhitelistCount, 
				greylisting.AutoWhitelistPercentage,

				greylisting.useAutoBlacklist, greylisting.AutoBlacklistPeriod, greylisting.AutoBlacklistCount, 
				greylisting.AutoBlacklistPercentage,

				greylisting.Comment, 
				greylisting.Disabled,
				
				policies.Name AS PolicyName
				
			FROM 
				greylisting, policies 

			WHERE 
				greylisting.ID = ?
				AND policies.ID = greylisting.PolicyID
			');
?>
		<p class="pageheader">Update Greylisting</p>

		<form action="greylisting-change.php" method="post">
			<div>
				<input type="hidden" name="frmaction" value="change2" />
				<input type="hidden" name="greylisting_id" value="<?php echo $_POST['greylisting_id']; ?>" />
			</div>
<?php

			$res = $stmt->execute(array($_POST['greylisting_id']));
			
			$row = $stmt->fetchObject();
			$stmt->closeCursor();
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
					<td><input type="text" name="greylisting_name" /></td>
				</tr>
				<tr>
					<td class="entrytitle">Link to policy</td>
					<td class="oldval"><?php echo $row->policyname ?></td>
					<td>
						<select name="greylisting_policyid">
							<option value="">--</option>
<?php
							$res = $db->query("SELECT ID, Name FROM policies ORDER BY Name");
							while ($row2 = $res->fetchObject()) {
?>
								<option value="<?php echo $row2->id ?>" ><?php echo $row2->name ?></option>
<?php
							}
							$res->closeCursor();
?>
						</select>
					</td>
				</tr>
				<tr>
					<td colspan="3" class="textcenter" style="border-bottom: 1px dashed black;">Greylisting</td>
				</tr>
				<tr>
					<td class="entrytitle">Use Greylisting</td>
					<td class="oldval"><?php 
							switch ($row->usegreylisting) {
								case null:
									echo "Inherit";
									break;
								case 0:
									echo "No";
									break;
								case 1:
									echo "Yes";
									break;
								default:
									echo "UNKNOWN";
									break;
							}
					?></td>
					<td>
						<select name="greylisting_usegreylisting">
							<option value="">--</option>
							<option value="1">Inherit</option>
							<option value="2">Yes</option>
							<option value="3">No</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						Greylist Period
						<?php tooltip('greylisting_period'); ?>
					</td>
					<td class="oldval"><?php echo is_null($row->greylistperiod) ? '*inherited*' : $row->greylistperiod ?></td>
					<td>
						<input type="text" name="greylisting_period" />
						<select name="greylisting_period_m">
							<option value="">--</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						Track
						<?php tooltip('greylisting_track'); ?>
					</td>
					<td class="oldval"><?php echo $row->track ?></td>
					<td>
						<select id="greylisting_track" name="greylisting_track"
								onChange="
									var myobj = document.getElementById('greylisting_track');
									var myobj2 = document.getElementById('greylisting_trackextra');

									if (myobj.selectedIndex == 1) {
										myobj2.disabled = false;
										myobj2.value = '/32';
									} else if (myobj.selectedIndex != 1) {
										myobj2.disabled = true;
										myobj2.value = 'n/a';
									}
							">
							<option value="">--</option>
							<option value="SenderIP">Sender IP</option>
						</select>
						<input type="text" id="greylisting_trackextra" name="greylisting_trackextra" size="18" value="n/a" disabled="disabled" />
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						Greylist Auth Validity
						<?php tooltip('greylisting_auth_validity'); ?>
					</td>
					<td class="oldval"><?php echo is_null($row->greylistauthvalidity) ? '*inherited*' : $row->greylistauthvalidity ?></td>
					<td>
						<input type="text" name="greylisting_authvalidity" />
						<select name="greylisting_authvalidity_m">
							<option value="">--</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						Greylist UnAuth Validity
						<?php tooltip('greylisting_unauth_validity'); ?>
					</td>
					<td class="oldval"><?php echo is_null($row->greylistunauthvalidity) ? '*inherited*' : $row->greylistunauthvalidity ?></td>
					<td>
						<input type="text" name="greylisting_unauthvalidity" />
						<select name="greylisting_unauthvalidity_m">
							<option value="">--</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td colspan="3" class="textcenter" style="border-bottom: 1px dashed black;">Auto-Whitelisting</td>
				</tr>
				<tr>
					<td class="entrytitle">Use AWL</td>
					<td class="oldval"><?php 
							switch ($row->useautowhitelist) {
								case null:
									echo "Inherit";
									break;
								case 0:
									echo "No";
									break;
								case 1:
									echo "Yes";
									break;
								default:
									echo "UNKNOWN";
									break;
							}
					?></td>
					<td>
						<select name="greylisting_useawl">
							<option value="">--</option>
							<option value="1">Inherit</option>
							<option value="2">Yes</option>
							<option value="3">No</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						AWL Period
						<?php tooltip('greylisting_awl_period'); ?>
					</td>
					<td class="oldval"><?php echo is_null($row->autowhitelistperiod) ? '*inherited*' : $row->autowhitelistperiod ?></td>
					<td>
						<input type="text" name="greylisting_awlperiod" />
						<select name="greylisting_awlperiod_m">
							<option value="">--</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						AWL After Count
						<?php tooltip('greylisting_awl_count'); ?>
					</td>
					<td class="oldval"><?php echo is_null($row->autowhitelistcount) ? '*inherited*' : $row->autowhitelistcount ?></td>
					<td>
						<input type="text" name="greylisting_awlcount" />
						<select name="greylisting_awlcount_m">
							<option value="">--</option>
							<option value="0">Disable</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						AWL After Percentage
						<?php tooltip('greylisting_awl_percentage'); ?>
					</td>
					<td class="oldval">
							<?php echo is_null($row->autowhitelistpercentage) ? '*inherited*' : $row->autowhitelistpercentage ?>
					</td>
					<td>
						<input type="text" name="greylisting_awlpercentage" />
						<select name="greylisting_awlpercentage_m">
							<option value="">--</option>
							<option value="0">Disable</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td colspan="3" class="textcenter" style="border-bottom: 1px dashed black;">Auto-Blacklisting</td>
				</tr>
				<tr>
					<td class="entrytitle">Use ABL</td>
					<td class="oldval"><?php 
							switch ($row->useautoblacklist) {
								case null:
									echo "Inherit";
									break;
								case 0:
									echo "No";
									break;
								case 1:
									echo "Yes";
									break;
								default:
									echo "UNKNOWN";
									break;
							}
					?></td>
					<td>
						<select name="greylisting_useabl">
							<option value="">--</option>
							<option value="1">Inherit</option>
							<option value="2">Yes</option>
							<option value="3">No</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						ABL Period
						<?php tooltip('greylisting_abl_period'); ?>
					</td>
					<td class="oldval"><?php echo is_null($row->autoblacklistperiod) ? '*inherited*' : $row->autoblacklistperiod ?></td>
					<td>
						<input type="text" name="greylisting_ablperiod" />
						<select name="greylisting_ablperiod_m">
							<option value="">--</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						ABL After Count
						<?php tooltip('greylisting_abl_count'); ?>
					</td>
					<td class="oldval"><?php echo is_null($row->autoblacklistcount) ? '*inherited*' : $row->autoblacklistcount ?></td>
					<td>
						<input type="text" name="greylisting_ablcount" />
						<select name="greylisting_ablcount_m">
							<option value="">--</option>
							<option value="0">Disable</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td class="entrytitle">
						ABL After Percentage
						<?php tooltip('greylisting_abl_percentage'); ?>
					</td>
					<td class="oldval">
							<?php echo is_null($row->autoblacklistpercentage) ? '*inherited*' : $row->autoblacklistpercentage ?>
					</td>
					<td>
						<input type="text" name="greylisting_ablpercentage" />
						<select name="greylisting_ablpercentage_m">
							<option value="">--</option>
							<option value="0">Disable</option>
							<option value="1">Inherit</option>
							<option value="2">Overwrite</option>
						</select>
					</td>
				</tr>
				<tr>
					<td colspan="3" class="textcenter" style="border-bottom: 1px dashed black;">&nbsp;</td>
				</tr>
				<tr>
					<td class="entrytitle texttop">Comment</td>
					<td class="oldval texttop"><?php echo $row->comment ?></td>
					<td><textarea name="greylisting_comment" cols="40" rows="5"></textarea></td>
				</tr>
				<tr>
					<td class="entrytitle">Disabled</td>
					<td class="oldval"><?php echo $row->disabled ? 'yes' : 'no' ?></td>
					<td>
						<select name="greylisting_disabled">
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
		<div class="warning">No Greylisting check selected</div>
<?php
	}
	
	
	
# SQL Updates
} elseif ($_POST['frmaction'] == "change2") {
?>
	<p class="pageheader">Greylisting Update Results</p>
<?php
	$updates = array();

	# Process all our options below
	if (!empty($_POST['greylisting_policyid'])) {
		array_push($updates,"PolicyID = ".$db->quote($_POST['greylisting_policyid']));
	}

	if (!empty($_POST['greylisting_name'])) {
		array_push($updates,"Name = ".$db->quote($_POST['greylisting_name']));
	}

	if (!empty($_POST['greylisting_usegreylisting'])) {
		if ($_POST['greylisting_usegreylisting'] == "1") {
			$usegreylisting = null;
		} elseif ($_POST['greylisting_usegreylisting'] == "2") {
			$usegreylisting = 1;
		} elseif ($_POST['greylisting_usegreylisting'] == "3") {
			$usegreylisting = 0;
		}
		array_push($updates,"UseGreylisting = ".$db->quote($usegreylisting));
	}

	if (!empty($_POST['greylisting_period_m'])) {
		if ($_POST['greylisting_period_m'] == "1") {
			$period = null;
		} elseif ($_POST['greylisting_period_m'] == "2") {
			$period = $_POST['greylisting_period'];
		}
		array_push($updates,"GreylistPeriod = ".$db->quote($period));
	}
	
	if (!empty($_POST['greylisting_track'])) {
		if ($_POST['greylisting_track'] == "SenderIP") {
			$track = sprintf('%s:%s',$_POST['greylisting_track'],$_POST['greylisting_trackextra']);
		} else {
			$track = $_POST['greylisting_track'];
		}

		array_push($updates,"Track = ".$db->quote($track));
	}
	
	if (!empty($_POST['greylisting_authvalidity_m'])) {
		if ($_POST['greylisting_authvalidity_m'] == "1") {
			$validity = null;
		} elseif ($_POST['greylisting_authvalidity_m'] == "2") {
			$validity = $_POST['greylisting_authvalidity'];
		}
		array_push($updates,"GreylistAuthValidity = ".$db->quote($validity));
	}
	if (!empty($_POST['greylisting_noauthvalidity_m'])) {
		if ($_POST['greylisting_noauthvalidity_m'] == "1") {
			$validity = null;
		} elseif ($_POST['greylisting_noauthvalidity_m'] == "2") {
			$validity = $_POST['greylisting_noauthvalidity'];
		}
		array_push($updates,"GreylistNoAuthValidity = ".$db->quote($validity));
	}

	# Autowhitelist	
	if (!empty($_POST['greylisting_useawl'])) {
		if ($_POST['greylisting_useawl'] == "1") {
			$useawl = null;
		} elseif ($_POST['greylisting_useawl'] == "2") {
			$useawl = 1;
		} elseif ($_POST['greylisting_useawl'] == "3") {
			$useawl = 0;
		}
		array_push($updates,"UseAutoWhitelist = ".$db->quote($useawl));
	}

	if (!empty($_POST['greylisting_awlperiod_m'])) {
		if ($_POST['greylisting_awlperiod_m'] == "1") {
			$awlperiod = null;
		} elseif ($_POST['greylisting_awlperiod_m'] == "2") {
			$awlperiod = $_POST['greylisting_awlperiod'];
		}
		array_push($updates,"AutoWhitelistPeriod = ".$db->quote($awlperiod));
	}

	# AWL Count
	if (!empty($_POST['greylisting_awlcount_m'])) {
		if ($_POST['greylisting_awlcount_m'] == "1") {
			$awlcount = null;
		} elseif ($_POST['greylisting_awlcount_m'] == "2") {
			$awlcount = $_POST['greylisting_awlcount'];
		}
		array_push($updates,"AutoWhitelistCount = ".$db->quote($awlcount));
	}

	# AWL Percentage
	if (!empty($_POST['greylisting_awlpercentage_m'])) {
		if ($_POST['greylisting_awlpercentage_m'] == "1") {
			$awlpercentage = null;
		} elseif ($_POST['greylisting_awlpercentage_m'] == "2") {
			$awlpercentage = $_POST['greylisting_awlpercentage'];
		}
		array_push($updates,"AutoWhitelistPercentage = ".$db->quote($awlpercentage));
	}

	# Autoblacklist
	if (!empty($_POST['greylisting_useabl'])) {
		if ($_POST['greylisting_useabl'] == "1") {
			$useabl = null;
		} elseif ($_POST['greylisting_useabl'] == "2") {
			$useabl = 1;
		} elseif ($_POST['greylisting_useabl'] == "3") {
			$useabl = 0;
		}
		array_push($updates,"UseAutoBlacklist = ".$db->quote($useabl));
	}

	if (!empty($_POST['greylisting_ablperiod_m'])) {
		if ($_POST['greylisting_ablperiod_m'] == "1") {
			$ablperiod = null;
		} elseif ($_POST['greylisting_ablperiod_m'] == "2") {
			$ablperiod = $_POST['greylisting_ablperiod'];
		}
		array_push($updates,"AutoBlacklistPeriod = ".$db->quote($ablperiod));
	}

	# AWL Count
	if (!empty($_POST['greylisting_ablcount_m'])) {
		if ($_POST['greylisting_ablcount_m'] == "1") {
			$ablcount = null;
		} elseif ($_POST['greylisting_ablcount_m'] == "2") {
			$ablcount = $_POST['greylisting_ablcount'];
		}
		array_push($updates,"AutoBlacklistCount = ".$db->quote($ablcount));
	}

	# AWL Percentage
	if (!empty($_POST['greylisting_ablpercentage_m'])) {
		if ($_POST['greylisting_ablpercentage_m'] == "1") {
			$ablpercentage = null;
		} elseif ($_POST['greylisting_ablpercentage_m'] == "2") {
			$ablpercentage = $_POST['greylisting_ablpercentage'];
		}
		array_push($updates,"AutoBlacklistPercentage = ".$db->quote($ablpercentage));
	}

	if (!empty($_POST['greylisting_comment'])) {
		array_push($updates,"Comment = ".$db->quote($_POST['greylisting_comment']));
	}
	if (isset($_POST['greylisting_disabled']) && $_POST['greylisting_disabled'] != "") {
		array_push($updates ,"Disabled = ".$db->quote($_POST['greylisting_disabled']));
	}

	# Check if we have updates
	if (sizeof($updates) > 0) {
		$updateStr = implode(', ',$updates);

		$res = $db->exec("UPDATE greylisting SET $updateStr WHERE ID = ".$db->quote($_POST['greylisting_id']));
		if ($res) {
?>
			<div class="notice">Greylisting updated</div>
<?php
		} else {
?>
			<div class="warning">Error updating Greylisting!</div>
			<div class="warning"><?php print_r($db->errorInfo()) ?></div>
<?php
		}

	} else {
?>
		<div class="warning">No changes made to Greylisting</div>
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
