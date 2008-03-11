<?php

include_once("includes/config.php");



# Print out HTML header
function printHeader($params = NULL)
{
	global $DB_POSTFIX_DSN;


    # Pull in params
    if (!is_null($params)) {
		if (isset($params['Tabs'])) {
			$tabs = $params['Tabs'];
		}
		if (isset($params['js.onLoad'])) {
			$jsOnLoad = $params['js.onLoad'];
		}
		if (isset($params['Title'])) {
			$title = $params['Title'];
		}
    }
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">

    <head>
	<title>Policyd Web Administration</title>
	<link rel="stylesheet" type="text/css" href="stylesheet.css" />
    </head>

    <body<?php if (!empty($jsOnLoad)) { echo " onLoad=\"".$jsOnLoad."\""; } ?>>


	<table id="maintable">
		<tr>
			<td id="header">Policyd Web Administration</td>
		</tr>

		<tr>
			<td>
				<table>
					<tr>
						<td id="menu">
	    					<img style="margin-top:-1px; margin-left:-1px;" src="images/top2.jpg" alt="" />
	    					<p><a href=".">Home</a></p>

							<p>Policies</p>
							<ul>
								<li><a href="policy-main.php">Main</a></li>
								<li><a href="policy-group-main.php">Groups</a></li>
							</ul>

							<p>Access Control</p>
							<ul>
				   				<li><a href="accesscontrol-main.php">Configure</a></li>
							</ul>
					
							<p>HELO/EHLO Checks</p>
							<ul>
		    					<li><a href="checkhelo-main.php">Configure</a></li>
		    					<li><a href="checkhelo-blacklist-main.php">Blacklist</a></li>
		    					<li><a href="checkhelo-whitelist-main.php">Whitelist</a></li>
							</ul>
					
							<p>SPF Checks</p>
							<ul>
		    					<li><a href="checkspf-main.php">Configure</a></li>
							</ul>
					
							<p>Greylisting</p>
							<ul>
		    					<li><a href="greylisting-main.php">Configure</a></li>
		    					<li><a href="greylisting-whitelist-main.php">Whitelist</a></li>
							</ul>
					
							<p>Quotas</p>
							<ul>
		    					<li><a href="quotas-main.php">Configure</a></li>
							</ul>
					
							<p>Amavis Integration</p>
							<ul>
		    					<li><a href="amavis-main.php">Configure</a></li>
							</ul>
<?php
							# Check if postfix DSN is set
							if (isset($DB_POSTFIX_DSN) && !empty($DB_POSTFIX_DSN)) 
							{
?>
								<p>Postfix Integration</p>
								<ul>
		    						<li><a href="postfix-transports-main.php">Transports</a></li>
		    						<li><a href="postfix-mailboxes-main.php">Mailboxes</a></li>
		    						<li><a href="postfix-aliases-main.php">Aliases</a></li>
		    						<li><a href="postfix-distgroups-main.php">Distribution Groups</a></li>
								</ul>
<?php
							}
?>					
	    					<img style="margin-left:-1px; margin-bottom: -6px" src="images/specs_bottom.jpg" alt="" />
						</td>

						<td class="content">
							<table class="content">
<?php
								# Check if we must display tabs or not
								if (!empty($tabs)) {
?>
									<tr><td id="topmenu"><ul>
<?php
										foreach ($tabs as $key => $value) {
?>											<li>
												<a href="<?php echo $value ?>" 
													title="<?php echo $key ?>">
												<span><?php echo $key ?></span></a>
											</li>
<?php
										}
?>
								    	</ul></td></tr>
<?php
								}	
?>
								<tr>
									<td>
<?php
}


# vim: ts=4
?>
