<?php


# Print out HTML header
function printHeader($params = NULL)
{

    # Pull in params
    if (!is_null($params)) {
		if (isset($params['Tabs'])) {
			$tabs = $params['Tabs'];
		}
		if (isset($params['js.onLoad'])) {
			$jsOnLoad = $params['js.onLoad'];
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

							<p>Policies
								<ul>
									<li><a href="policy-main.php">Main</a></li>
									<li><a href="policy-group-main.php">Groups</a></li>
								</ul>
							</p>

							<p>Access Control
								<ul>
				    					<li><a href="acl-main.php">Configure</a></li>
								</ul>
							</p>
					
							<p>Quotas
								<ul>
		    							<li><a href="quotas-main.php">Configure</a></li>
								</ul>
							</p>
					
							<p>Postfix Integration
								<ul>
				    					<li><a href="postfix-main.php">Configure</a></li>
		    							<li><a href="postfix-vda.php">Mailbox Quotas</a></li>
								</ul>
							</p>
					
							<p>Amavis Integration
								<ul>
		    							<li><a href="amavis-main.php">Configure</a></li>
								</ul>
							</p>
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
