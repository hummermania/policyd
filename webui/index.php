<?php
# Main index file
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


printHeader();

?>
	<p class="pageheader">Features Supported</p>
	<ul>
		<li id="listtitle">Policies &amp; Policy Groups
			<ul>
				<li>Define policy groups made up of various combinations of tags.
				<li>Define and manage policies comprising of ACL's which can include groups.
			</ul>

		<li>Access Control
			<ul>
				<li>Control access based on policy. eg. Rejecting mail matching a specific policy.
			</ul>

		<li>Amavis Integration
			<ul>
				<li>Anti-virus checks.
				<li>Anti-spam checks.
				<li>Banned filename checks.
				<li>Email header checks.
				<li>Message size limits.
				<li>Blacklist/whitelist senders.
				<li>Email interception (BCC).
			</ul>

		<li>Greylisting
			<ul>
				<li>Support for greylisting and masking sender IP addresses.
				<li>Support for auto-whitelisting and auto-greylisting based on count or count+percentage.
			</ul>

		<li>HELO/EHLO Checks
			<ul>
				<li>Check sending server HELO/EHLO for validity and RFC compliance.
			</ul>

		<li>SPF Checks
			<ul>
				<li>Check the SPF records of a domain and see if the inbound email is allowed or prohibited.
			</ul>

		<li>Postfix Integration
			<ul>
				<li>Setup and create transports.
				<li>Create mailboxes.
				<li>Create mailbox aliases.
				<li>Manage distribution groups.
			</ul>
		
		<li>Quotas
			<ul>
				<li>Define message count quotas for policies.
				<li>Define cumulative size quotas for policies.
				<li>Track these quotas based on various methods, including sender IP block, sender user/domain/email address.
			</ul>

	</ul>
<?php

printFooter();

# vim: ts=4
?>
