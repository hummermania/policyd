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
		<li id="listtitle">Protocols
			<ul>
				<li>Bizanga
				<li>Postfix
			</ul>
		</li>

		<li id="listtitle">Policies &amp; Policy Groups
			<ul>
				<li>Define policy groups made up of various combinations of tags.</li>
				<li>Define and manage policies comprising of ACL's which can include groups.</li>
			</ul>
		</li>

		<li>Access Control
			<ul>
				<li>Control access based on policy. eg. Rejecting mail matching a specific policy.</li>
			</ul>
		</li>

		<li>Amavis Integration
			<ul>
				<li>Anti-virus checks.</li>
				<li>Anti-spam checks.</li>
				<li>Banned filename checks.</li>
				<li>Email header checks.</li>
				<li>Message size limits.</li>
				<li>Blacklist/whitelist senders.</li>
				<li>Email interception (BCC).</li>
			</ul>
		</li>

		<li>Greylisting
			<ul>
				<li>Support for greylisting and masking sender IP addresses.</li>
				<li>Support for auto-whitelisting and auto-greylisting based on count or count+percentage.</li>
			</ul>
		</li>

		<li>HELO/EHLO Checks
			<ul>
				<li>Check sending server HELO/EHLO for validity and RFC compliance.</li>
			</ul>
		</li>

		<li>SPF Checks
			<ul>
				<li>Check the SPF records of a domain and see if the inbound email is allowed or prohibited.</li>
			</ul>
		</li>

		<li>Postfix Integration
			<ul>
				<li>Setup and create transports.</li>
				<li>Create mailboxes.</li>
				<li>Create mailbox aliases.</li>
				<li>Manage distribution groups.</li>
			</ul>
		</li>
		
		<li>Quotas
			<ul>
				<li>Define message count quotas for policies.</li>
				<li>Define cumulative size quotas for policies.</li>
				<li>Track these quotas based on various methods, including sender IP block, sender user/domain/email address.</li>
			</ul>
		</li>

	</ul>
<?php

printFooter();

# vim: ts=4
?>
