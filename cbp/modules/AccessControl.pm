# Access control module
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


package cbp::modules::AccessControl;

use strict;
use warnings;


use cbp::logging;
use cbp::dblayer;


# User plugin info
our $pluginInfo = {
	name 			=> "Access Control Plugin",
	priority		=> 90,
	init		 	=> \&init,
	request_process	=> \&check,
};


# Module configuration
my %config;


# Create a child specific context
sub init {
	my $server = shift;
	my $inifile = $server->{'inifile'};

	# Defaults
	$config{'enable'} = 0;

	# Parse in config
	if (defined($inifile->{'accesscontrol'})) {
		foreach my $key (keys %{$inifile->{'accesscontrol'}}) {
			$config{$key} = $inifile->{'accesscontrol'}->{$key};
		}
	}

	# Check if enabled
	if ($config{'enable'} =~ /^\s*(y|yes|1|on)\s*$/i) {
		$server->log(LOG_NOTICE,"  => AccessControl: enabled");
		$config{'enable'} = 1;
	}
}


# Check the request
sub check {
	my ($server,$sessionData) = @_;
	

	# If we not enabled, don't do anything
	return undef if (!$config{'enable'});

	# We only valid in the RCPT state
	return undef if (!defined($sessionData->{'ProtocolState'}) || $sessionData->{'ProtocolState'} ne "RCPT");

	# Our verdict and data
	my ($verdict,$verdict_data);

	# Loop with priorities, low to high
	foreach my $priority (sort {$a <=> $b} keys %{$sessionData->{'Policy'}}) {

		# Loop with policies
		foreach my $policyID (@{$sessionData->{'Policy'}->{$priority}}) {

			my $sth = DBSelect("
				SELECT
					Verdict, Data
				FROM
					access_control
				WHERE
					PolicyID = ".DBQuote($policyID)."
					AND Disabled = 0
			");
			if (!$sth) {
				$server->log(LOG_ERR,"Database query failed: ".cbp::dblayer::Error());
				return undef;
			}
			my $row = $sth->fetchrow_hashref();
			DBFreeRes($sth);

			# If no result, next
			next if (!$row);

			# Setup result
			$verdict = $row->{'Verdict'};
			$verdict_data = $row->{'Data'};

		} # foreach my $policyID (@{$sessionData->{'Policy'}->{$priority}})

		# Last if we found something
		last if ($verdict);

	} # foreach my $priority (sort {$a <=> $b} keys %{$sessionData->{'_policy'}})

	return ($verdict,$verdict_data);
}



1;
# vim: ts=4
