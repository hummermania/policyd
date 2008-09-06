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
use cbp::protocols;


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
	return CBP_SKIP if (!$config{'enable'});

	# We only valid in the RCPT state
	return CBP_SKIP if (!defined($sessionData->{'ProtocolState'}) || $sessionData->{'ProtocolState'} ne "RCPT");

	# Check if we have any policies matched, if not just pass
	return CBP_SKIP if (!defined($sessionData->{'Policy'}));

	# Result
	my $res;

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
				return $server->protocol_response(PROTO_DB_ERROR);
			}
			my $row = $sth->fetchrow_hashref();
			DBFreeRes($sth);

			# If no result, next
			next if (!$row);

			# Setup result
			if (!defined($row->{'verdict'})) {
				$server->maillog("module=AccessControl, action=none, host=%s, helo=%s, from=%s, to=%s, reason=no_verdict",
						$sessionData->{'ClientAddress'},
						$sessionData->{'Helo'},
						$sessionData->{'Sender'},
						$sessionData->{'Recipient'});
				next; # No verdict

			} elsif ($row->{'verdict'} =~ /^hold$/i) {
				$server->maillog("module=AccessControl, action=hold, host=%s, helo=%s, from=%s, to=%s, reason=verdict",
						$sessionData->{'ClientAddress'},
						$sessionData->{'Helo'},
						$sessionData->{'Sender'},
						$sessionData->{'Recipient'});
				return $server->protocol_response(PROTO_HOLD,$row->{'data'});

			} elsif ($row->{'verdict'} =~ /^reject$/i) {
				$server->maillog("module=AccessControl, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=verdict",
						$sessionData->{'ClientAddress'},
						$sessionData->{'Helo'},
						$sessionData->{'Sender'},
						$sessionData->{'Recipient'});
				return $server->protocol_response(PROTO_REJECT,$row->{'data'});

			} elsif ($row->{'verdict'} =~ /^discard$/i) {
				$server->maillog("module=AccessControl, action=discard, host=%s, helo=%s, from=%s, to=%s, reason=verdict",
						$sessionData->{'ClientAddress'},
						$sessionData->{'Helo'},
						$sessionData->{'Sender'},
						$sessionData->{'Recipient'});
				return $server->protocol_response(PROTO_DISCARD,$row->{'data'});

			} elsif ($row->{'verdict'} =~ /^filter$/i) {
				$server->maillog("module=AccessControl, action=filter, host=%s, helo=%s, from=%s, to=%s, reason=verdict",
						$sessionData->{'ClientAddress'},
						$sessionData->{'Helo'},
						$sessionData->{'Sender'},
						$sessionData->{'Recipient'});
				return $server->protocol_response(PROTO_FILTER,$row->{'data'});

			} elsif ($row->{'verdict'} =~ /^redirect$/i) {
				$server->maillog("module=AccessControl, action=redirect, host=%s, helo=%s, from=%s, to=%s, reason=verdict",
						$sessionData->{'ClientAddress'},
						$sessionData->{'Helo'},
						$sessionData->{'Sender'},
						$sessionData->{'Recipient'});
				return $server->protocol_response(PROTO_REDIRECT,$row->{'data'});

			} else {
				$server->log(LOG_ERR,"[ACCESSCONTROL] Unknown Verdict specification in access control '".$row->{'verdict'}."'");
				$server->maillog("module=AccessControl, action=none, host=%s, helo=%s, from=%s, to=%s, reason=invalid_verdict",
						$sessionData->{'ClientAddress'},
						$sessionData->{'Helo'},
						$sessionData->{'Sender'},
						$sessionData->{'Recipient'});
				return $server->protocol_response(PROTO_DATA_ERROR);
			}

		} # foreach my $policyID (@{$sessionData->{'Policy'}->{$priority}})

	} # foreach my $priority (sort {$a <=> $b} keys %{$sessionData->{'_policy'}})

	return CBP_CONTINUE;
}



1;
# vim: ts=4
