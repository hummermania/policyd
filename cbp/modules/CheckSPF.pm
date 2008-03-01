# SPF checking module
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


package cbp::modules::CheckSPF;

use strict;
use warnings;


use cbp::logging;
use cbp::dblayer;

use Mail::SPF;


# User plugin info
our $pluginInfo = {
	name 			=> "SPF Check Plugin",
	check 			=> \&check,
	init		 	=> \&init,
};


# Our config
my %config;

# SPF server
my $spf_server;


# Create a child specific context
sub init {
	my $server = shift;
	my $inifile = $server->{'inifile'};

	# Defaults
	$config{'enable'} = 0;

	# Parse in config
	if (defined($inifile->{'checkspf'})) {
		foreach my $key (keys %{$inifile->{'checkspf'}}) {
			$config{$key} = $inifile->{'checkspf'}->{$key};
		}
	}

	# Check if enabled
	if ($config{'enable'} =~ /^\s*(y|yes|1|on)\s*$/i) {
		$server->log(LOG_NOTICE,"  => CheckSPF: enabled");
		$config{'enable'} = 1;
		$spf_server = Mail::SPF::Server->new();
	}
}


# Check the request
sub check {
	my ($server,$request) = @_;

	# If we not enabled, don't do anything
	return undef if (!$config{'enable'});

	# We only valid in the RCPT state
	return undef if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");
	
	# Policy we're about to build
	my %policy;
	
	# Loop with priorities, high to low
	foreach my $priority (sort {$b <=> $a} keys %{$request->{'_policy'}}) {

		# Loop with policies
		foreach my $policyID (@{$request->{'_policy'}->{$priority}}) {

			my $sth = DBSelect("
				SELECT
					UseSPF, RejectFailedSPF, AddSPFHeader

				FROM
					checkspf

				WHERE
					PolicyID = ".DBQuote($policyID)."
					AND Disabled = 0
			");
			if (!$sth) {
				$server->log(LOG_ERR,"[CHECKSPF] Database query failed: ".cbp::dblayer::Error());
				return undef;
			}
			while (my $row = $sth->fetchrow_hashref()) {
				# If defined, its to override
				if (defined($row->{'UseSPF'})) {
					$policy{'UseSPF'} = $row->{'UseSPF'};
				}
				# If defined, its to override
				if (defined($row->{'RejectFailedSPF'})) {
					$policy{'RejectFailedSPF'} = $row->{'RejectFailedSPF'};
				}
				# If defined, its to override
				if (defined($row->{'AddSPFHeader'})) {
					$policy{'AddSPFHeader'} = $row->{'AddSPFHeader'};
				}
			} # while (my $row = $sth->fetchrow_hashref())
		} # foreach my $policyID (@{$request->{'_policy'}->{$priority}})
	} # foreach my $priority (sort {$b <=> $a} keys %{$request->{'_policy'}})
	$server->log(LOG_DEBUG,"[CHECKSPF] SPF policy: ".Dumper($policy));

	# Check if we must use SPF
	if (defined($policy{'UseSPF'}) && $policy{'UseSPF'} eq "1") {
		# Create SPF request
		my $rqst = Mail::SPF::Request->new(
				'scope' => 'mfrom', # or 'helo', 'pra'
				'identity' => $request->{'sender'},
				'ip_address' => $request->{'client_address'},
				'helo_identity' => $request->{'helo_name'}, # optional,
		);

		# Get result
		my $result = $spf_server->process($rqst);
	
		$server->log(LOG_DEBUG,"[CHECKSPF] SPF result: ".Dumper($result->local_explanation));

		# Make reason more pretty
		(my $reason = $result->local_explanation) =~ s/:/,/;

		# Intended action is accept
		if ($result->code eq "pass") {
			$server->maillog("module=CheckSPF, action=none, host=%s, helo=%s, from=%s, to=%s, reason=pass",
					$request->{'client_address'},
					$request->{'helo_name'},
					$request->{'sender'},
					$request->{'recipient'});

		# Intended action is reject
		} elsif ($result->code eq "fail") {
			my $action = "none";

			# Check if we need to reject
			if (defined($policy{'RejectFailedSPF'}) && $policy{'RejectFailedSPF'} eq "1") {
				$action = "reject";
			} elsif (defined($policy{'AddSPFHeader'}) && $policy{'AddSPFHeader'} eq "1") {
				$action = "add_header";
			}

			$server->maillog("module=CheckSPF, action=$action, host=%s, helo=%s, from=%s, to=%s, reason=fail",
					$request->{'client_address'},
					$request->{'helo_name'},
					$request->{'sender'},
					$request->{'recipient'});

			# Check if we need to reject
			if ($action eq "reject") {
				return("REJECT","Failed SPF check: $reason");
			} elsif ($action eq "add_header") {
				return("PREPEND",$result->received_spf_header);
			}

		# Intended action is accept and mark
		} elsif ($result->code eq "softfail") {
			my $action = "none";

			# Check if we need to add a header
			if (defined($policy{'AddSPFHeader'}) && $policy{'AddSPFHeader'} eq "1") {
				$action = "add_header";
			}

			$server->maillog("module=CheckSPF, action=$action, host=%s, helo=%s, from=%s, to=%s, reason=softfail",
					$request->{'client_address'},
					$request->{'helo_name'},
					$request->{'sender'},
					$request->{'recipient'});

			# Check if we need to add a header
			if ($action eq "add_header") {
				return("PREPEND",$result->received_spf_header);
			}

		# Intended action is accept
		} elsif ($result->code eq "neutral") {
			my $action = "none";

			# Check if we need to add a header
			if (defined($policy{'AddSPFHeader'}) && $policy{'AddSPFHeader'} eq "1") {
				$action = "add_header";
			}

			$server->maillog("module=CheckSPF, action=$action, host=%s, helo=%s, from=%s, to=%s, reason=neutral",
					$request->{'client_address'},
					$request->{'helo_name'},
					$request->{'sender'},
					$request->{'recipient'});

			# Check if we need to add a header
			if ($action eq "add_header") {
				return("PREPEND",$result->received_spf_header);
			}

		# Intended action is unspecified
		} elsif ($result->code eq "permerror") {
			my $action = "none";

			# Check if we need to reject
			if (defined($policy{'RejectFailedSPF'}) && $policy{'RejectFailedSPF'} eq "1") {
				$action = "reject";
			} elsif (defined($policy{'AddSPFHeader'}) && $policy{'AddSPFHeader'} eq "1") {
				$action = "add_header";
			}

			$server->maillog("module=CheckSPF, action=$action, host=%s, helo=%s, from=%s, to=%s, reason=permerror",
					$request->{'client_address'},
					$request->{'helo_name'},
					$request->{'sender'},
					$request->{'recipient'});

			# Check if we need to reject
			if ($action eq "reject") {
				return("REJECT","Failed SPF check: $reason");
			} elsif ($action eq "add_header") {
				return("PREPEND",$result->received_spf_header);
			}

		# Intended action is either accept or reject
		} elsif ($result->code eq "temperror") {
			my $action = "none";

			# Check if we need to reject
			if (defined($policy{'RejectFailedSPF'}) && $policy{'RejectFailedSPF'} eq "1") {
				$action = "defer";
			} elsif (defined($policy{'AddSPFHeader'}) && $policy{'AddSPFHeader'} eq "1") {
				$action = "add_header";
			}

			$server->maillog("module=CheckSPF, action=$action, host=%s, helo=%s, from=%s, to=%s, reason=temperror",
					$request->{'client_address'},
					$request->{'helo_name'},
					$request->{'sender'},
					$request->{'recipient'});

			# Check if we need to defer
			if ($action eq "defer") {
				return("DEFER_IF_PERMIT","Failed SPF check: $reason");
			} elsif ($action eq "add_header") {
				return("PREPEND",$result->received_spf_header);
			}


		# Intended action is accept
		} elsif ($result->code eq "none") {
			$server->maillog("module=CheckSPF, action=add_header, host=%s, helo=%s, from=%s, to=%s, reason=none",
					$request->{'client_address'},
					$request->{'helo_name'},
					$request->{'sender'},
					$request->{'recipient'});

		}
	}

	return undef;
}


1;
# vim: ts=4
