# Helo checking module
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


package cbp::modules::CheckHelo;

use strict;
use warnings;


use cbp::logging;
use cbp::dblayer;
use cbp::protocols;
use cbp::system;

use Net::DNS::Resolver;


# User plugin info
our $pluginInfo = {
	name 			=> "HELO/EHLO Check Plugin",
	priority		=> 80,
	init		 	=> \&init,
	request_process	=> \&check,
	cleanup			=> \&cleanup,
};


# Our config
my %config;


# Create a child specific context
sub init {
	my $server = shift;
	my $inifile = $server->{'inifile'};

	# Defaults
	$config{'enable'} = 0;

	# Parse in config
	if (defined($inifile->{'checkhelo'})) {
		foreach my $key (keys %{$inifile->{'checkhelo'}}) {
			$config{$key} = $inifile->{'checkhelo'}->{$key};
		}
	}

	# Check if enabled
	if ($config{'enable'} =~ /^\s*(y|yes|1|on)\s*$/i) {
		$server->log(LOG_NOTICE,"  => CheckHelo: enabled");
		$config{'enable'} = 1;
	}
}


# Do our check
sub check {
	my ($server,$sessionData) = @_;

	# If we not enabled, don't do anything
	return CBP_SKIP if (!$config{'enable'});

	# We only valid in the RCPT state
	return CBP_SKIP if (!defined($sessionData->{'ProtocolState'}) || $sessionData->{'ProtocolState'} ne "RCPT");
	
	# We need a HELO...
	return CBP_SKIP if (!defined($sessionData->{'Helo'}) || $sessionData->{'Helo'} eq "");
	
	# Check if we have any policies matched, if not just pass
	return CBP_SKIP if (!defined($sessionData->{'Policy'}));

	# Policy we're about to build
	my %policy;

	# Loop with priorities, low to high
	foreach my $priority (sort {$a <=> $b} keys %{$sessionData->{'Policy'}}) {

		# Loop with policies
		foreach my $policyID (@{$sessionData->{'Policy'}->{$priority}}) {

			my $sth = DBSelect("
				SELECT
					UseBlacklist, BlacklistPeriod,

					UseHRP, HRPPeriod, HRPLimit,

					RejectInvalid, RejectIP, RejectUnresolvable

				FROM
					checkhelo

				WHERE
					PolicyID = ".DBQuote($policyID)."
					AND Disabled = 0
			");
			if (!$sth) {
				$server->log(LOG_ERR,"[CHECKHELO] Database query failed: ".cbp::dblayer::Error());
				return $server->protocol_response(PROTO_DB_ERROR);
			}
			while (my $row = $sth->fetchrow_hashref()) {
				# If defined, its to override
				if (defined($row->{'useblacklist'})) {
					$policy{'UseBlacklist'} = $row->{'useblacklist'};
				}
				if (defined($row->{'blacklistperiod'})) {
					$policy{'BlacklistPeriod'} = $row->{'blacklistperiod'};
				}
	
				if (defined($row->{'usehrp'})) {
					$policy{'UseHRP'} = $row->{'usehrp'};
				}
				if (defined($row->{'hrpperiod'})) {
					$policy{'HRPPeriod'} = $row->{'hrpperiod'};
				}
				if (defined($row->{'hrplimit'})) {
					$policy{'HRPLimit'} = $row->{'hrplimit'};
				}
	
				if (defined($row->{'rejectinvalid'})) {
					$policy{'RejectInvalid'} = $row->{'rejectinvalid'};
				}
				if (defined($row->{'rejectip'})) {
					$policy{'RejectIP'} = $row->{'rejectip'};
				}
				if (defined($row->{'rejectunresolvable'})) {
					$policy{'RejectUnresolvable'} = $row->{'rejectunresolvable'};
				}
			} # while (my $row = $sth->fetchrow_hashref())
		} # foreach my $policyID (@{$sessionData->{'Policy'}->{$priority}})
	} # foreach my $priority (sort {$a <=> $b} keys %{$sessionData->{'Policy'}})

	# Check if we have a policy
	if (!%policy) {
		return CBP_CONTINUE;
	}

	# Insert/update HELO in database
	my $sth = DBDo("
		UPDATE
			checkhelo_tracking
		SET
			LastUpdate = ".DBQuote($sessionData->{'Timestamp'})."
		WHERE
			Address = ".DBQuote($sessionData->{'ClientAddress'})."
			AND Helo = ".DBQuote($sessionData->{'Helo'})."
	");
	if (!$sth) {
		$server->log(LOG_ERR,"[CHECKHELO] Database update failed: ".cbp::dblayer::Error());
		return $server->protocol_response(PROTO_DB_ERROR);
	}
	# If we didn't update anything, insert
	if ($sth eq "0E0") {
		$sth = DBDo("
			INSERT INTO checkhelo_tracking
				(Address,Helo,LastUpdate)
			Values
				(
					".DBQuote($sessionData->{'ClientAddress'}).",
					".DBQuote($sessionData->{'Helo'}).",
					".DBQuote($sessionData->{'Timestamp'})."
				)
		");
		if (!$sth) {
			use Data::Dumper;
			$server->log(LOG_ERR,"[CHECKHELO] Database query failed: ".cbp::dblayer::Error().", data: ".Dumper($sessionData));
			return $server->protocol_response(PROTO_DB_ERROR);
		}
		$server->log(LOG_DEBUG,"[CHECKHELO] Recorded helo '".$sessionData->{'Helo'}."' from address '".$sessionData->{'ClientAddress'}."'");
	# And just a bit of debug
	} else {
		$server->log(LOG_DEBUG,"[CHECKHELO] Updated timestamp for helo '".$sessionData->{'Helo'}."' from address '".
				$sessionData->{'ClientAddress'}."'");
	}

	# Check if we whitelisted or not...
	$sth = DBSelect("
		SELECT
			Source

		FROM
			checkhelo_whitelist

		WHERE
			Disabled = 0
	");
	if (!$sth) {
		$server->log(LOG_ERR,"[CHECKHELO] Database query failed: ".cbp::dblayer::Error());
		return $server->protocol_response(PROTO_DB_ERROR);
	}
	# Loop with whitelist and calculate
	while (my $row = $sth->fetchrow_hashref()) {
		# Check format is SenderIP
		if ((my $address = $row->{'source'}) =~ s/^SenderIP://i) {

			# Parse CIDR into its various peices
			my $parsedIP = parseCIDR($address);
			# Check if this is a valid cidr or IP
			if (ref $parsedIP eq "HASH") {
				# Check if IP is whitelisted
				if ($sessionData->{'ParsedClientAddress'}->{'IP_Long'} >= $parsedIP->{'Network_Long'} && 
							$sessionData->{'ParsedClientAddress'}->{'IP_Long'} <= $parsedIP->{'Broadcast_Long'}) {
					$server->maillog("module=CheckHelo, action=pass, host=%s, helo=%s, from=%s, to=%s, reason=whitelisted",
							$sessionData->{'ClientAddress'},
							$sessionData->{'Helo'},
							$sessionData->{'Sender'},
							$sessionData->{'Recipient'});
					DBFreeRes($sth);
					return $server->protocol_response(PROTO_PASS);
				}
			} else {
				$server->log(LOG_ERR,"[CHECKHELO] Failed to parse address '$address' is invalid.");
				DBFreeRes($sth);
				return $server->protocol_response(PROTO_DATA_ERROR);
			}

		} else {
			$server->log(LOG_ERR,"[CHECKHELO] Whitelist entry '".$row->{'source'}."' is invalid.");
			DBFreeRes($sth);
			return $server->protocol_response(PROTO_DATA_ERROR);
		}
	}

	# Check if we need to reject invalid HELO's
	if (defined($policy{'RejectInvalid'}) && $policy{'RejectInvalid'} eq "1") {

		# Check if helo is an IP address
		if ($sessionData->{'Helo'} =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {

			# Check if we must reject IP address HELO's
			if (defined($policy{'RejectIP'}) && $policy{'RejectIP'} eq "1") {

				$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=ip_not_allowed",
						$sessionData->{'ClientAddress'},
						$sessionData->{'Helo'},
						$sessionData->{'Sender'},
						$sessionData->{'Recipient'});

				return $server->protocol_response(PROTO_REJECT,
						"Invalid HELO/EHLO; Must be a FQDN or an address literal, not '".$sessionData->{'Helo'}."'");
			}

		# Address literal is valid
		} elsif  ($sessionData->{'Helo'} =~ /^\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]$/) {

		# Check if helo is a FQDN - Only valid characters in a domain is alnum and a -
		} elsif ($sessionData->{'Helo'} =~ /^[\w-]+(\.[\w-]+)+$/) {

			# Check if we must reject unresolvable HELO's
			if (defined($policy{'RejectUnresolvable'}) && $policy{'RejectUnresolvable'} eq "1") {
				my $res = Net::DNS::Resolver->new;
				my $query = $res->search($sessionData->{'Helo'});

				# If the query failed
				if ($query) {

					# Look for MX or A records
					my $found = 0;
					foreach my $rr ($query->answer) {
						next unless ($rr->type eq "A" || $rr->type eq "MX");
						$found = 1;
					}

					# Check if we found any valid DNS records
					if (!$found) {

						$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=resolve_notfound",
								$sessionData->{'ClientAddress'},
								$sessionData->{'Helo'},
								$sessionData->{'Sender'},
								$sessionData->{'Recipient'});

						return $server->protocol_response(PROTO_REJECT,
							"Invalid HELO/EHLO; No A or MX records found for '".$sessionData->{'Helo'}."'");
					}

				} else {

					# Check for error
					if ($res->errorstring eq "NXDOMAIN") {

						$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=resolve_nxdomain",
								$sessionData->{'ClientAddress'},
								$sessionData->{'Helo'},
								$sessionData->{'Sender'},
								$sessionData->{'Recipient'});

						return $server->protocol_response(PROTO_REJECT,
							"Invalid HELO/EHLO; Cannot resolve '".$sessionData->{'Helo'}."', no such domain");

					} elsif ($res->errorstring eq "NOERROR") {

						$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=resolve_noerror",
								$sessionData->{'ClientAddress'},
								$sessionData->{'Helo'},
								$sessionData->{'Sender'},
								$sessionData->{'Recipient'});

						return $server->protocol_response(PROTO_REJECT,
							"Invalid HELO/EHLO; Cannot resolve '".$sessionData->{'Helo'}."', no records found");

					} elsif ($res->errorstring eq "SERVFAIL") {

						$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=resolve_servfail",
								$sessionData->{'ClientAddress'},
								$sessionData->{'Helo'},
								$sessionData->{'Sender'},
								$sessionData->{'Recipient'});

						return $server->protocol_response(PROTO_REJECT,
							"Invalid HELO/EHLO; Failure while trying to resolve '".$sessionData->{'Helo'}."'");

					} else {
						$server->log(LOG_ERR,"[CHECKHELO] Unknown error resolving '".$sessionData->{'Helo'}."': ".$res->errorstring);
						return $server->protocol_response(PROTO_ERROR);
					}
				} # if ($query)
			} # if (defined($policy{'RejectUnresolvable'}) && $policy{'RejectUnresolvable'} eq "1") {

		# Reject blatent RFC violation
		} else { # elsif ($sessionData->{'Helo'} =~ /^[\w-]+(\.[\w-]+)+$/)
			return $server->protocol_response(PROTO_REJECT,
					"Invalid HELO/EHLO; Must be a FQDN or an address literal, not '".$sessionData->{'Helo'}."'");
		}
	} # if (defined($policy{'RejectInvalid'}) && $policy{'RejectInvalid'} eq "1")

	# Check if we must use the blacklist or not
	if (defined($policy{'UseBlacklist'}) && $policy{'UseBlacklist'} eq "1") {
		my $start = 0;

		# Check period for blacklisting
		if (defined($policy{'BlacklistPeriod'})) {
			if ($policy{'BlacklistPeriod'} > 0) {
				$start = $policy{'BlacklistPeriod'};
			}
		}
		# Select and compare the number of tracking HELO's in the past time with the blacklisted ones
		$sth = DBSelect("
			SELECT
				Count(*) AS Count

			FROM
				checkhelo_tracking, checkhelo_blacklist

			WHERE
				checkhelo_tracking.LastUpdate >= ".DBQuote($start)."
				AND checkhelo_tracking.Address = ".DBQuote($sessionData->{'ClientAddress'})."
				AND checkhelo_tracking.Helo = checkhelo_blacklist.Helo
				AND checkhelo_blacklist.Disabled = 0
		");
		if (!$sth) {
			$server->log(LOG_ERR,"Database query failed: ".cbp::dblayer::Error());
			return $server->protocol_response(PROTO_DB_ERROR);
		}
		my $row = $sth->fetchrow_hashref();

		# If count > 0 , then its blacklisted
		if ($row->{'count'} > 0) {
			$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=blacklisted",
					$sessionData->{'ClientAddress'},
					$sessionData->{'Helo'},
					$sessionData->{'Sender'},
					$sessionData->{'Recipient'});

			return $server->protocol_response(PROTO_REJECT,"REJECT","Invalid HELO/EHLO; Blacklisted");
		}
	}

	# Check if we must use HRP
	if (defined($policy{'UseHRP'}) && $policy{'UseHRP'} eq "1") {

		# Check if HRPPeriod is defined
		if (defined($policy{'HRPPeriod'})) {

			# Check if HRPPeriod is valid
			if ($policy{'HRPPeriod'} > 0) {

				# Check HRPLimit is defined
				if (defined($policy{'HRPLimit'})) {

					# check HRPLimit is valid
					if ($policy{'HRPLimit'} > 0) {
						my $start = 0;

						# Check period for blacklisting
						if (defined($policy{'HRPPeriod'})) {
							if ($policy{'HRPPeriod'} > 0) {
								$start = $policy{'HRPPeriod'};
							}
						}

						my $sth = DBSelect("
							SELECT
								Count(*) AS Count

							FROM
								checkhelo_tracking

							WHERE
								Address = ".DBQuote($sessionData->{'ClientAddress'})."
								AND LastUpdate >= ".DBQuote($start)."
						");
						if (!$sth) {
							$server->log(LOG_ERR,"Database query failed: ".cbp::dblayer::Error());
							return $server->protocol_response(PROTO_DB_ERROR);
						}
						my $row = $sth->fetchrow_hashref();


						# If count > $limit , reject
						if ($row->{'count'} > $policy{'HRPLimit'}) {
							$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=hrp_blacklisted",
									$sessionData->{'ClientAddress'},
									$sessionData->{'Helo'},
									$sessionData->{'Sender'},
									$sessionData->{'Recipient'});

							return $server->protocol_response(PROTO_REJECT,"Invalid HELO/EHLO; HRP limit exceeded");
						}

					} else {
						$server->log(LOG_ERR,"[CHECKHELO] Resolved policy UseHRP is set, HRPPeriod is set but HRPPeriod is invalid");
						return $server->protocol_response(PROTO_DATA_ERROR);
					}


				} else {
					$server->log(LOG_ERR,"[CHECKHELO] Resolved policy UseHRP is set, HRPPeriod is set but HRPLimit is not defined");
					return $server->protocol_response(PROTO_DATA_ERROR);
				}


			} else {
				$server->log(LOG_ERR,"[CHECKHELO] Resolved policy UseHRP is set, but HRPPeriod is invalid");
				return $server->protocol_response(PROTO_DATA_ERROR);
			}


		} else {
			$server->log(LOG_ERR,"[CHECKHELO] Resolved policy UseHRP is set, but HRPPeriod is not defined");
			return $server->protocol_response(PROTO_DATA_ERROR);
		}

	}

	return CBP_CONTINUE;
}


# Cleanup function
sub cleanup
{
	my ($server) = @_;

	# Get now
	my $now = time();

	#
	# Tracking table cleanup
	#
	
	# Get maximum periods
	my $sth = DBSelect("
		SELECT 
			MAX(BlacklistPeriod) AS BlacklistPeriod, MAX(HRPPeriod) AS HRPPeriod
		FROM 
			checkhelo
	");
	if (!$sth) {
		$server->log(LOG_ERR,"[CHECKHELO] Failed to query maximum periods: ".cbp::dblayer::Error());
		return -1;
	}
	my $row = $sth->fetchrow_hashref();

	# Check we have results
	return if (!defined($row->{'blacklistperiod'}) || !defined($row->{'hrpperiod'}));

	# Work out which one is largest
	my $period = $row->{'blacklistperiod'} > $row->{'hrpperiod'} ? $row->{'blacklistperiod'} : $row->{'hrpperiod'};

	# Bork if we didn't find anything of interest
	return if (!($period > 0));

	# Get start time
	$period = $now - $period;

	# Remove old tracking entries from database
	$sth = DBDo("
		DELETE FROM 
			checkhelo_tracking
		WHERE
			LastUpdate < ".DBQuote($period)."
	");
	if (!$sth) {
		$server->log(LOG_ERR,"[CHECKHELO] Failed to remove old helo records: ".cbp::dblayer::Error());
		return -1;
	}

	$server->log(LOG_INFO,"[CHECKHELO] Removed ".( $sth ne "0E0" ? $sth : 0)." records from tracking table");
}





1;
# vim: ts=4
