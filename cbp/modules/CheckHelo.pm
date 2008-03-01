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
use cbp::system;

use Net::DNS::Resolver;


# User plugin info
our $pluginInfo = {
	name 			=> "HELO/EHLO Check Plugin",
	check 			=> \&check,
	init		 	=> \&init,
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
				return undef;
			}
			while (my $row = $sth->fetchrow_hashref()) {
				# If defined, its to override
				if (defined($row->{'UseBlacklist'})) {
					$policy{'UseBlacklist'} = $row->{'UseBlacklist'};
				}
				if (defined($row->{'BlacklistPeriod'})) {
					$policy{'BlacklistPeriod'} = $row->{'BlacklistPeriod'};
				}
	
				if (defined($row->{'UseHRP'})) {
					$policy{'UseHRP'} = $row->{'UseHRP'};
				}
				if (defined($row->{'HRPPeriod'})) {
					$policy{'HRPPeriod'} = $row->{'HRPPeriod'};
				}
				if (defined($row->{'HRPLimit'})) {
					$policy{'HRPLimit'} = $row->{'HRPLimit'};
				}
	
				if (defined($row->{'RejectInvalid'})) {
					$policy{'RejectInvalid'} = $row->{'RejectInvalid'};
				}
				if (defined($row->{'RejectIP'})) {
					$policy{'RejectIP'} = $row->{'RejectIP'};
				}
				if (defined($row->{'RejectUnresolvable'})) {
					$policy{'RejectUnresolvable'} = $row->{'RejectUnresolvable'};
				}
			} # while (my $row = $sth->fetchrow_hashref())
		} # foreach my $policyID (@{$request->{'_policy'}->{$priority}})
	} # foreach my $priority (sort {$b <=> $a} keys %{$request->{'_policy'}})

	# Insert/update HELO in database
	my $sth = DBDo("
		UPDATE
			checkhelo_tracking
		SET
			LastUpdate = ".DBQuote($request->{'_timestamp'})."
		WHERE
			Address = ".DBQuote($request->{'client_address'})."
			AND Helo = ".DBQuote($request->{'helo_name'})."
	");
	if (!$sth) {
		$server->log(LOG_ERR,"[CHECKHELO] Database query failed: ".cbp::dblayer::Error());
		return undef;
	}
	# If we didn't update anything, insert
	if ($sth eq "0E0") {
		$sth = DBDo("
			INSERT INTO checkhelo_tracking
				(Address,Helo,LastUpdate)
			Values
				(
					".DBQuote($request->{'client_address'}).",
					".DBQuote($request->{'helo_name'}).",
					".DBQuote($request->{'_timestamp'})."
				)
		");
		if (!$sth) {
			$server->log(LOG_ERR,"[CHECKHELO] Database query failed: ".cbp::dblayer::Error());
			return undef;
		}
		$server->log(LOG_DEBUG,"[CHECKHELO] Recorded helo '".$request->{'helo_name'}."' from address '".$request->{'client_address'}."'");
	# And just a bit of debug
	} else {
		$server->log(LOG_DEBUG,"[CHECKHELO] Updated timestamp for helo '".$request->{'helo_name'}."' from address '".$request->{'client_address'}."'");
	}

	# Are we whitelisted or not?
	my $whitelisted = 0;
	# Check if we whitelisted or not...
	$sth = DBSelect("
		SELECT
			Address

		FROM
			checkhelo_whitelist

		WHERE
			Disabled = 0
	");
	if (!$sth) {
		$server->log(LOG_ERR,"[CHECKHELO] Database query failed: ".cbp::dblayer::Error());
		return undef;
	}
	# Loop with whitelist and calculate
	while (my $row = $sth->fetchrow_hashref()) {
		# Check if this is a valid cidr or IP
		if ($row->{'Address'} =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/(\d{1,2}))?$/) {
			my $ip = $1;
			my $mask = ( defined($2) && $2 > 1 && $2 <= 32 ) ? $2 : 32;

			# Pull long for IP we going to test
			my $ip_long = ip_to_long($ip);
			# Convert mask to longs
			my $mask_long = ipbits_to_mask($mask);
			# AND with mask to get network addy
			my $network_long = $ip_long & $mask_long;
			# AND with mask to get broadcast addy
			my $bcast_long = $ip_long & ~$mask_long;
		
			# Check if IP is whitelisted
			if ($ip_long >= $network_long && $ip_long <= $bcast_long) {
				$server->maillog("module=CheckHelo, action=none, host=%s, from=%s, to=%s, reason=whitelisted",
						$request->{'client_address'},
						$request->{'helo_name'},
						$request->{'sender'},
						$request->{'recipient'});
				DBFreeRes($sth);
				return undef;
			}

		} else {
			$server->log(LOG_ERR,"[CHECKHELO] Whitelist entry '".$row->{'Address'}."' is invalid.");
			DBFreeRes($sth);
			return undef;
		}
	}

	# Check if we need to reject invalid HELO's
	if (defined($policy{'RejectInvalid'}) && $policy{'RejectInvalid'} eq "1") {

		# Check if helo is an IP address
		if ($request->{'helo_name'} =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {

			# Check if we must reject IP address HELO's
			if (defined($policy{'RejectIP'}) && $policy{'RejectIP'} eq "1") {

				$server->maillog("module=CheckHelo, action=reject, host=%s, from=%s, to=%s, reason=ip_not_allowed",
						$request->{'client_address'},
						$request->{'helo_name'},
						$request->{'sender'},
						$request->{'recipient'});

				return("REJECT","Invalid HELO/EHLO; Must be a FQDN or an address literal, not '".$request->{'helo_name'}."'");
			}

		# Address literal is valid
		} elsif  ($request->{'helo_name'} =~ /^\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]$/) {

		# Check if helo is a FQDN - Only valid characters in a domain is alnum and a -
		} elsif ($request->{'helo_name'} =~ /^[\w-]+(\.[\w-]+)+$/) {

			# Check if we must reject unresolvable HELO's
			if (defined($policy{'RejectUnresolvable'}) && $policy{'RejectUnresolvable'} eq "1") {
				my $res = Net::DNS::Resolver->new;
				my $query = $res->search($request->{'helo_name'});

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

						$server->maillog("module=CheckHelo, action=reject, host=%s, from=%s, to=%s, reason=resolve_notfound",
								$request->{'client_address'},
								$request->{'helo_name'},
								$request->{'sender'},
								$request->{'recipient'});

						return("REJECT","Invalid HELO/EHLO; No A or MX records found for '".$request->{'helo_name'}."'");
					}

				} else {

					# Check for error
					if ($res->errorstring eq "NXDOMAIN") {

						$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=resolve_nxdomain",
								$request->{'client_address'},
								$request->{'helo_name'},
								$request->{'sender'},
								$request->{'recipient'});

						return("REJECT","Invalid HELO/EHLO; Cannot resolve '".$request->{'helo_name'}."', no such domain");

					} elsif ($res->errorstring eq "NOERROR") {

						$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=resolve_noerror",
								$request->{'client_address'},
								$request->{'helo_name'},
								$request->{'sender'},
								$request->{'recipient'});

						return("REJECT","Invalid HELO/EHLO; Cannot resolve '".$request->{'helo_name'}."', no records found");

					} elsif ($res->errorstring eq "SERVFAIL") {

						$server->maillog("module=CheckHelo, action=defer_if_permit, host=%s, helo=%s, from=%s, to=%s, reason=resolve_servfail",
								$request->{'client_address'},
								$request->{'helo_name'},
								$request->{'sender'},
								$request->{'recipient'});

						return("DEFER_IF_PERMIT","Invalid HELO/EHLO; Failure while trying to resolve '".$request->{'helo_name'}."'");

					} else {
						$server->log(LOG_ERR,"[CHECKHELO] Unknown error resolving '".$request->{'helo_name'}."': ".$res->errorstring);
				 		return undef;
					}
				} # if ($query)
			} # if (defined($policy{'RejectUnresolvable'}) && $policy{'RejectUnresolvable'} eq "1") {

		# Reject blatent RFC violation
		} else { # elsif ($request->{'helo_name'} =~ /^[\w-]+(\.[\w-]+)+$/)
			return("REJECT","Invalid HELO/EHLO; Must be a FQDN or an address literal, not '".$request->{'helo_name'}."'");
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
				Count(checkhelo_tracking.ID) AS Count

			FROM
				checkhelo_tracking, checkhelo_blacklist

			WHERE
				checkhelo_tracking.LastUpdate >= ".DBQuote($start)."
				AND checkhelo_tracking.Address = ".DBQuote($request->{'client_address'})."
				AND checkhelo_tracking.Helo = checkhelo_blacklist.Helo
				AND checkhelo_blacklist.Disabled = 0
		");
		if (!$sth) {
			$server->log(LOG_ERR,"Database query failed: ".cbp::dblayer::Error());
			return undef;
		}
		my $row = $sth->fetchrow_hashref();

		# If count > 0 , then its blacklisted
		if ($row->{'Count'} > 0) {
			$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=blacklisted",
					$request->{'client_address'},
					$request->{'helo_name'},
					$request->{'sender'},
					$request->{'recipient'});

			return("REJECT","Invalid HELO/EHLO; Blacklisted");
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
								Count(ID) AS Count

							FROM
								checkhelo_tracking

							WHERE
								Address = ".DBQuote($request->{'client_address'})."
								AND LastUpdate >= ".DBQuote($start)."
						");
						if (!$sth) {
							$server->log(LOG_ERR,"Database query failed: ".cbp::dblayer::Error());
							return undef;
						}
						my $row = $sth->fetchrow_hashref();


						# If count > $limit , reject
						if ($row->{'Count'} > $policy{'HRPLimit'}) {
							$server->maillog("module=CheckHelo, action=reject, host=%s, helo=%s, from=%s, to=%s, reason=hrp_blacklisted",
									$request->{'client_address'},
									$request->{'helo_name'},
									$request->{'sender'},
									$request->{'recipient'});

							return("REJECT","Invalid HELO/EHLO; HRP limit exceeded");
						}

					} else {
						$server->log(LOG_ERR,"[CHECKHELO] Resolved policy UseHRP is set, HRPPeriod is set but HRPPeriod is invalid");
					}


				} else {
					$server->log(LOG_ERR,"[CHECKHELO] Resolved policy UseHRP is set, HRPPeriod is set but HRPLimit is not defined");
				}


			} else {
				$server->log(LOG_ERR,"[CHECKHELO] Resolved policy UseHRP is set, but HRPPeriod is invalid");
			}


		} else {
			$server->log(LOG_ERR,"[CHECKHELO] Resolved policy UseHRP is set, but HRPPeriod is not defined");
		}

	}

	return undef;
}


1;
# vim: ts=4
