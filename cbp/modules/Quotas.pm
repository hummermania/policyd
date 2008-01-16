# Quotas module
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


package cbp::modules::Quotas;

use strict;
use warnings;


use cbp::logging;
use cbp::dblayer;
use cbp::system;


# User plugin info
our $pluginInfo = {
	name 			=> "Quotas Plugin",
	check 			=> \&check,
	init		 	=> \&init,
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
	if (defined($inifile->{'quotas'})) {
		foreach my $key (keys %{$inifile->{'quotas'}}) {
			$config{$key} = $inifile->{'quotas'}->{$key};
		}
	}

	# Check if enabled
	if ($config{'enable'} =~ /^\s*(y|yes|1|on)\s*$/i) {
		$config{'enable'} = 1;
	}
}


# Destroy
sub finish {
}



# Check the request
sub check {
	my ($server,$request) = @_;
	

	# If we not enabled, don't do anything
	return undef if (!$config{'enable'});

	# We only valid in the RCPT and EOM state
	if (!defined($request->{'protocol_state'})) {
		return undef;
	}
	if ($request->{'protocol_state'} ne "RCPT" && $request->{'protocol_state'} ne "END-OF-MESSAGE") {
		return undef;
	}

	# Check if we have any policies matched, if not just pass
	if (!defined($request->{'_policy'})) {
		return undef;
	}

	# Our verdict and data
	my ($verdict,$verdict_data);

	my $now = time();


	#
	# RCPT state
	#   If we in this state we increase the RCPT counters for each key we have
	#   we only do this if we not going to reject the message. We also check if
	#   we have exceeded our size quota. The Size quota is updated in the EOM
	#   stage
	#
	if ($request->{'protocol_state'} eq "RCPT") {

		# Key tracking list, if quotaExceeded is not undef, it will contain the msg
		my %newCounters;  # Indexed by QuotaLimitsID
		my @trackingList;
		my $hasExceeded;


		# Loop with priorities, high to low
		foreach my $priority (sort {$b <=> $a} keys %{$request->{'_policy'}}) {

			# Loop with each policyID
			foreach my $policyID (@{$request->{'_policy'}->{$priority}}) {

				# Get quota object
				my $quotas = getQuotas($server,$policyID);
				# Check if we got a quota or not
				if (!defined($quotas)) {
					next;
				}
			
				# Loop with quotas
				foreach my $quota (@{$quotas}) {

					# Grab tracking keys
					my $key = getKey($server,$quota,$request);
					if (!defined($key)) {
						$server->log(LOG_WARN,"[QUOTAS] No key information found for quota ID '".$quota->{'ID'}."'");
						next;
					}
	
					# Get limits
					my $limits = getLimits($server,$quota->{'ID'});
					if (!defined($limits)) {
						$server->log(LOG_NOTICE,"[QUOTAS] No limits defined for quota ID '".$quota->{'ID'}."'");
						next;
					}
	
					# Loop with limits
					foreach my $limit (@{$limits}) {
	
						# Get quota tracking info
						my $qtrack = getTrackingInfo($server,$limit->{'ID'},$key);
	
						# Check if we have a queue tracking item
						if (defined($qtrack)) {
							my $elapsedTime = defined($qtrack->{'LastUpdate'}) ? ( $now - $qtrack->{'LastUpdate'} ) : $quota->{'Period'};
							
							# Check if elapsedTime is longer than period, or negative (time diff between servers?)
							if ($elapsedTime > $quota->{'Period'} || $elapsedTime < 0) {
								$qtrack->{'Counter'} = 0;
	
							# Calculate the % of the period we have, and multiply it with the counter ... this should give us a reasonably
							# accurate counting
							} else {
								$qtrack->{'Counter'} = ( 1 - ($elapsedTime / $quota->{'Period'}) ) * $qtrack->{'Counter'};
							}
								
							# Make sure increment is at least 0
							$newCounters{$qtrack->{'QuotasLimitsID'}} = $qtrack->{'Counter'} if (!defined($newCounters{$qtrack->{'QuotasLimitsID'}}));
		
							my $limitType = lc($limit->{'Type'});
	
							# Make sure its the MessageCount counter
							if ($limitType eq "messagecount") {
								# Check for violation
								if ($qtrack->{'Counter'} > $limit->{'CounterLimit'}) {
									$hasExceeded = "Policy rejection, message count quota exceeded";
								}
								# Bump up limit
								$newCounters{$qtrack->{'QuotasLimitsID'}}++;
	
							# Check for cumulative size violation
							} elsif ($limitType eq "messagecumulativesize") {
								# Check for violation
								if ($qtrack->{'Counter'} > $limit->{'CounterLimit'}) {
									$hasExceeded = "Policy rejection, cumulative message size quota exceeded";
								}
							}
	
						} else {
							$qtrack->{'QuotasLimitsID'} = $limit->{'ID'};
							$qtrack->{'Key'} = $key;
							$qtrack->{'Counter'} = 0;
								
							# Make sure increment is at least 0
							$newCounters{$qtrack->{'QuotasLimitsID'}} = $qtrack->{'Counter'} if (!defined($newCounters{$qtrack->{'QuotasLimitsID'}}));
							
							# Check if this is a message counter
							if (lc($limit->{'Type'}) eq "messagecount") {
								# Bump up limit
								$newCounters{$qtrack->{'QuotasLimitsID'}}++;
							}
						}
	
						# Save quota tracking info
						push(@trackingList,$qtrack);
	
					}  # foreach my $limit (@{$limits})
					next;
	
				} # foreach my $policyID (@{$request->{'_policy'}->{$priority}})

			} # foreach my $quota (@{$quotas})

		} # foreach my $priority (sort {$b <=> $a} keys %{$request->{'_policy'}})

		# If we have not exceeded, update
		if (!$hasExceeded) {

			# Loop with tracking ID's and update
			foreach my $qtrack (@trackingList) {

				# Update database
				my $sth = DBDo("
					UPDATE 
						quotas_tracking
					SET
						Counter = ".DBQuote($newCounters{$qtrack->{'QuotasLimitsID'}}).",
						LastUpdate = ".DBQuote($now)."
					WHERE
						QuotasLimitsID = ".DBQuote($qtrack->{'QuotasLimitsID'})."
						AND Key = ".DBQuote($qtrack->{'Key'})."
				");
				if (!$sth) {
					$server->log(LOG_ERR,"[QUOTAS] Failed to update quota_tracking item: ".cbp::dblayer::Error());
					next;
				}
				
				# If nothing updated, then insert our record
				if ($sth eq "0E0") {
					# Insert into database
					my $sth = DBDo("
						INSERT INTO quotas_tracking
							(QuotasLimitsID,Key,LastUpdate,Counter)
						VALUES
							(
								".DBQuote($qtrack->{'QuotasLimitsID'}).",
								".DBQuote($qtrack->{'Key'}).",
								".DBQuote($qtrack->{'LastUpdate'}).",
								".DBQuote($newCounters{$qtrack->{'QuotasLimitsID'}})."
							)
					");
					if (!$sth) {
						$server->log(LOG_ERR,"[QUOTAS] Failed to update quota_tracking item: ".cbp::dblayer::Error());
						next;
					}
				}

				# Remove limit
				delete($newCounters{$qtrack->{'QuotasLimitsID'}});
			}

		# If we have exceeded, set verdict
		} else {
			$verdict = "REJECT";
			$verdict_data = $hasExceeded;
		}

	#
	# END-OF-MESSAGE state
	#   The Size quota is updated in this state
	#
	} elsif ($request->{'protocol_state'} eq "END-OF-MESSAGE") {

		my @keys;

		my %newCounters;  # Indexed by limit ID

		# Loop with priorities, high to low
		foreach my $priority (sort {$b <=> $a} keys %{$request->{'_recipient_policy'}}) {

			# Loop with email addies
			foreach my $emailAddy (keys %{$request->{'_recipient_policy'}{$priority}}) {

				# Loop with each policyID
				foreach my $policyID (@{$request->{'_policy'}->{$priority}}) {

					# Check if we got a quota or not
					my $quotas = getQuotas($server,$policyID);
					if (!defined($quotas)) {
						next;
					}

					# Loop with quotas
					foreach my $quota (@{$quotas}) {

						# HACK: Fool getKey into thinking we actually do have a recipient
						$request->{'recipient'} = $emailAddy;
	
						# Grab tracking keys
						my $key = getKey($server,$quota,$request);
						if (!defined($key)) {
							$server->log(LOG_WARN,"[QUOTAS] No key information found for quota ID '".$quota->{'ID'}."'");
							next;
						}
	
						# Get limits
						my $limits = getLimits($server,$quota->{'ID'});
						if (!defined($limits)) {
							$server->log(LOG_WARN,"[QUOTAS] No limits defined for quota ID '".$quota->{'ID'}."'");
							next;
						}
	
						# Loop with limits
						foreach my $limit (@{$limits}) {
	
							# Get quota tracking info
							my $qtrack = getTrackingInfo($server,$limit->{'ID'},$key);
							# Check if we have a queue tracking item
							if (defined($qtrack)) {
	
								# Check if we're working with cumulative sizes
								if (lc($limit->{'Type'}) eq "messagecumulativesize") {
									# Make sure increment is at least 0
									$newCounters{$qtrack->{'ID'}} = $qtrack->{'Counter'} if (!defined($newCounters{$qtrack->{'ID'}}));
			
									# Bump up counter
									$newCounters{$qtrack->{'ID'}} += $request->{'size'};
								}
							}
						
	
						} # foreach my $limit (@{$limits})
					} # foreach my $quota (@{$quotas})
				} # foreach my $policyID (@{$request->{'_policy'}->{$priority}})
			} # foreach my $emailAddy (keys %{$request->{'_recipient_policy'}{$priority}})
		} # foreach my $priority (sort {$b <=> $a} keys %{$request->{'_recipient_policy'}})

		# Loop with tracking ID's and update
		foreach my $qtrackID (keys %newCounters) {
			# Update database
			my $sth = DBDo("
				UPDATE 
					quotas_tracking
				SET
					Counter = ".DBQuote($newCounters{$qtrackID}).",
					LastUpdate = ".DBQuote($now)."
				WHERE
					ID = ".DBQuote($qtrackID)."
			");
			if (!$sth) {
				$server->log(LOG_ERR,"[QUOTAS] Failed to update quota_tracking item: ".cbp::dblayer::Error());
				next;
			}
		} # foreach my $qtrack (@trackingList) 
	}
	
	return ($verdict,$verdict_data);
}


# Get key from spec and email addy
sub getEmailKey
{
	my ($spec,$addy) = @_;

	my $key;

	# We need to track the sender
	if ($spec eq 'user@domain') {
		$key = $addy;

	} elsif ($spec eq 'user@') {
		($key) = ( $addy =~ /^([^@]+@)/ );

	} elsif ($spec eq '@domain') {
		($key) = ( $addy =~ /^(?:[^@]+)(@.*)/ );
	}

	return $key;
}


# Get key from IP spec
sub getIPKey
{
	my ($spec,$ip) = @_;

	my $key;

	# Check if spec is ok...
	if (defined($spec) && $spec =~ /^\/(\d+)$/) {
		my $mask = $1;

		# If we couldn't pull the mask, just return
		return if (!defined($mask));

		# Pull long for IP we going to test
		my $ip_long = ip_to_long($ip);

		# Convert mask to longs
		my $mask_long = ipbits_to_mask($mask);

		# AND with mask to get network addy
		my $network_long = $ip_long & $mask_long;

		# Convert to quad;/
		my $cidr_network = long_to_ip($network_long);

		# Create key
		$key = sprintf("%s/%s",$cidr_network,$mask);
	}

	return $key;
}


# Get quota from policyID
sub getQuotas
{
	my ($server,$policyID) = @_;


	my @res;

	# Grab quota data
	my $sth = DBSelect("
		SELECT
			ID,
			Period, 
			Track

		FROM
			quotas

		WHERE
			PolicyID = ".DBQuote($policyID)."
			AND Disabled = 0
	");
	if (!$sth) {
		$server->log(LOG_ERR,"Failed to get quota data: ".cbp::dblayer::Error());
		next;
	}
	while (my $quota = $sth->fetchrow_hashref()) {
		push(@res,$quota);
	}
	DBFreeRes($sth);

	return \@res;
}


# Get key from request
sub getKey
{
	my ($server,$quota,$request) = @_;


	my $res;


	# Split off method and splec
	my ($method,$spec) = ($quota->{'Track'} =~ /^([^:]+):(\S+)/);

	# Make sure we have a method and spec from above
	if (!defined($method) || !defined($spec)) {
		$server->log(LOG_WARN,"[QUOTAS] Invalid tracking specification '".$quota->{'Track'}."'");
	}

	# Lowercase method & spec
	$method = lc($method);
	$spec = lc($spec);

	# Check TrackSenderIP
	if ($method eq "senderip") {
		my $key = getIPKey($spec,$request->{'client_address'});

		# Check for no key
		if (defined($key)) {
			$res = "client_address:$key";
		} else {
			$server->log(LOG_WARN,"[QUOTAS] Unknown key specification in TrackSenderIP");
		}


	# Check TrackSender
	} elsif ($method eq "sender") {
		my $key = getEmailKey($spec,$request->{'sender'});
	
		# Check for no key
		if (defined($key)) {
			$res = "sender:$key";
		} else {
			$server->log(LOG_WARN,"[QUOTAS] Unknown key specification in TrackSender");
		}


	# Check TrackRecipient
	} elsif ($method eq "recipient") {
		my $key = getEmailKey($spec,$request->{'recipient'});
	
		# Check for no key
		if (defined($key)) {
			$res = "recipient:$key";
		} else {
			$server->log(LOG_WARN,"[QUOTAS] Unknown key specification in TrackRecipient");
		}
	}

	return $res;
}


# Get tracking info
sub getTrackingInfo
{
	my ($server,$quotaID,$key) = @_;
	
	
	# Query quota info
	my $sth = DBSelect("
		SELECT 
			ID, QuotasLimitsID,
			Key, Counter, LastUpdate
		FROM
			quotas_tracking
		WHERE
			QuotasLimitsID = ".DBQuote($quotaID)."
			AND Key = ".DBQuote($key)."
	");
	if (!$sth) {
		$server->log(LOG_ERR,"[QUOTAS] Failed to query quotas_tracking: ".cbp::dblayer::Error());
		next;
	}
	my $qtrack = $sth->fetchrow_hashref(); 
	DBFreeRes($sth);

	return $qtrack;
}


# Get limits
sub getLimits
{
	my ($server,$quotasID) = @_;

	# Query quota info
	my $sth = DBSelect("
		SELECT 
			ID,
			Type, CounterLimit
		FROM
			quotas_limits
		WHERE
			QuotasID = ".DBQuote($quotasID)."
			AND Disabled = 0
	");
	if (!$sth) {
		$server->log(LOG_ERR,"[QUOTAS] Failed to query quotas_limits: ".cbp::dblayer::Error());
		return;
	}
	my $list;
	while (my $qtrack = $sth->fetchrow_hashref()) {
		push(@{$list},$qtrack);
	}
	DBFreeRes($sth);

	return $list;
}


1;
# vim: ts=4
