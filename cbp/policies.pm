# Policy handling functions
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


package cbp::policies;

use strict;
use warnings;

# Exporter stuff
require Exporter;
our (@ISA,@EXPORT);
@ISA = qw(Exporter);
@EXPORT = qw(
	getPolicy
	encodePolicyData
	decodePolicyData
);


use cbp::logging;
use cbp::dblayer;
use cbp::system;


# Database handle
my $dbh = undef;

# Our current error message
my $error = "";

# Set current error message
# Args: error_message
sub setError
{
	my $err = shift;
	my ($package,$filename,$line) = caller;
	my (undef,undef,undef,$subroutine) = caller(1);

	# Set error
	$error = "$subroutine($line): $err";
}

# Return current error message
# Args: none
sub Error
{
	my $err = $error;

	# Reset error
	$error = "";

	# Return error
	return $err;
}



# Return a hash of policies matches
# Returns:
# 	Hash - indexed by policy priority, the value is an array of policy ID's
sub getPolicy
{
    my ($server,$sourceIP,$emailFrom,$emailTo,$saslUsername) = @_;
	my $log = defined($server->{'config'}{'logging'}{'policies'});


	# Start with blank policy list
	my %matchedPolicies = ();


	# Grab all the policy members
	my $sth = DBSelect('
		SELECT 
			policies.Name, policies.Priority, policies.Disabled AS PolicyDisabled,
			policy_members.ID, policy_members.PolicyID, policy_members.Source, 
			policy_members.Destination, policy_members.Disabled AS MemberDisabled
		FROM
			policies, policy_members
		WHERE
			policies.Disabled = 0
			AND policy_members.Disabled = 0
			AND policy_members.PolicyID = policies.ID
	');
	if (!$sth) {
		$server->log(LOG_DEBUG,"[POLICIES] Error while selecing policy members from database: ".cbp::dblayer::Error());
		return undef;
	}
	# Loop with results
	my @policyMembers;
	while (my $row = $sth->fetchrow_hashref()) {
		# Log what we see
		if ($row->{'PolicyDisabled'} eq "1") {
			$server->log(LOG_DEBUG,"[POLICIES] Policy '".$row->{'Name'}."' is disabled") if ($log);
		} elsif ($row->{'MemberDisabled'} eq "1") {
			$server->log(LOG_DEBUG,"[POLICIES] Policy member item with ID '".$row->{'ID'}."' is disabled") if ($log);
		} else {
			$server->log(LOG_DEBUG,"[POLICIES] Found policy member with ID '".$row->{'ID'}."' in policy '".$row->{'Name'}."'") if ($log);
			push(@policyMembers,$row);
		}
	}

	# Process the Members
	foreach my $policyMember (@policyMembers) {

		#
		# Source Test
		#
		my $sourceMatch = 1;
		if (defined($policyMember->{'Source'}) && lc($policyMember->{'Source'}) ne "any") {
			# Split off sources
			my @rawSources = split(/,/,$policyMember->{'Source'});

			# Parse in group data
			my @sources;
			foreach my $source (@rawSources) {
				# Match group
				if (my ($negate,$group) = ($source =~ /^(!?)?%(\S+)$/)) {

					# Grab group members
					my $members = getGroupMembers($group);
					if (ref $members ne "ARRAY") {
						$server->log(LOG_WARN,"[POLICIES] Error '$members' while retriving group members for source group '$group' in ".
								"policy '".$policyMember->{'Name'}."', policy member ID '".$policyMember->{'ID'}."' ");
						next;
					}
					# Check if actually have any
					if (@{$members} < 1) {
						$server->log(LOG_WARN,"[POLICIES] No group members for source group '$group' in policy '".$policyMember->{'Name'}.
								"', policy member ID '".$policyMember->{'ID'}."' ");
					}

					# Check if we should negate
					foreach my $member (@{$members}) {
						if (!($member =~ /^!/) && $negate) {
							$member = "!$member";
						}
						push(@sources,$member);
					}

				# If its not a group, just add
				} else {
					push(@sources,$source);
				}
				$server->log(LOG_DEBUG,"[POLICIES] Resolved sources '".join(',',@sources)."' from policy member ID '".$policyMember->{'ID'}."'") if ($log);
			}
		

			# Process sources and see if we match
			foreach my $source (@sources) {
				my $res = 0;

				# Match IP
				if ($source =~ /^!?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})$/) {
					$res = ipMatches($sourceIP,$source);
					$server->log(LOG_DEBUG,"[POLICIES] Resolved policy '".$policyMember->{'Name'}.
							"' source '$source' is an IP/CIDR specification, match = $res") if ($log);

				# Match SASL user, must be above email addy to match SASL usernames in the same format as email addies
				} elsif ($source =~ /^!?\$\S+$/) {
					$res = saslUsernameMatches($saslUsername,$source);
					$server->log(LOG_DEBUG,"[POLICIES] Resolved policy '".$policyMember->{'Name'}.
							"' source '$source' is SASL user specification, match = $res") if ($log);

				# Match email addy
				} elsif ($source =~ /^!?\S*@\S+$/) {
					$res = emailAddressMatches($emailFrom,$source);
					$server->log(LOG_DEBUG,"[POLICIES] Resolved policy '".$policyMember->{'Name'}.
							"' source '$source' is an email address specification, match = $res") if ($log);

				} else {
					$server->log(LOG_WARN,"[POLICIES] Resolved policy '".$policyMember->{'Name'}.
							"' source '".$source."' is not a valid specification");
				}

				# Check result
				if (!$res) {
					$sourceMatch = 0;
					last;
				}

			}

			# Check if we passed the tests
			next if (!$sourceMatch);
		}


		#
		# Destination Test
		#
		my $destinationMatch = 1;
		if (defined($policyMember->{'Destination'}) && lc($policyMember->{'Destination'}) ne "any") {
			# Split off destinations
			my @rawDestinations = split(/,/,$policyMember->{'Destination'});

			# Parse in group data
			my @destinations;
			foreach my $destination (@rawDestinations) {
				# Match group
				if (my ($negate,$group) = ($destination =~ /^(!?)?%(\S+)$/)) {

					# Grab group members
					my $members = getGroupMembers($group);
					if (ref $members ne "ARRAY") {
						$server->log(LOG_WARN,"[POLICIES] Error '$members' while retriving group members for destination group '$group' in ".
								"policy '".$policyMember->{'Name'}."', policy member ID '".$policyMember->{'ID'}."' ");
						next;
					}

					# Check if actually have any
					if (@{$members} < 1) {
						$server->log(LOG_WARN,"[POLICIES] No group members for source group '$group' in policy '".$policyMember->{'Name'}.
								"', policy member ID '".$policyMember->{'ID'}."' ");
					}

					# Check if we should negate
					foreach my $member (@{$members}) {
						if (!($destination =~ /^!/) && $negate) {
							$member = "!$member";
						}
						push(@destinations,$member);
					}


				# If its not a group, just add
				} else {
					push(@destinations,$destination);
				}
				$server->log(LOG_DEBUG,"[POLICIES] Resolved destinations '".join(',',@destinations)."' from policy member ID '".
						$policyMember->{'ID'}."'") if ($log);
			}
			
			# Process destinations and see if we match
			foreach my $destination (@destinations) {
				my $res = 0;

				# Match email addy
				if ($destination =~ /^!?\S*@\S+$/) {
					$res = emailAddressMatches($emailTo,$destination);
					$server->log(LOG_DEBUG,"[POLICIES] Resolved policy '".$policyMember->{'Name'}.
							"' destination '$destination' is an email address specification, match = $res") if ($log);

				} else {
					$server->log(LOG_WARN,"[POLICIES] Resolved policy '".$policyMember->{'Name'}.
								"' destination '".$destination."' is not a valid specification");
				}

				# If we have a negative result, last and b0rk out
				if (!$res) {
					$destinationMatch = 0;
					last;
				}

			}

			# Check if we passed the tests
			next if (!$destinationMatch);
		}

		push(@{$matchedPolicies{$policyMember->{'Priority'}}},$policyMember->{'PolicyID'});
	}


	return \%matchedPolicies;
}



# Get group members from group name
sub getGroupMembers
{
	my $group = shift;


	# Grab group members
	my $sth = DBSelect("
		SELECT 
			policy_group_members.Member
		FROM
			policy_groups, policy_group_members
		WHERE
			policy_groups.Name = ".DBQuote($group)."
			AND policy_groups.ID = policy_group_members.PolicyGroupID
			AND policy_groups.Disabled = 0
			AND policy_group_members.Disabled = 0
	");
	if (!$sth) {
		return cbp::dblayer::Error();
	}
	# Pull in groups
	my @groupMembers = ();
	while (my $row = $sth->fetchrow_hashref()) {
		push(@groupMembers,$row);
	}

	# Loop with results
	my @res;
	foreach my $item (@groupMembers) {
		push(@res,$item->{'Member'});
	}

	return \@res;
}



# Check if first arg falls within second arg CIDR
sub ipMatches
{
	my ($ip,$cidr) = @_;


	# Pull off parts of IP
	my ($cidr_negate,$cidr_address,$cidr_mask) = ($cidr =~ /^(!?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/(\d{1,2}))$/);

	# Pull long for IP we going to test
	my $ip_long = ip_to_long($ip);

	# Convert CIDR to longs
	my $cidr_address_long = ip_to_long($cidr_address);
	my $cidr_mask_long = bits_to_mask($cidr_mask ? $cidr_mask : 32);
	# Pull out network address
	my $cidr_network_long = $cidr_address_long & $cidr_mask_long;
	# And broadcast
	my $cidr_broadcast_long = $cidr_address_long | (IPMASK ^ $cidr_mask_long);

	# Convert to quad;/
	my $cidr_network = long_to_ip($cidr_network_long);
	my $cidr_broadcast = long_to_ip($cidr_broadcast_long);

	# Default to no match
	my $match = 0;

	# Check IP is within range
	if ($ip_long >= $cidr_network_long && $ip_long <= $cidr_broadcast_long) {
		# Check for match, we cannot be negating though
		if (!$cidr_negate) {
			$match = 1;
		}
	# If we didn't match and its a negation, its actually a match
	} elsif ($cidr_negate) {
		$match = 1;
	}

	return $match;
}


# Check if first arg lies within the scope of second arg email/domain
sub emailAddressMatches
{
	my ($email,$template) = @_;

	my $match = 0;

	# Strip email addy
	my ($email_user,$email_domain) = ($email =~ /^(\S+)@(\S+)$/);
	my ($template_negate,$template_user,$template_domain) = ($template =~ /^(!)?(\S*)@(\S+)$/);

	if (lc($email_domain) eq lc($template_domain) && (lc($email_user) eq lc($template_user) || $template_user eq "")) {
		if (!$template_negate) {
			$match = 1;
		}
	} elsif ($template_negate) {
		$match = 1;
	}

	return $match;
}


# Check if first arg lies within the scope of second arg sasl specification
sub saslUsernameMatches
{
	my ($saslUsername,$template) = @_;

	my $match = 0;

	# Decipher template
	my ($template_negate,$template_user) = ($template =~ /^(!?)?\$(\S+)$/);

	# $- is a special case which allows matching against no SASL username
	if ($template_user eq '-' && !$saslUsername) {
		if (!$template_negate) {
			$match = 1;
		}
	} elsif (lc($saslUsername) eq lc($template_user) || $template_user eq "*") {
		if (!$template_negate) {
			$match = 1;
		}
	} elsif ($template_negate) {
		$match = 1;
	}

	return $match;
}


# Encode policy data into session recipient data
sub encodePolicyData
{
	my ($email,$policy) = @_;

	# Generate...    <recipient@domain>#priority=policy_id,policy_id,policy_id;priority2=policy_id2,policy_id2/recipient2@...
	my $ret = "<$email>#";
	foreach my $priority (keys %{$policy}) {
		$ret .= sprintf('%s=%s;',$priority,join(',',@{$policy->{$priority}}));
	}

	return $ret;
}


# Decode recipient data into policy data
sub decodePolicyData
{
	my $recipientData = shift;


	my %recipientToPolicy;
	# Build policy str list and recipients list
	foreach my $item (split(/\//,$recipientData)) {
		# Skip over first /
		next if ($item eq "");

		my ($email,$rawPolicy) = ($item =~ /<([^>]*)>#(.*)/);
		
		# Loop with raw policies
		foreach my $policy (split(/;/,$rawPolicy)) {
			# Strip off priority and policy IDs
			my ($prio,$policyIDs) = ( $policy =~ /(\d+)=(.*)/ );
			# Pull off policyID's from string
			foreach my $pid (split(/,/,$policyIDs)) {
				push(@{$recipientToPolicy{$email}{$prio}},$pid);
			}
		}
	}

	return \%recipientToPolicy;
}


1;
# vim: ts=4
