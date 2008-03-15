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
    my ($sourceIP,$emailFrom,$emailTo,$saslUsername) = @_;


	# Start with blank policy list
	my %matchedPolicies = ();


	# Grab all the policy ACL's
	my $sth = DBSelect('
		SELECT 
			policies.Name,
			policy_acls.PolicyID, policies.Priority, policy_acls.Source, policy_acls.Destination
		FROM
			policies, policy_acls
		WHERE
			policies.Disabled = 0
			AND policy_acls.Disabled = 0
			AND policy_acls.PolicyID = policies.ID
	');
	if (!$sth) {
		setError(cbp::dblayer::Error());
		return undef;
	}
	# Loop with results
	my @policyACLs;
	while (my $row = $sth->fetchrow_hashref()) {
		push(@policyACLs,$row);
	}

	# Process the ACL's
	foreach my $policyACL (@policyACLs) {

		#
		# Source Test
		#
		my $sourceMatch = 1;
		if (defined($policyACL->{'Source'}) && lc($policyACL->{'Source'}) ne "any") {
			# Split off sources
			my @rawSources = split(/,/,$policyACL->{'Source'});

			# Parse in group data
			my @sources;
			foreach my $source (@rawSources) {
				# Match group
				if (my ($negate,$group) = ($source =~ /^(!?)?%(\S+)$/)) {

					# Grab group members
					my $members = getGroupMembers($group);
					if (!$members) {
						setError(Error());
						return undef;
					}

					# Check if we should negate
					foreach my $member (@{$members}) {
						if (!($source =~ /^!/) && $negate) {
							$member = "!$member";
						}
						push(@sources,$member);
					}


				# If its not a group, just add
				} else {
					push(@sources,$source);
				}
			}
			
			# Process sources and see if we match
			foreach my $source (@sources) {
				my $res = 0;

				# Match IP
				if ($source =~ /^!?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})$/) {
					$res = ipMatches($sourceIP,$source);

				# Match email addy
				} elsif ($source =~ /^!?\S*@\S+$/) {
					$res = emailAddressMatches($emailFrom,$source);

				# Match sasl user
				} elsif ($source =~ /^!?\$\S+$/) {
					$res = saslUsernameMatches($saslUsername,$source);

				} else {
					setError("Source '".$source."' is not valid in policy '".$policyACL->{'Name'}."' acl or group");
					return undef;
				}

				# If we have a negative result, last and b0rk out
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
		if (defined($policyACL->{'Destination'}) && lc($policyACL->{'Destination'}) ne "any") {
			# Split off destinations
			my @rawDestinations = split(/,/,$policyACL->{'Destination'});

			# Parse in group data
			my @destinations;
			foreach my $destination (@rawDestinations) {
				# Match group
				if (my ($negate,$group) = ($destination =~ /^(!?)?%(\S+)$/)) {

					# Grab group members
					my $members = getGroupMembers($group);
					if (!$members) {
						setError(Error());
						return undef;
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
			}
			
			# Process destinations and see if we match
			foreach my $destination (@destinations) {
				my $res = 0;

				# Match email addy
				if ($destination =~ /^!?\S*@\S+$/) {
					$res = emailAddressMatches($emailTo,$destination);

				} else {
					setError("Destination '".$destination."' is not valid in policy '".$policyACL->{'Name'}."' acl or group");
					return undef;
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

		push(@{$matchedPolicies{$policyACL->{'Priority'}}},$policyACL->{'PolicyID'});
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
		setError(cbp::dblayer::Error());
		return undef;
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

	if (lc($saslUsername) eq lc($template_user) || $template_user eq "*") {
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

	# Generate...    recipient@domain#priority=policy_id,policy_id,policy_id;priority2=policy_id2,policy_id2/recipient2@...
	my $ret = "$email#";
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

		my ($email,$rawPolicy) = ($item =~ /([^#]+)#(.*)/);
		
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
