# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-09
# Desc: Module to implement HELO/EHLO whitelisting & blacklisting

package cbp::feature::helo;

use strict;
use warnings;

use cbp::modules;
use cbp::ltable;
use cbp::logging;

use Data::Dumper;


# User plugin info
our $pluginInfo = {
	name 			=> "HELO/EHLO Plugin",
	check 			=> \&check,
	load 			=> \&load,
	init		 	=> \&init,
	finish		 	=> \&finish,
};


# Our config
my %config;
my @whitelistLookupTables;
my @blacklistLookupTables;
my @trackingLookupTables;
my @trackingUpdateTables;


# Load modules stuff
sub load {
	my $server = shift;
	my $ini = $server->{'inifile'};

	
	# Defaults
	$config{'enable'} = 0;

	$config{'bypass_for_sasl'} = 1;

	$config{'enable_whitelist'} = 1;
	$config{'whitelist_lookup'} = "helo_whitelist";

	$config{'enable_tracking'} = 1;
	$config{'tracking_lookup'} = "helo_tracking";
	$config{'tracking_update'} = "helo_tracking";
	
	$config{'tracking_window'} = undef;
	$config{'tracking_window_limit'} = 5;
	
	$config{'tracking_auto_prune'} = 0;
	
	$config{'enable_blacklist'} = 1;
	$config{'blacklist_lookup'} = "helo_blacklist";

	$config{'reject_unresolvable_helo'} = 0;
	$config{'reject_ip_address'} = 0;


	# Parse in config
	foreach my $token (
			"enable",
			"bypass_for_sasl",
			"enable_whitelist",
			"whitelist_lookup",
			"enable_tracking",
			"tracking_lookup",
			"tracking_update",
			"tracking_window",
			"tracking_window_limit",
			"tracking_auto_prune",
			"enable_blacklist",
			"blacklist_lookup",
			"reject_unresolvable_helo",
			"reject_ip_address",
	) {
		my $val = $ini->val("helo",$token);
		$config{$token} = $val if (defined($val));
	}

}


# Create a child specific context
sub init {
	my $server = shift;


	# Load lookup tables
	foreach (split(/[, ]/,$config{'whitelist_lookup'})) {
		my $table = cbp::ltable->new($server,$_);
		push(@whitelistLookupTables,$table) if (defined($table));
	}
	foreach (split(/[, ]/,$config{'blacklist_lookup'})) {
		my $table = cbp::ltable->new($server,$_);
		push(@blacklistLookupTables,$table) if (defined($table));
	}
	foreach (split(/[, ]/,$config{'tracking_lookup'})) {
		my $table = cbp::ltable->new($server,$_);
		push(@trackingLookupTables,$table) if (defined($table));
	}

	# Load update tables
	foreach (split(/[, ]/,$config{'tracking_update'})) {
		my $table = cbp::ltable->new($server,$_);
		push(@trackingUpdateTables,$table) if (defined($table));
	}
}


# Destroy
sub finish {
	foreach my $table ((@whitelistLookupTables,@blacklistLookupTables,@trackingLookupTables,@trackingUpdateTables)) {
		$table->close();
	}
}



# Check the request
sub check {
	my $request = shift;

	# If we not enabled, don't do anything
	return undef if (!$config{'enable'});


	# We only valid in the RCPT state
	return undef if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");
	# Return if we don't have a helo_name
	return undef if (!defined($request->{'helo_name'}) || $request->{'helo_name'} eq "");
	# Return if we don't have the stuff we need
	return undef if (!defined($request->{'client_address'}) || $request->{'client_address'} eq "");


	my $res;

	# Bypass checks for SASL users
	if ($config{'bypass_for_sasl'} && defined($request->{'sasl_username'}) && $request->{'sasl_username'} ne "") {
		logger(LOG_NOTICE,"[HELO] Bypassing for SASL user '".$request->{'sasl_username'}."'[".$request->{'client_address'}."]");
		return undef;
	}
	
	# Check if we should use HELO whitelisting
	if ($config{'enable_whitelist'}) {
		my $found = 0;
		# Loop with lookup tables
		foreach my $table (@whitelistLookupTables) {
			$res = $table->lookup({
				'client_address' => $request->{'client_address'},
			});
			logger(LOG_INFO,"[HELO] Whitelist check against '".$table->name."' returned ".(@{$res})." results");
			# Check result
			if (@{$res} >= 1) {
				$found = 1;
				last;
			}
		}
		# If we found a whitelist entry, return undef
		if ($found == 1) {
			logger(LOG_NOTICE,"[HELO] Address '".$request->{'client_address'}."' whitelisted");
			return undef;
		}
	}
	
	# Check if we should use HELO tracking
	if ($config{'enable_tracking'}) {
		my $helo_exceeded = 0;
		my @oldHelos;

		# Record the HELO in all our update databases
		foreach my $table (@trackingUpdateTables) {
			# Hey look .... a helo, record it
			$res = $table->store(LTABLE_UPDATE_ON_CONFLICT, {
					'client_address'	=> $request->{'client_address'},
					'helo_name'			=> $request->{'helo_name'},
					'timestamp'			=> $request->{'_timestamp'},
			});
			logger(LOG_INFO,"[HELO] Recorded helo '".$request->{'helo_name'}."' from '".$request->{'client_address'}."'");
		}

		# Lookup
		foreach my $table (@trackingLookupTables) {
			# Lookup and see how many
			$res = $table->lookup({
					'client_address'	=> $request->{'client_address'},
			});
			logger(LOG_INFO,"[HELO] Lookup for '".$request->{'client_address'}."' returned ".(@{$res})." results");
			# Check if we have limits on what we accept
			if (defined($config{'tracking_window'})) {
				my $helo_count = 0;

				# Check what to count
				foreach my $i (@{$res}) {
					# Check if we should count the HELO
					if ($i->{'timestamp'} > $request->{'_timestamp'} - $config{'tracking_window'}) {
						$helo_count++;
					} else {
						# This is an old HELO, lets just delete it just now
						push(@oldHelos,$i->{'helo_name'});
					}
				}
	
				# Check if helo count exceeds our limit
				if ($helo_count >= $config{'tracking_window_limit'}) {
					logger(LOG_INFO,"[HELO] Tracking window for ".$request->{'client_address'}." exceeded HELO limit ".$config{'tracking_window_limit'}
							."($helo_count)");
					$helo_exceeded = 1;
				}
			}
		}

		# Check if we should automagically prune the HELO's
		if ($config{'tracking_auto_prune'} && @oldHelos > 0) {
			# Nuke old HELO's out of our databases
			foreach my $table (@trackingUpdateTables) {
				$res = $table->remove({
						'helo_name'			=> \@oldHelos,
				});
			}
			logger(LOG_INFO,"[HELO] Pruned ".(@oldHelos)." HELO's for ".$request->{'client_address'});
		}

		# If HELO count exceeded, reject
		if ($helo_exceeded) {
			logger(LOG_NOTICE,"[HELO] Address '".$request->{'client_address'}."' exceeds allowed helo count of '".$config{'max_helo_count'});
			return "action=REJECT Rejected HELO/EHLO: Threshold exceeded";
		}
	}

	# Check for stuff to blacklist
	if ($config{'enable_blacklist'}) {
		my $found = 0;
		# Loop with lookup tables
		foreach my $table (@blacklistLookupTables) {
			$res = $table->lookup({
				'helo_name' => $request->{'helo_name'},
			});
			logger(LOG_INFO,"[HELO] Blacklist check against '".$table->name."' returned ".(@{$res})." results");
			# Check result
			if (@{$res} >= 1) {
				$found = 1;
				last;
			}
		}
		# If we found a blacklist entry, reject
		if ($found == 1) {
			logger(LOG_NOTICE,"[HELO] Address '".$request->{'client_address'}."' blacklisted");
			return "action=REJECT Rejected HELO/EHLO: Blacklisted";
		}
	}

	# Check if helo is an address literal
	if ($request->{'helo_name'} =~ /^\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]$/) {
		logger(LOG_INFO,"[HELO] No further checks, this is an address literal: '".$request->{'helo_name'}."'");
		return undef;

	# Check the use of an IP address in the HELO/EHLO command. This violations RFC, and IP address must be an FQDN or address literal
	} elsif ($request->{'helo_name'} =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
		if ($config{'reject_ip_address'}) {
			logger(LOG_NOTICE,"[HELO] Rejecting HELO/EHLO which is an IP address '".$request->{'helo_name'}."'");
			return "action=REJECT Rejected HELO/EHLO: '".$request->{'helo_name'}."' is not FQDN";
		}
		return undef;
	
	# Check if helo is a FQDN - Only valid characters in a domain is alnum and a -
	} elsif ($request->{'helo_name'} =~ /^[\w-]+(\.[\w-]+)+$/) {

		# Check if we must check resolvability
		if ($config{'reject_unresolvable_helo'}) {
			my $res = Net::DNS::Resolver->new;
			my $query = $res->search($request->{'helo_name'});

			# If the query failed
			if (!$query) {

				# Check for error
				if ($res->errorstring eq "NXDOMAIN") {
					logger(LOG_NOTICE,"[HELO] Rejecting HELO/EHLO '".$request->{'helo_name'}."', not found.");
					return "action=REJECT Invalid HELO/EHLO: '".$request->{'helo_name'}."' does not resolve, no such domain";
				} elsif ($res->errorstring eq "NOERROR") {
					logger(LOG_NOTICE,"[HELO] Rejecting HELO/EHLO '".$request->{'helo_name'}."', no records.");
					return "action=REJECT Invalid HELO/EHLO: '".$request->{'helo_name'}."' does not resolve, no records found";
				} elsif ($res->errorstring eq "SERVFAIL") {
					logger(LOG_NOTICE,"Rejecting HELO/EHLO '".$request->{'helo_name'}."', temp fail.");
					return "action=DEFER_IF_PERMIT Invalid HELO/EHLO: Failure while trying to resolve '".$request->{'helo_name'}."'";
				} else {
					logger(LOG_ERR,"[HELO] Unknown error resolving '".$request->{'helo_name'}."': ".$res->errorstring);
			 		return undef;
				}
    	    }

			# Look for MX or A records
			my $found = 0;
			foreach my $rr ($query->answer) {
				next unless ($rr->type eq "A" || $rr->type eq "MX");
				$found = 1;
			}

			# Check if we found any valid DNS records
			if (!$found) {
				logger(LOG_NOTICE,"[HELO] Rejecting HELO/EHLO '".$request->{'helo_name'}."', no valid records.");
				return "action=REJECT Invalid HELO/EHLO: No A or MX records found for '".$request->{'helo_name'}."'";
			}
		}

		return undef;
	}

	# If we failed the FQDN check, reject
	logger(LOG_NOTICE,"Rejecting HELO/EHLO '".$request->{'helo_name'}."', invalid.");
	return "action=REJECT Invalid HELO/EHLO: '".$request->{'helo_name'}."' is invalid, RFC2821 section 3.6 requires a HELO/EHLO be a resolvable FQDN hostname";
}





1;
# vim: ts=4
