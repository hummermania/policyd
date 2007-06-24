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
my @trackingLookupTables;
my @trackingUpdateTables;


# Load modules stuff
sub load {
	my $server = shift;
	my $ini = $server->{'inifile'};

	
	# Defaults
	$config{'enable'} = 0;

	$config{'enable_whitelist'} = 1;
	$config{'whitelist_lookup'} = "helo_whitelist";

	$config{'enable_tracking'} = 1;
	$config{'tracking_lookup'} = "helo_tracking";
	$config{'tracking_update'} = "helo_tracking";
	
	$config{'tracking_window'} = undef;
	$config{'tracking_window_limit'} = 5;
	
	$config{'tracking_auto_prune'} = 0;


	# Parse in config
	foreach my $token (
			"enable",
			"enable_whitelist",
			"whitelist_lookup",
			"enable_tracking",
			"tracking_lookup",
			"tracking_update",
			"tracking_window",
			"tracking_window_limit",
			"tracking_auto_prune",
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
	foreach my $table ((@whitelistLookupTables,@trackingLookupTables, @trackingUpdateTables)) {
		$table->close();
	}
}



# Check the request
sub check {
	my $request = shift;

	# If we not enabled, don't do anything
	return 0 if (!$config{'enable'});


	# We only valid in the RCPT state
	return 0 if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");
	# Return if we don't have a helo_name
	return 0 if (!defined($request->{'helo_name'}) || $request->{'helo_name'} eq "");
	# Return if we don't have the stuff we need
	return 0 if (!defined($request->{'client_address'}) || $request->{'client_address'} eq "");


	my $res;

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
					logger(LOG_INFO,"[HELO] Tracking window for ".$request->{'client_address'}." exceeded HELO limit ".$config{'tracking_window_limit'}."($helo_count)");
					$helo_exceeded = 1;
				}
			}
		}

		# Check if we should automagically prune the HELO's
		if ($config{'tracking_auto_prune'} && @oldHelos > 0) {
			# Nuke old HELO's out of our databases
			foreach my $table (@trackingUpdateTables) {
				# FIXME - enable this
#				$res = $table->remove({
#						'helo_name'			=> @oldHelos,
#				});
			}
			logger(LOG_INFO,"[HELO] Pruned ".(@oldHelos)." HELO's for ".$request->{'client_address'});
		}

		# If HELO count exceeded, reject
		if ($helo_exceeded) {
			# FIXME - enable this
			logger(LOG_NOTICE,"[HELO] Address '".$request->{'client_address'}."' exceeds allowed helo count of '".$config{'max_helo_count'});
		}


	}


	# check helo validity, does it violate rfc in its construction?

	# check helo count for host

	# check if helo resolves, if not, maybe reject
	# if helo resolves, set address it resolves to

	# if we an address literal, set address to address literal

	# check if helo address is whitelisted?







	# QUERY DICTIONARY HERE, if we get a positive result, blacklist


	# Check helo
	my @blacklist = ('localhost','localhost.localdomain');
	my $found = 0;
	foreach (@blacklist) {
		if ($request->{'helo_name'} eq $_) {
			$found = 1;
			last;
		}
	}

	if ($found) {
		logger(3,"Blacklisting sending server '".$request->{'client_address'}."', blacklisted helo.");
		setCheckResult("action=REJECT Blacklisted: HELO/EHLO");
		return 1;
	}

	return 0;
}





1;
# vim: ts=4
