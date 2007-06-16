# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-09
# Desc: Module to implement HELO/EHLO whitelisting & blacklisting

package cbp::feature::helo;

use cbp::modules;
use cbp::ltable;



# User plugin info
our $pluginInfo = {
	name 	=> "HELO/EHLO Plugin",
	check 	=> \&check,
	init 	=> \&init,
};


# Our config
my %config;
my @lookupTables;
my @updateTables;


# Init
sub init {
	my $server = shift;
	my $ini = $server->{'inifile'};

	
	# Defaults
	$config{'enable'} = 0;

	$config{'enable_whitelist'} = 1;
	$config{'whitelist_lookup'} = "helo_whitelist";

	$config{'enable_tracking'} = 1;
	$config{'tracking_lookup'} = "helo_tracking";
	$config{'tracking_update'} = "helo_tracking";


	logger(1,"DEBUG: ".$ini->val("table ".$config{'tracking_lookup'},"provider"));
	logger(1,"DEBUG: ".$ini->val("table ".$config{'tracking_update'},"provider"));


	# Parse in config
	for $token (
			"enable",
			"enable_whitelist",
			"whitelist_lookup",
			"enable_tracking",
			"tracking_lookup",
			"tracking_update",
	) {
		my $val = $ini->val("helo",$token);
		$config{$token} = $val if (defined($val));
	}

	# Load lookup tables
	foreach (split(/[, ]/,$config{'tracking_lookup'})) {
		my $table = loadTable($server,$_);
		push(@lookupTables,$table) if (defined($table));
	}

	# Load update tables
	foreach (split(/[, ]/,$config{'tracking_update'})) {
		my $table = loadTable($server,$_);
		push(@updateTables,$table) if (defined($table));
	}

}



# Check the request
sub check {
	my $request = shift;


	# If we not enabled, don't do anything
	return 0 if ($config{'enable'});


	# We only valid in the RCPT state
	return 0 if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");
	# Return if we don't have a helo_name
	return 0 if (!defined($request->{'helo_name'}) || $request->{'helo_name'} eq "");
	# Return if we don't have the stuff we need
	return 0 if (!defined($request->{'client_address'}) || $request->{'client_address'} eq "");


	my $res;

	# Check if we should use HELO whitelisting
	if ($config{'enable_whitelist'}) {
		# Do a whitelist lookup
		$res = keyLookup($config{'whitelist_lookup'}, {
				'address' 		=> $request->{'client_address'},
		});
	}

	# Check if we should use HELO tracking
	if ($config{'enable_tracking'}) {
		# Hey look .... a helo, record it
		$res = keyStore($config{'tracking_update'}, KEY_UPDATE_ON_CONFLICT, {
				'address'	=> $request->{'client_address'},
				'helo'		=> $request->{'helo_name'},
				'timestamp'	=> $request->{'_timestamp'},
		});
		# Lookup and see how many
		$res = keyLookup($config{'tracking_lookup'}, {
				'address' 		=> $request->{'client_address'},
		});
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
