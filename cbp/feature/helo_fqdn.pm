# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Module to check if a HELO/EHLO is FQDN


package cbp::feature::helo_fqdn;

use Net::DNS;
use cbp::modules;




# User plugin info
our $pluginInfo = {
	name 	=> "FQDN HELO/EHLO Plugin",
	check 	=> \&check,
	init 	=> \&init,
};

# Our config
my %config;


# Init
sub init {
	my $server = shift;
	my $ini = $server->{'inifile'};

	
	# Defaults
	$config{'enable'} = 0;
	$config{'bypass_for_sasl'} = 1;
	$config{'allow_address_literals'} = 1;
	$config{'reject_unresolvables'} = 0;

	# Parse in config
	for $token (
			"enable",
			"bypass_for_sasl",
			"allow_address_literals",
			"reject_unresolvables",
	) {
		my $val = $ini->val("helo_fqdn",$token);
		# If defined, set
		if (defined($val)) {
			print(STDERR "$token/$val\n");
		}
	}
}


# Check the request
sub check {
	my $request = shift;


	# Check is only valid in the RCPT state
	return 0 if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");
	# Return if we don't have a helo_name
	if (!defined($request->{'helo_name'}) || $request->{'helo_name'} eq "") {
		logger(2,"Didn't get 'helo_name'!");
		return 0;
	}


	# Bypass FQDN checks for SASL users
	if ($config{'bypass_for_sasl'}) {
		return 0 if (defined($request->{'sasl_username'}) && $request->{'sasl_username'} ne "");
	}

	# Check if helo is an address literal
	if ($config{'allow_address_literals'}) {
		return 0 if ($request->{'helo_name'} =~ /^\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]$/);
	}

	# Check if helo is a FQDN - Only valid characters in a domain is alnum and a -
	if ($request->{'helo_name'} =~ /^[\w-]+(\.[\w-]+)+$/) {

		# Check if we must check resolvability
		if ($config{'reject_unresolvables'}) {
			my $res = Net::DNS::Resolver->new;
			my $query = $res->search($request->{'helo_name'});

			# If the query failed
			if (!$query) {

				# Check for error
				if ($res->errorstring eq "NXDOMAIN") {
					logger(3,"Rejecting HELO/EHLO '".$request->{'helo_name'}."', not found.");
					setCheckResult("action=REJECT Invalid HELO/EHLO: Does not resolve, no such domain");
					return 1;
				} elsif ($res->errorstring eq "NOERROR") {
					logger(3,"Rejecting HELO/EHLO '".$request->{'helo_name'}."', no records.");
					setCheckResult("action=REJECT Invalid HELO/EHLO: Does not resolve, no records found");
					return 1;
				} elsif ($res->errorstring eq "SERVFAIL") {
					logger(3,"Rejecting HELO/EHLO '".$request->{'helo_name'}."', temp fail.");
					setCheckResult("action=DEFER_IF_PERMIT Failure while trying to resolve HELO/EHLO");
					return 1;  # FIXME - Use proper defer-if-permit here and return 0?
				} else {
					logger(1,"Unknown error resolving '".$request->{'helo_name'}."': ".$res->errorstring);
			 		return 0;
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
				logger(3,"Rejecting HELO/EHLO '".$request->{'helo_name'}."', no valid records.");
				setCheckResult("action=REJECT Invalid HELO/EHLO: No A or MX records found");
				return 1;
			}
		}

		return 0;
	}

	# If we failed the FQDN check, reject
	logger(3,"Rejecting HELO/EHLO '".$request->{'helo_name'}."', invalid.");
	setCheckResult(
		"action=REJECT Invalid HELO/EHLO: Not FQDN".
		# If we allow address literls, say we do, or we don't
		($config{'allow_address_literals'} ? " or address literal" : "") .
		" as required by RFC2821 secion 3.6"
	);
	return 1;
}





1;
# vim: ts=4
