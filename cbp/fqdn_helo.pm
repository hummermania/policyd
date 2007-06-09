# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Module to check if a HELO/EHLO is FQDN


package cbp::fqdn_helo;

use Net::DNS;
use cbp::modules;




# User plugin info
our $pluginInfo = {
	name 	=> "FQDN HELO/EHLO Plugin",
	check 	=> \&check,
};


# Check the request
sub check {
	my $request = shift;


	# We only valid in the RCPT state
	return 0 if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");
	# Return if we don't have a helo_name
	return 0 if (!defined($request->{'helo_name'}) || $request->{'helo_name'} eq "");


	# FIXME - configureation, bypass FQDN checks for SASL users
	return 0 if (defined($request->{'sasl_username'}) && $request->{'sasl_username'} ne "");

	# FIXME - configuration, restrict to address literal
	# Check if helo is an address literal
	return 0 if ($request->{'helo_name'} =~ /^\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]$/);

	# FIXME - configuration, restrict to FQDN
	# Check if helo is a FQDN - Only valid characters in a domain is alnum and a -
	if ($request->{'helo_name'} =~ /^[\w-]+(\.[\w-]+)+$/) {
		# FIXME - configuration, resolvable FQDN
		my $res = Net::DNS::Resolver->new;
		my $query = $res->search($request->{'helo_name'});
		# If the query failed
		if (!$query) {
			# Check errror
			if ($res->errorstring eq "NXDOMAIN") {
				logModule(2,"Rejecting HELO/EHLO '".$request->{'helo_name'}."', not found.");
				setCheckResult("action=REJECT Invalid HELO/EHLO: Does not resolve");
				return 1;
			if ($res->errorstring eq "SERVFAIL") {
				setCheckResult("action=DEFER_IF_PERMIT Cannot resolve HELO/EHLO");
				return 1;  # FIXME - Use proper defer-if-permit here and return 0?
			} else {
				logModule(2,"Unknown error resolving '".$request->{'helo_name'}."': ".$res->errorstring);
			}
         }

		 return 0;
	}


	logModule(2,"Rejecting HELO/EHLO '".$request->{'helo_name'}."'");


	setCheckResult("action=REJECT Invalid HELO/EHLO: RFC2821 requires FQDN HELO/EHLO");

	return 1;
}





1;
# vim: ts=4
