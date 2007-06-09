# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Module to check reverse DNS of sending server


package cbp::reverse_source;

use cbp::modules;




# User plugin info
our $pluginInfo = {
	name 	=> "Reverse Sending Server Plugin",
	check 	=> \&check,
};


# Check the request
sub check {
	my $request = shift;


	# We only valid in the RCPT state
	return 0 if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");
	# Return if we don't have the stuff we need
	return 0 if (!defined($request->{'client_address'}) || $request->{'client_address'} eq "");

	# FIXME - configuration, resolvable FQDN
	my $res = Net::DNS::Resolver->new;
	my $query = $res->search($request->{'client_address'});
	# If the query failed
	if (!$query) {
		# Check errror
		if ($res->errorstring eq "NXDOMAIN") {
			logger(3,"Rejecting sending server '".$request->{'client_address'}."', not found.");
			setCheckResult("action=REJECT Sending IP not reversed: No PTR record found");
			return 1;
		} elsif ($res->errorstring eq "NOERROR") {
			logger(3,"Rejecting sending server '".$request->{'client_address'}."', not records.");
			setCheckResult("action=REJECT Sending IP not reversed: No PTR record found");
			return 1;
		} elsif ($res->errorstring eq "SERVFAIL") {
			logger(3,"Rejecting sending server '".$request->{'client_address'}."', temp fail.");
			setCheckResult("action=DEFER_IF_PERMIT Cannot reverse sending server");
			return 1;  # FIXME - Use proper defer-if-permit here and return 0?
		} else {
			logger(0,"Unknown error resolving '".$request->{'client_address'}."': ".$res->errorstring);
		}
     }
	# Look for MX or A records
	my $found = 0;
	foreach my $rr ($query->answer) {
		next unless ($rr->type eq "PTR");
		$found = 1;
	}
	# Check if we found any valid DNS records
	if (!$found) {
		logger(3,"Rejecting sending server '".$request->{'client_address'}."', not reversed.");
		setCheckResult("action=REJECT Sending IP not reversed: No PTR record found");
		return 1;
	}

	return 0;
}





1;
# vim: ts=4
