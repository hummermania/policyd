# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-09
# Desc: Module to implement various HELO/EHLO checks

package cbp::helo;

use cbp::modules;




# User plugin info
our $pluginInfo = {
	name 	=> "HELO/EHLO Plugin",
	check 	=> \&check,
};


# Check the request
sub check {
	my $request = shift;

	
	# We only valid in the RCPT state
	return 0 if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");
	# Return if we don't have a helo_name
	return 0 if (!defined($request->{'helo_name'}) || $request->{'helo_name'} eq "");
	# Return if we don't have the stuff we need
	return 0 if (!defined($request->{'client_address'}) || $request->{'client_address'} eq "");

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
