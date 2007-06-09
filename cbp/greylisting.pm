# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Module to implement greylisting

package cbp::greylisting;

use cbp::modules;




# User plugin info
our $pluginInfo = {
	name 	=> "Greylisting Plugin",
	check 	=> \&check,
};


# Check the request
sub check {
	my $request = shift;

	
	# We only valid in the RCPT state
	return 0 if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");

	my $time = time();

	# Log what we see
	logger(3,
		sprintf('Server: %s, From: %s, To: %s, Time: %s'."\n",$request->{'client_address'},$request->{'sender'},$request->{'recipient'},$time)
	);	
#setCheckResult("action=DEFER_IF_PERMIT Policy Rejection: Greylisted");

	return 0;
}





1;
# vim: ts=4
