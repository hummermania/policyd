# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Module to implement spamtraps


package cbp::spamtrap;

use cbp::modules;




# User plugin info
our $pluginInfo = {
	name 	=> "Spamtrap Plugin",
	check 	=> \&check,
};


# Check the request
sub check {
	my $request = shift;


#	setCheckResult("action=REJECT Policy Rejection: Spamtrap(Blacklisted)");

	return 0;
}





1;
# vim: ts=4
