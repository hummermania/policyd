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


	setCheckResult("action=DEFER_IF_PERMIT Policy Rejection: Greylisted");

	return 0;
}





1;
# vim: ts=4
