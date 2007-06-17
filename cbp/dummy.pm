# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Dummy module


package cbp::dummy;

use strict;
use warnings;

use cbp::modules;




# User plugin info
our $pluginInfo = {
	name 	=> "Dummy Plugin",
	check 	=> \&check,
};


# Check the request
sub check {
	my $request = shift;



	return 0;
}





1;
# vim: ts=4
