# Access control module
# Copyright (C) 2008, LinuxRulz
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


package cbp::modules::AccessControl;

use strict;
use warnings;


use cbp::logging;
use cbp::dblayer;


# User plugin info
our $pluginInfo = {
	name 			=> "Access Control Plugin",
	check 			=> \&check,
	init		 	=> \&init,
};


# Module configuration
my %config;


# Create a child specific context
sub init {
	my $server = shift;
	my $inifile = $server->{'inifile'};

	# Defaults
	$config{'enable'} = 0;


	# Parse in config
	if (defined($inifile->{'accesscontrol'})) {
		foreach my $key (keys %{$inifile->{'accesscontrol'}}) {
			$config{$key} = $inifile->{'accesscontrol'}->{$key};
		}
	}
}


# Destroy
sub finish {
}



# Check the request
sub check {
	my ($server,$request) = @_;
	
	use Data::Dumper;
#	$server->log(LOG_DEBUG,"CHECK: ".Dumper($request));

	# If we not enabled, don't do anything
	return undef if (!$config{'enable'});

	# We only valid in the RCPT state
	return undef if (!defined($request->{'protocol_state'}) || $request->{'protocol_state'} ne "RCPT");

}



1;
# vim: ts=4
