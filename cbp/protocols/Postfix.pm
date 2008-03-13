# Postfix SMTP Access delegation protocol support module
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


package cbp::protocols::Postfix;


use strict;
use warnings;


use cbp::logging;
use cbp::dblayer;


# User plugin info
our $pluginInfo = {
	name 			=> "Postfix SMTP Access Delegation Protocol Suppot Module",
	init		 	=> \&init,
	priority	 	=> 50,
	protocol_check	=> \&protocol_check,
	protocol_parse	=> \&protocol_parse,
};


# Module configuration
my %config;


# Create a child specific context
sub init {
	my $server = shift;
	my $inifile = $server->{'inifile'};

	# Defaults
	$config{'enable'} = 1;

	# Check if enabled
	if ($config{'enable'} =~ /^\s*(y|yes|1|on)\s*$/i) {
		$server->log(LOG_NOTICE,"  => Protocol(Postfix): enabled");
		$config{'enable'} = 1;
	}
}


# Check the buffer to see if this protocol is what we want
sub protocol_check {
	my ($server,$buffer) = @_;
	

	# If we not enabled, don't do anything
	return undef if (!$config{'enable'});

	# Check for policy protocol
	if ($buffer =~ /^\w+=[^\012]+\015?\012/) {
		if ($buffer =~ /\015?\012\015?\012/) {
			$server->log(LOG_INFO,"Identified Postfix protocol");
			return 1;
		}
	}

	return 0;
}


# Process buffer into sessionData
sub protocol_parse {
	my ($server,$buffer) = @_;

	my %res;

	# Loop with each line
	foreach my $line (split /\015?\012/, $buffer) {
		# If we don't get a pair, b0rk
		last unless $line =~ s/^([^=]+)=(.*)$//;
		$res{$1} = $2;
	}

	return \%res;
}



1;
# vim: ts=4
