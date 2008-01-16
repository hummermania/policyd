# System functions
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



package cbp::system;

use strict;
use warnings;

# Exporter stuff
require Exporter;
our (@ISA,@EXPORT);
@ISA = qw(Exporter);
@EXPORT = qw(
	isValidIP

	ip_to_long
	long_to_ip
	ipbits_to_mask

	IPMASK
);

use Socket qw(
	inet_ntoa
	inet_aton
);


use constant {
	IPMASK 	=> 0xffffffff,
};


# Check for valid IP
sub isValidIP
{
	my $ip = shift;

	my (@ip) = split(/\./, $ip);
	return undef if (scalar(@ip) != 4);


	foreach my $octet (@ip) {
		return 0 unless $octet =~ /^\d+$/;
		return 0 unless $octet >= 0 && $octet <= 255;
	}

	return 1;
}


# Get long int from IP
sub ip_to_long
{
	my $ip = shift;

	# Validate IP
	return undef if (!isValidIP($ip));

	# Unpack IP into a long
	return unpack('L', inet_aton($ip));
}


# Convert IP to long int
sub long_to_ip {
	my $long = shift;

	# Pack into network and convert to IP
	my $ip = inet_ntoa(pack('L', $long));
	
	# Validate
	return undef if (!isValidIP($ip));

	return $ip;
}


# Get mask for ip bits
sub ipbits_to_mask {
	my $nbits = shift;

	# Get string to pass to pack
	my $str = '1' x $nbits . '0' x (32 - $nbits);

	# Grab long mask
	my $mask = unpack('L', pack('B*', $str));
	
	return $mask;
}



1;
# vim: ts=4
