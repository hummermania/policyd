# System functions
# Copyright (C) 2009, AllWorldIT
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
	bits_to_mask

	parseCIDR

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
	return unpack('N', inet_aton($ip));
}


# Convert IP to long int
sub long_to_ip {
	my $long = shift;

	# Pack into network and convert to IP
	my $ip = inet_ntoa(pack('N', $long));
	
	# Validate
	return undef if (!isValidIP($ip));

	return $ip;
}


# Get mask for ip bits
sub bits_to_mask {
	my $nbits = shift;

	# Get string to pass to pack
	my $str = '1' x $nbits . '0' x (32 - $nbits);

	# Grab long mask
	my $mask = unpack('N', pack('B*', $str));
	
	return $mask;
}


# Parse a CIDR into the various peices
sub parseCIDR
{
	my $cidr = shift;

	# Regex CIDR
	if ($cidr =~ /^(\d{1,3})(?:\.(\d{1,3})(?:\.(\d{1,3})(?:\.(\d{1,3}))?)?)?(?:\/(\d{1,2}))?$/) {
		# Strip any ip blocks and mask from string
		my ($a,$b,$c,$d,$mask) = ($1,$2,$3,$4,$5);

		# Set undefined ip blocks and mask if missing
		if (!defined($b)) {
			$b = 0;
			$mask = 8 if !defined($mask);
		}
		if (!defined($c)) {
			$c = 0;
			$mask = 16 if !defined($mask);
		}
		if (!defined($d)) {
			$d = 0;
			$mask = 24 if !defined($mask);
		}

		# Default mask
		$mask = ( defined($mask) && $mask >= 1 && $mask <= 32 ) ? $mask : 32;

		# Build ip
		my $ip = "$a.$b.$c.$d";

		# Pull long for IP we going to test
		my $ip_long = ip_to_long($ip);
		# Convert mask to longs
		my $mask_long = bits_to_mask($mask);
		my $mask2_long = IPMASK ^ $mask_long;
		# AND with mask to get network addy
		my $network_long = $ip_long & $mask_long;
		# AND with mask2 to get broadcast addy
		my $bcast_long = $ip_long | $mask2_long;

		# Retrun array of data
		my $res = {
				'IP_Long' => $ip_long,
				'IP' => long_to_ip($ip_long),
				'Mask_Long' => $mask_long,
				'Network_Long' => $network_long,
				'Network' => long_to_ip($network_long),
				'Broadcast_Long' => $bcast_long,
				'Broadcast' => long_to_ip($bcast_long),
		};

		return $res;

	} else {
		return undef;
	}
}


1;
# vim: ts=4
