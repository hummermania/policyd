# Caching engine
# Copyright (C) 2007 Nigel Kukard  <nkukard@lbsd.net>
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


package cbp::cache;

use strict;
use warnings;


require Exporter;
our (@ISA,@EXPORT);
@ISA = qw(Exporter);
@EXPORT = qw(
	cacheStoreKeyPair
	cacheGetKeyPair
);

use Cache::FastMmap;

# Cache stuff
my $cache_type = "FastMmap";
my $cache;


# Our current error message
my $error = "";

# Set current error message
# Args: error_message
sub setError
{
	my $err = shift;
	my ($package,$filename,$line) = caller;
	my (undef,undef,undef,$subroutine) = caller(1);

	# Set error
	$error = "$subroutine($line): $err";
}

# Return current error message
# Args: none
sub Error
{
	my $err = $error;

	# Reset error
	$error = "";

	# Return error
	return $err;
}





# Initialize cache
sub Init
{
	my $server = shift;
	my $ch;


	# Create Cache
	$ch = Cache::FastMmap->new(
		'page_size' => 2048,
		'num_pages' => 1000,
		'raw_values' => 1,
		'unlink_on_exit'	=> 1,
	);

	# Stats
	$ch->set('Cache/Stats/Hit',0);
	$ch->set('Cache/Stats/Miss',0);

	# Set server vars
	$server->{'cache_engine'}{'handle'} = $ch;
};

# Destroy cache
sub Destroy
{
	my $server = shift;

};

# Connect child to cache
sub connect
{
	my $server = shift;

	$cache = $server->{'cache_engine'}{'handle'};
}


# Disconnect child from cache
sub disconnect
{
	my $server = shift;

}


# Store keypair in cache
# Parameters:
# 		CacheName	- Name of cache we storing things in
# 		Key			- Item key
# 		Value		- Item value
sub cacheStoreKeyPair
{
	my ($cacheName,$key,$value) = @_;


	if (!defined($cacheName)) {
		setError("Cache name not defined in store");
		return -1;
	}

	if (!defined($key)) {
		setError("Key not defined for cache '$cacheName' store");
		return -1;
	}

	if (!defined($value)) {
		setError("Value not defined for cache '$cacheName' key '$key' store");
		return -1;
	}

	# If we're not caching just return
	return 0 if ($cache_type eq 'none');
	
	# Store
	$cache->set("$cacheName/$key",$value);

	return 0;
}


# Get data from key in cache
# Parameters:
# 		CacheName	- Name of cache we storing things in
# 		Key			- Item key
sub cacheGetKeyPair
{
	my ($cacheName,$key) = @_;

	
	if (!defined($cacheName)) {
		setError("Cache name not defined in get");
		return (-1);
	}

	if (!defined($key)) {
		setError("Key not defined for cache '$cacheName' get");
		return (-1);
	}

	# If we're not caching just return
	if ($cache_type eq 'none') {
		return (0,undef);
	}

	# Check and count
	my $res = $cache->get("$cacheName/$key");
	if ($res) {
		$cache->get_and_set('Cache/Stats/Hit',sub { return ++$_[1]; });
	} else {
		$cache->get_and_set('Cache/Stats/Miss',sub { return ++$_[1]; });
	}

	return (0,$res);
}


# Return cache hit ratio
sub getHitRatio
{
	my $res;


	# Get counter
	$res = $cache->get('Cache/Stats/Hit');

	return $res;
}


# Return cache miss ratio
sub getMissRatio
{
	my $res;


	# Get counter
	$res = $cache->get('Cache/Stats/Miss');

	return $res;
}


1;
# vim: ts=4
