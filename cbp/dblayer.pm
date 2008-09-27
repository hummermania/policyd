# Common database layer module
# Copyright (C) 2005-2007 Nigel Kukard  <nkukard@lbsd.net>
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



package cbp::dblayer;

use strict;
use warnings;

# Exporter stuff
require Exporter;
our (@ISA,@EXPORT);
@ISA = qw(Exporter);
@EXPORT = qw(
	DBConnect
	DBSelect
	DBDo
	DBLastInsertID
	DBBegin
	DBCommit
	DBRollback
	DBQuote
	DBFreeRes
	
	DBSelectNumResults

	hashifyLCtoMC
);



use cbp::config;

use cbp::dbilayer;


# Database handle
my $dbh = undef;

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



# Initialize database handle
# Args: <database handle>
sub setHandle
{
		my $handle = shift;

		$dbh = $handle;
}


# Return database selection results...
# Args: <select statement>
sub DBSelect
{
	my ($query,@params) = @_;


	my $table_prefix = $dbh->table_prefix();

	# Replace table prefix macro
	$query =~ s/\@TP\@/$table_prefix/g;

	# Prepare query
	my $sth;
	if (!($sth = $dbh->select($query,@params))) {
		setError("Error executing select '$query': ".$dbh->Error());
		return undef;	
	}

	return $sth;
}


# Perform a command
# Args: <command statement>
sub DBDo
{
	my ($command,@params) = @_;


	my $table_prefix = $dbh->table_prefix();

	# Replace table prefix macro
	$command =~ s/\@TP\@/$table_prefix/g;

	# Prepare query
	my $sth;
	if (!($sth = $dbh->do($command,@params))) {
		setError("Error executing command '$command': ".$dbh->Error());
		return undef;	
	}

	return $sth;
}


# Function to get last insert id
# Args: <table> <column>
sub DBLastInsertID
{
	my ($table,$column) = @_;


	my $res;
	if (!($res = $dbh->lastInsertID(undef,undef,$table,$column))) {
		setError("Error getting last inserted id: ".$dbh->Error());
		return undef;	
	}

	return $res;
}


# Function to begin a transaction
# Args: none
sub DBBegin
{
	my $res;
	if (!($res = $dbh->begin())) {
		setError("Error beginning transaction: ".$dbh->Error());
		return undef;	
	}

	return $res;
}


# Function to commit a transaction
# Args: none
sub DBCommit
{
	my $res;
	if (!($res = $dbh->commit())) {
		setError("Error committing transaction: ".$dbh->Error());
		return undef;	
	}

	return $res;
}


# Function to rollback a transaction
# Args: none
sub DBRollback
{
	my $res;
	if (!($res = $dbh->rollback())) {
		setError("Error rolling back transaction: ".$dbh->Error());
		return undef;	
	}

	return $res;
}


# Function to quote a database variable
# Args: <stuff to quote>
sub DBQuote
{
	my $stuff = shift;


	return $dbh->quote($stuff);
}


# Function to cleanup DB query
# Args: <sth>
sub DBFreeRes
{
	my $sth = shift;


	if ($sth) {
		$sth->finish();
	}	
}



#
# Value Added Functions
#


# Function to get table prefix
sub DBTablePrefix
{
	return $dbh->table_prefix();
}



# Return how many results came up from the specific SELECT query
# Args: <select statement>
sub DBSelectNumResults
{
	my $query = shift;


	# Prepare query
	my $sth;
	if (!($sth = $dbh->select("SELECT COUNT(*) AS num_results $query"))) {
		setError("Error executing select: ".$dbh->Error());
		return undef;	
	}

	# Grab row
	my $row = $sth->fetchrow_hashref();
	if (!defined($row)) {
		setError("Failed to get results from a select: ".$dbh->Error());
		return undef;
	}	

	# Pull number
	my $num_results = $row->{'num_results'};
	$sth->finish();

	return $num_results;
}


# Convert a lower case array to mixed case
sub hashifyLCtoMC
{
	my ($record,@entries) = @_;


	# If we undefined, return
	return undef if (!defined($record));

	my $res;

	# Loop with each item, assign from lowecase database record to our result
	foreach my $entry (@entries) {
		$res->{$entry} = $record->{lc($entry)};
	}

	return $res;
}





1;
# vim: ts=4
