# Database independent layer module
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




package cbp::dbilayer;

use strict;
use warnings;


use cbp::config;
use DBI;



my $internalError = "";


sub internalErr
{
	my $error = $internalError;

	$internalError = "";

	return $error;
}


# Initialize class and return a fully connected object
sub Init
{
	my $server = shift;
	my $dbconfig = $server->{'cbp'}->{'database'};


	# Check if we created
	my $dbh = cbp::dbilayer->new($dbconfig->{'DSN'},$dbconfig->{'Username'},$dbconfig->{'Password'},$dbconfig->{'TablePrefix'});
	return undef if (!defined($dbh));

	return $dbh;
}


# Constructor
sub new
{
	my ($class,$dsn,$username,$password,$table_prefix) = @_;

	# Iternals
	my $self = {
		_dbh => undef,
		_error => undef,

		_dsn => undef,
		_username => undef,
		_password => undef,

		_table_prefix => "",

		_in_transaction => undef,
	};

	# Set database parameters	
	if (defined($dsn)) {
		$self->{_dsn} = $dsn;
		$self->{_username} = $username;
		$self->{_password} = $password;
		$self->{_table_prefix} = $table_prefix if (defined($table_prefix) && $table_prefix ne "");
	} else {
		$internalError = "Invalid DSN given";
		return undef;
	}

	# Create...
	bless $self, $class;
	return $self;
}



# Return current error message
# Args: none
sub Error
{
	my ($self) = @_;

	my $err = $self->{_error};

	# Reset error
	$self->{_error} = "";

	# Return error
	return $err;
}


# Return connection to database
# Args: none
sub connect
{
	my ($self) = @_;


	$self->{_dbh} = DBI->connect($self->{_dsn}, $self->{_username}, $self->{_password}, { 
			'AutoCommit' => 1, 
			'PrintError' => 0,
			'FetchHashKeyName' => 'NAME_lc'
	});

	# Connect to database if we have to, check if we ok
	if (!$self->{_dbh}) {
		$self->{_error} = "Error connecting to database: $DBI::errstr";
		return -1;
	}

	# Apon connect we are not in a transaction
	$self->{_in_transaction} = 0;

	return 0;
}


# Check database connection  
# Args: none
sub _check
{
	my $self = shift;


	# If we not in a transaction try connect
	if ($self->{_in_transaction} == 0) {
		# Try ping
		if (!$self->{_dbh}->ping()) {
			# Disconnect & reconnect
			$self->{_dbh}->disconnect();
			$self->connect(); 
		}
	}
}


# Return database selection results...
# Args: <select statement>
sub select
{
	my ($self,$query,@params) = @_;


	$self->_check();

#	# Build single query instead of using binding of params
#	# not all databases support binding, and not all support all
#	# the places we use ?
#	$query =~ s/\?/%s/g;
#	# Map each element in params to the quoted value
#	$query = sprintf($query,
#		map { $self->quote($_) } @params
#	);
#use Data::Dumper; print STDERR Dumper($query);
	# Prepare query
	my $sth;
	if (!($sth = $self->{_dbh}->prepare($query))) {
		$self->{_error} = $self->{_dbh}->errstr;
		return undef;	
	}

	# Check for execution error
#	if (!$sth->execute()) {
	if (!$sth->execute(@params)) {
		$self->{_error} = $self->{_dbh}->errstr;
		return undef;	
	}

	return $sth;
}


# Perform a command
# Args: <command statement>
sub do
{
	my ($self,$command,@params) = @_;


	$self->_check();

#	# Build single command instead of using binding of params
#	# not all databases support binding, and not all support all
#	# the places we use ?
#	$command =~ s/\?/%s/g;
#	# Map each element in params to the quoted value
#	$command = sprintf($command,
#		map { $self->quote($_) } @params
#	);
#use Data::Dumper; print STDERR Dumper($command);

	# Prepare query
	my $sth;
#	if (!($sth = $self->{_dbh}->do($command))) {
	if (!($sth = $self->{_dbh}->do($command,undef,@params))) {
		$self->{_error} = $self->{_dbh}->errstr;
		return undef;	
	}

	return $sth;
}


# Function to get last insert id
# Args: <table> <column>
sub lastInsertID
{
	my ($self,$table,$column) = @_;


	# Get last insert id
	my $res;
	if (!($res = $self->{_dbh}->last_insert_id(undef,undef,$table,$column))) {
		$self->{_error} = $self->{_dbh}->errstr;
		return undef;	
	}

	return $res;
}


# Function to begin a transaction
# Args: none
sub begin
{
	my ($self) = @_;

	$self->_check();
	
	$self->{_in_transaction}++;

	# Don't really start transaction if we more than 1 deep
	if ($self->{_in_transaction} > 1) {
		return 1;
	}

	# Begin
	my $res;
	if (!($res = $self->{_dbh}->begin_work())) {
		$self->{_error} = $self->{_dbh}->errstr;
		return undef;	
	}
	
	return $res;
}


# Function to commit a transaction
# Args: none
sub commit
{
	my ($self) = @_;

	
	# Reduce level
	$self->{_in_transaction}--;

	# If we not at top level, return success
	if ($self->{_in_transaction} > 0) {
		return 1;
	}

	# Reset transaction depth to 0
	$self->{_in_transaction} = 0;

	# Commit
	my $res;
	if (!($res = $self->{_dbh}->commit())) {
		$self->{_error} = $self->{_dbh}->errstr;
		return undef;	
	}
	
	return $res;
}


# Function to rollback a transaction
# Args: none
sub rollback
{
	my ($self) = @_;


	# If we at top level, return success
	if ($self->{_in_transaction} < 1) {
		return 1;
	}
	
	$self->{_in_transaction} = 0;

	# Rollback
	my $res;
	if (!($res = $self->{_dbh}->rollback())) {
		$self->{_error} = $self->{_dbh}->errstr;
		return undef;	
	}
	
	return $res;
}


# Function to quote a database variable
# Args: <stuff to quote>
sub quote
{
	my ($self,$stuff) = @_;

	return $self->{_dbh}->quote($stuff);
}


# Function to cleanup DB query
# Args: <sth>
sub free
{
	my ($self,$sth) = @_;


	if ($sth) {
		$sth->finish();
	}	
}


# Function to return the table prefix
sub table_prefix
{
	my $self = shift;

	return $self->{_table_prefix};
}




1;
# vim: ts=4
