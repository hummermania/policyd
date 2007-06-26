# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: DBI Lookup Database Type


package cbp::database::dbi;

use strict;
use warnings;

use cbp::logging;
use cbp::modules;

use DBI;
use Data::Dumper;



# User plugin info
our $pluginInfo = {
	name 	=> "DBI Lookup Database Type",
	type	=> "dbi",
	init	=> \&init,
	new		=> sub { cbp::database::dbi->new(@_) },
};

# Our config
my %config;


# Initialize
sub init {
	my $server = shift;
	my $ini = $server->{'inifile'};

	return 0;
}


# Constructor
sub new {
	my ($class,$server,$name) = @_;
	my $ini = $server->{'inifile'};


	my $self = {
		_dbh   => undef,
		_dsn   => undef,
	};

	# Database connection info
	$self->{'_dsn'} = $ini->val("database $name",'dsn');
	my $username = $ini->val("database $name",'username');
	my $password = $ini->val("database $name",'password');

	# Connect to database
	$self->{'_dbh'} = DBI->connect($self->{'_dsn'}, $username, $password, {
			'AutoCommit' => 1, 
			'PrintError' => 0 
	});
	# Check for error	
	if (!$self->{'_dbh'}) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to connect to '".$self->{'_dsn'}."': $DBI::errstr");
	}

	bless $self, $class;
	return $self;
}


# Close down
sub close {
	my $self = shift;

	$self->{'_dbh'}->disconnect();
	logger(LOG_ERR,"[DATABASE/DBI] Closing '".$self->{'_dsn'}."'");
}



# Function to see if we ok
sub getStatus {
	my $self = shift;


	return $self->{'_dbh'} ? 0 : -1;
}


# Do a lookup
sub lookup {
	my ($self,$query) = @_;

	# Prepare statement
	my $sth = $self->{'_dbh'}->prepare($query);
	if (!$sth) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to prepare statement '$query': ".$self->{'_dbh'}->errstr);
		return -1;
	}

	# Execute
	my $res = $sth->execute();
	if (!$res) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to execute statement: '$query': ".$self->{'_dbh'}->errstr);
		return -1;
	}

	# Setup results
	my @results;
	while (my $item = $sth->fetchrow_hashref()) {
		push(@results,$item);
	}

	# Finish off
	$sth->finish();

	logger(LOG_DEBUG,"[DATABASE/DBI] LOOKUP Results: ".Dumper(\@results));
	return \@results;
}


# Store something
sub store {
	my ($self,$query) = @_;


	# Prepare statement
	my $sth = $self->{'_dbh'}->prepare($query);
	if (!$sth) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to prepare statement '$query': ".$self->{'_dbh'}->errstr);
		return -1;
	}

	# Execute
	my $res = $sth->execute();
	if (!$res) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to execute statement: '$query': ".$self->{'_dbh'}->errstr);
		return -1;
	}

	# Finish off
	$sth->finish();

	logger(LOG_DEBUG,"[DATABASE/DBI] STORE Results: $res");

	return $res;
}


# Update something
sub update {
	my ($self,$query) = @_;


	# Prepare statement
	my $sth = $self->{'_dbh'}->prepare($query);
	if (!$sth) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to prepare statement '$query': ".$self->{'_dbh'}->errstr);
		return -1;
	}

	# Execute
	my $res = $sth->execute();
	if (!$res) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to execute statement: '$query': ".$self->{'_dbh'}->errstr);
		return -1;
	}

	# Finish off
	$sth->finish();

	logger(LOG_DEBUG,"[DATABASE/DBI] UPDATE Results: $res");

	return $res;
}


# Remove something
sub remove {
	my ($self,$query) = @_;


	# Prepare statement
	my $sth = $self->{'_dbh'}->prepare($query);
	if (!$sth) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to prepare statement '$query': ".$self->{'_dbh'}->errstr);
		return -1;
	}

	# Execute
	my $res = $sth->execute();
	if (!$res) {
		logger(LOG_ERR,"[DATABASE/DBI] Failed to execute statement: '$query': ".$self->{'_dbh'}->errstr);
		return -1;
	}

	# Finish off
	$sth->finish();

	logger(LOG_DEBUG,"[DATABASE/DBI] REMOVE Results: $res");

	return $res;
}


# Quote something
sub quote {
	my ($self,$string) = @_;
	return $self->{'_dbh'}->quote($string);
}



1;
# vim: ts=4
