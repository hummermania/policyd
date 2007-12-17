# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Module support for cluebringer policyd


package cbp::modules;

use strict;
use warnings;

# Exporter stuff
require Exporter;
our (@ISA,@EXPORT,@EXPORT_OK);
@ISA = qw(Exporter);
@EXPORT = qw(
	logger
);
@EXPORT_OK = qw(
	loadFeature
	registerFeature
	getFeatures

	loadDatabase
	registerDatabase
	getDatabases

	setLogger
);

use cbp::logging;
use Data::Dumper;


# List of features loaded
my @featureList;
# List of database types loaded
my @databaseList;

# Logger function
my $logger = sub { shift; print(STDERR @_, "\n"); };
# Module return result
my $result = "";


# Function to register a feature
sub registerFeature {
	my ($feature,$data) = @_;


	# Sanitize first
	if (!defined($data)) {
		&$logger(LOG_ERR,"No feature data for '$feature'!\n");
		return undef;
	} elsif (!$data->{'name'}) {
		&$logger(LOG_ERR,"No feature name given for '$feature'!\n");
		return undef;
	} elsif (!$data->{'check'}) {
		&$logger(LOG_ERR,"No check function to run for feature '$feature'!\n");
		return undef;
	}

	push(@featureList,$data);

	return $data;
}


# Function to register a database type
sub registerDatabase {
	my ($dbt,$data) = @_;


	# Sanitize first
	if (!defined($data)) {
		&$logger(LOG_ERR,"No database data for '$dbt'!\n");
		return undef;
	} elsif (!$data->{'name'}) {
		&$logger(LOG_ERR,"No database name given for '$dbt'!\n");
		return undef;
	} elsif (!$data->{'new'}) {
		&$logger(LOG_ERR,"No new function for database '$dbt'!\n");
		return undef;
	}

	push(@databaseList,$data);

	return $data;
}


# Function to load a feature
sub loadFeature {
	my ($feature,$server) = @_;

	# Load feature
	my $res = eval("
		use cbp::modules;
		use cbp::feature::${feature};
		registerFeature(\"$feature\",\$cbp::feature::${feature}::pluginInfo);
	");
	# If we got undef, something is wrong
	if (!defined($res)) {
		&$logger(LOG_ERR,"Error loading feature '$feature': $@");

	# Check if we should run the load function
	} elsif (defined($res->{'load'})) {
		$res->{'load'}($server);
	}
}


# Function to load a lookup database type
sub loadDatabase {
	my ($ldbt,$server) = @_;

	# Load feature
	my $res = eval("
		use cbp::modules;
		use cbp::database::${ldbt};
		registerDatabase(\"$ldbt\",\$cbp::database::${ldbt}::pluginInfo);
	");
	# If we got undef, something is wrong
	if (!defined($res)) {
		&$logger(LOG_ERR,"Error loading lookup database type '$ldbt': $@");

	# Check if we should run the load function
	} elsif (defined($res->{'load'})) {
		$res->{'load'}($server);
	}
}


# Return feature list
sub getFeatures {
	return @featureList;
}

# Return database type list
sub getDatabases {
	return @databaseList;
}



# Set logger
sub setLogger {
	$logger = shift;
}

# Log something
sub logger {
	&$logger(@_);
}


1;
# vim: ts=4
