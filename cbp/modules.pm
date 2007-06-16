# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Module support for cluebringer policyd


package cbp::modules;


# Exporter stuff
require Exporter;
our (@ISA,@EXPORT,@EXPORT_OK);
@ISA = qw(Exporter);
@EXPORT = qw(
	logger
);
@EXPORT_OK = qw(
	loadFeature
	loadDBType
	getFeatures
	getDBTypes

	registerFeature
	registerDBType

	setCheckResult
	getCheckResult

	setLogger
);

use Data::Dumper;


# List of features loaded
my @featureList;
# List of database types loaded
my @DBTypeList;

# Logger function
my $logger = sub { shift; print(STDERR @_, "\n"); };
# Module return result
my $result = "";


# Function to register a feature
sub registerFeature {
	my ($feature,$data) = @_;


	# Sanitize first
	if (!defined($data)) {
		&$logger(1,"No feature data for '$feature'!\n");
		return undef;
	} elsif (!$data->{'name'}) {
		&$logger(1,"No feature name given for '$feature'!\n");
		return undef;
	} elsif (!$data->{'check'}) {
		&$logger(1,"No check function to run for feature '$feature'!\n");
		return undef;
	}

	push(@featureList,$data);

	return $data;
}


# Function to register a database type
sub registerDBType {
	my ($dbt,$data) = @_;


	# Sanitize first
	if (!defined($data)) {
		&$logger(1,"No DBType data for '$dbt'!\n");
		return undef;
	} elsif (!$data->{'name'}) {
		&$logger(1,"No DBType name given for '$dbt'!\n");
		return undef;
	} elsif (!$data->{'new'}) {
		&$logger(1,"No new function for DBType '$dbt'!\n");
		return undef;
	}

	push(@DBTypeList,$data);

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
		&$logger(1,"Error loading feature '$feature': $@");

	# Check if we should init
	} elsif (defined($res->{'init'})) {
		$res->{'init'}($server);
	}
}


# Function to load a lookup database type
sub loadDBType {
	my ($ldbt,$server) = @_;

	# Load feature
	my $res = eval("
		use cbp::modules;
		use cbp::database::${ldbt};
		registerDBType(\"$ldb\",\$cbp::database::${ldbt}::pluginInfo);
	");
	# If we got undef, something is wrong
	if (!defined($res)) {
		&$logger(1,"Error loading lookup database type '$ldbt': $@");

	# Check if we should init
	} elsif (defined($res->{'init'})) {
		$res->{'init'}($server);
	}
}


# Return feature list
sub getFeatures {
	return @featureList;
}

# Return database type list
sub getDBTypes {
	return @DBTypeList;
}



# Set logger
sub setLogger {
	$logger = shift;
}

# Log something
sub logger {
	&$logger(@_);
}


# Get status
sub getCheckResult {
	return $result;
}

# Return status from a module
sub setCheckResult {
	$result = shift;
}





1;
# vim: ts=4
