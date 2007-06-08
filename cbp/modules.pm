# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Module support for cluebringer policyd


package cbp::modules;

# Exporter stuff
require Exporter;
our (@ISA,@EXPORT,@EXPORT_OK);
@ISA = qw(Exporter);
@EXPORT = qw(
	setCheckResult
	getCheckResult
);
@EXPORT_OK = qw(
	loadModule
	getModules
	setLogger

	registerModule
);

# List of modules loaded
my @moduleList;
# Logger function
my $logger = sub { shift; print(STDERR @_, "\n"); };
# Module return result
my $result = "";


# Function to register a module
sub registerModule {
	my ($module,$data) = @_;


	# Sanitize first
	if (!defined($data)) {
		&$logger(3,"No module data for '$module'!\n");
		return -1;
	} elsif (!$data->{'name'}) {
		&$logger(3,"No module name given for '$module'!\n");
		return -1;
	} elsif (!$data->{'check'}) {
		&$logger(3,"No function to run for module '$module'!\n");
		return -1;
	}

	push(@moduleList,$data);

	return 0;
}


# Function to load a module
sub loadModule {
	my $module = shift;

	# Load module
	my $res = eval("
		use cbp::$module qw(registerModule);
		registerModule(\"$module\",\$cbp::${module}::pluginInfo);
	");

	if (!defined($res) || $res != 0) {
		&$logger(3,"Error loading module '$module':\n$@");
	}
}


# Return module list
sub getModules {
	return @moduleList;
}


# Set logger
sub setLogger {
	$logger = shift;
}


# Get status
sub getCheckResult {
	return $status;
}

# Return status from a module
sub setCheckResult {
	$status = shift;
}





1;
# vim: ts=4
