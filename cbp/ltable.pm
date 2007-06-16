# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Lookup table support for cluebringer


package cbp::ltable;


# Exporter stuff
require Exporter;
our (@ISA,@EXPORT,@EXPORT_OK);
@ISA = qw(Exporter);
@EXPORT = qw(
	loadTable

	keyLookup
	keyStore

	KEY_UPDATE_ON_CONFLICT
);
@EXPORT_OK = qw(
);

use cbp::modules;
use Data::Dumper;

# Constants
use constant {
	KEY_UPDATE		=> 1,
};



# Lookup function
sub keyLookup {
	my ($key,$values) = @_;


#	get
	logger(3,"Lookup key:");
	logger(3,Dumper($values));
}


# Lookup function
sub keyStore {
	my ($key,$mode,$values) = @_;

	logger(3,"Storing key:");
	logger(3,Dumper($values));
}


# Load a lookup table
sub loadTable {
	my ($server,$table) = @_;
	my $ini = $server->{'inifile'};


	my $provider = $ini->val("table $table",'provider');

	logger(3,"Provider: $provider");
	
	# GET LIST OF DATABASE TYPES, create new object of the one we need

	# Initialize its query strings
}




1;
# vim: ts=4
