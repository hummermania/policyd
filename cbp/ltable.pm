# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: Table support for cluebringer


package cbp::ltable;

use strict;
use warnings;

# Exporter stuff
require Exporter;
our (@ISA,@EXPORT,@EXPORT_OK);
@ISA = qw(Exporter);
@EXPORT = qw(
	loadTable

	KEY_UPDATE_ON_CONFLICT
);
@EXPORT_OK = qw(
);


# Stuff we need
use cbp::modules qw(
	logger

	getDBTypes
);

use constant {
	KEY_UPDATE_ON_CONFLICT		=> 1,
};

use Data::Dumper;


# Database handles
my %databases;


# Constructor
sub new {
	my ($class,$server,$table) = @_;
	my $ini = $server->{'inifile'};


	my $self = {
		_dbh => undef,
		_query_template => undef,
		_update_template => undef,
		_insert_template => undef,
	};

	my $dbname = $ini->val("table $table",'database');

	# Use existing databae handle
	if (defined($databases{$dbname})) {
		logger(3,"Using existing database $dbname for $table.");
		$self->{'_dbh'} = $databases{$dbname};	
	# Create new database handle
	} else {
		# Grab db types
		my @dbTypes = getDBTypes();
		# Get database type
		my $dbtype = $ini->val("database $dbname",'type');
		logger(3,"Using new database $dbname/$dbtype for $table.");
		# Loop with them
		foreach my $db (@dbTypes) {
			# Check for match
			if ($dbtype eq $db->{'type'}) {
				# Create database handle
				my $dbh = $db->{'new'}($server,$dbname);
				$databases{$dbname} = $dbh;
				# Use it
				$self->{'_dbh'} = $dbh;
				last;
			}
		}
	}

	# Setup queryies
	my $query = $ini->val("table $table",'query');
	$self->{'_query_template'} = $query if (defined($query));
	my $update = $ini->val("table $table",'update');
	$self->{'_update_template'} = $update if (defined($update));
	my $insert = $ini->val("table $table",'insert');
	$self->{'_insert_template'} = $insert if (defined($insert));

	bless $self, $class;
	return $self;
}


# Lookup function to dispatch to database
sub lookup {
	my ($self,$params) = @_;

	logger(2,"Lookup: ".Dumper($params));
}


1;
# vim: ts=4
