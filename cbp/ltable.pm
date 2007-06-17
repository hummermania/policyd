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
		_backend => undef,
		_query_template => undef,
		_update_template => undef,
		_insert_template => undef,
	};

	my $dbname = $ini->val("table $table",'database');

	# Use existing databae handle
	if (defined($databases{$dbname})) {
		logger(3,"Using existing database $dbname for $table.");
		$self->{'_backend'} = $databases{$dbname};	
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
				my $handle = $db->{'new'}($server,$dbname);
				$databases{$dbname} = $handle;
				# Use it
				$self->{'_backend'} = $handle;
				last;
			}
		}
	}

	# Setup queryies
	foreach my $i ("query","update","insert") {
		my $template = $ini->val("table $table",$i);
		# If we have a template defined, clean it up a bit
		if (defined($template)) {
			($self->{"_${i}_template"} = $template) =~ s/(\n|[[:cntrl:]])+/ /g;
		}
	}

	bless $self, $class;
	return $self;
}


# Lookup function to dispatch to database
sub lookup {
	my ($self,$params) = @_;

	# Do lookup
	my $res = $self->{'_backend'}->lookup(
			$self->prepare($self->{'_query_template'},$params)
	);

	return $res;
}


# Store function to dispatch to database
sub store {
	my ($self,$mode,$params) = @_;


	# Do insert
	my $res = $self->{'_backend'}->store(
			$self->prepare($self->{'_insert_template'},$params)
	);

	return $res;
}


# Prepare a query to the backend
sub prepare {
	my ($self,$template,$params) = @_;

	# Parse in params into template
	my $query = $template;
	foreach my $macro (%{$params}) {
		my $val = $self->{'_backend'}->quote(defined($params->{$macro}) ? $params->{$macro} : "");
		$query =~ s/%$macro%/$val/g;
	}

	return $query;
}



1;
# vim: ts=4
