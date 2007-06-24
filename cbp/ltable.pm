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

	LTABLE_UPDATE_ON_CONFLICT
);
@EXPORT_OK = qw(
);
use constant {
	LTABLE_UPDATE_ON_CONFLICT		=> 1,
};


# Stuff we need
use cbp::modules qw(
	logger

	getDatabases
);
use cbp::logging;
use Data::Dumper;


# Database handles
my %databases;


# Constructor
sub new {
	my ($class,$server,$table) = @_;
	my $ini = $server->{'inifile'};


	my $self = {
		_name => $table,
		_backend => undef,
		_dbname => undef,
		_query_template => undef,
		_update_template => undef,
		_insert_template => undef,
	};

	my $dbname = $ini->val("table $table",'database');
	$self->{'_dbname'} = $dbname;

	# Use existing databae handle
	if (defined($databases{$dbname})) {
		logger(LOG_INFO,"[LTABLE] Using existing database $dbname for $table.");
		$self->{'_backend'} = $databases{$dbname};	
	# Create new database handle
	} else {
		# Grab db types
		my @dbs = getDatabases();
		# Get database type
		my $dbtype = $ini->val("database $dbname",'type');
		logger(LOG_INFO,"[LTABLE] Using new database $dbname/$dbtype for $table.");
		# Loop with them
		foreach my $db (@dbs) {
			# Check for match
			if ($dbtype eq $db->{'type'}) {
				# Create database handle
				my $handle = $db->{'new'}($server,$dbname);
				# Check status
				if ($handle->getStatus() == 0) {
					$databases{$dbname} = $self->{'_backend'} = $handle;
					last;
				}
			}
		}
	}

	# Return undef if we had a fuckup above
	if (!$self->{'_backend'}) {
		return undef;
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


# Close down
sub close {
	my $self = shift;
	
	if (defined($databases{$self->{'_dbname'}})) {
		logger(LOG_INFO,"[LTABLE] Closing table ".$self->{'_dbname'}."/".$self->{'_name'});
		$self->{'_backend'}->close();
		delete($databases{$self->{'_dbname'}});
	}
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

	my $res;

	# Try update, if we get 0, insert
	if ($mode == LTABLE_UPDATE_ON_CONFLICT) {
		$res = $self->update($params);
		if ($res == 0) {
			logger(LOG_INFO,"[LTABLE] Nothing updated, we must insert");
			# Do insert
			my $res = $self->{'_backend'}->store(
				$self->prepare($self->{'_insert_template'},$params)
			);
		} else {
			logger(LOG_NOTICE,"[LTABLE] Updated $res records");
		}
	} else {
		logger(LOG_INFO,"[LTABLE] We must insert");
		# Do insert
		my $res = $self->{'_backend'}->store(
				$self->prepare($self->{'_insert_template'},$params)
		);
	}


	return $res;
}


# Update function to dispatch to database
sub update {
	my ($self,$params) = @_;


	# Do update
	my $res = $self->{'_backend'}->update(
			$self->prepare($self->{'_update_template'},$params)
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


# Return our name
sub name {
	my ($self) = @_;

	return $self->{'_name'};
}


# Return status
sub getStatus {
	my ($self) = @_;

	return $self->{'_backend'}->getStatus();
}


1;
# vim: ts=4
