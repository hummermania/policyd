# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: DBI Lookup Database Type


package cbp::database::dbi;

use cbp::modules;
use Data::Dumper;



# User plugin info
our $pluginInfo = {
	name 	=> "DBI Lookup Database Type",
	type	=> "dbi",
	new		=> \&new,
};


#constructor
sub new {
	my ($class) = @_;

	my $self = {
		_address   => undef
	};


	bless $self, $class;
	return $self;
}


sub lookup {
	my ($self,$hash) = @_;


	logger(4,"LOOKUP: ".Dumper($hash));
	return 1;
}


sub update {
}



1;
# vim: ts=4
