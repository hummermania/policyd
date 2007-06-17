# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-08
# Desc: DBI Lookup Database Type


package cbp::database::dbi;

use strict;
use warnings;

use cbp::modules;

use Data::Dumper;



# User plugin info
our $pluginInfo = {
	name 	=> "DBI Lookup Database Type",
	type	=> "dbi",
	new		=> sub { cbp::database::dbi->new(@_) },
};


#constructor
sub new {
	my ($class,$server,$name) = @_;
	my $ini = $server->{'inifile'};


	my $self = {
		_address   => undef
	};

	my $dsn = $ini->val("database $name",'dsn');

	logger(2,"NEW $class with DSN $dsn");

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
