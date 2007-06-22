# Author: Nigel Kukard  <nkukard@lbsd.net>
# Date: 2007-06-21
# Desc: Logging constants


package cbp::logging;

use strict;
use warnings;


# Exporter stuff
require Exporter;
our (@ISA,@EXPORT,@EXPORT_OK);
@ISA = qw(Exporter);
@EXPORT = qw(
	LOG_ERR
	LOG_WARN
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
);
@EXPORT_OK = qw(
);


use constant {
	LOG_ERR		=> 0,
	LOG_WARN	=> 1,
	LOG_NOTICE	=> 2,
	LOG_INFO	=> 3,
	LOG_DEBUG	=> 4
};


1;
# vim: ts=4
