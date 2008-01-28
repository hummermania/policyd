# Cluebringer policy support for amavisd-new
# Copyright (C) 2008, LinuxRulz
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


package Amavis::Custom;
use strict;

use lib('/root/cluebringer-trunk');


my $DB_dsn = "DBI:SQLite:dbname=/tmp/cluebringer.sqlite";
my $DB_user = "";
my $DB_pass = "";


# This is the amavis policy options we can use
my %policyOptions = (
	'boolean' =>  [ qw(
			bypass_virus_checks
			bypass_banned_checks
			bypass_spam_checks
			bypass_header_checks
			
			spam_modifies_subject
	) ],

	'float' => [ qw(
			spam_tag_level
			spam_tag2_level
			spam_tag3_level
			spam_kill_level
			spam_dsn_cutoff_level
			spam_quarantine_cutoff_level
	) ],

	'text' => [ qw(
			spam_tag_subject
			spam_tag2_subject
			spam_tag3_subject
			
			quarantine_virus
			quarantine_banned_file
			quarantine_bad_header
			quarantine_spam
	) ],

	'integer' => [ qw(
			max_message_size
	) ],

	'textlist' => [ qw(
			banned_files

			sender_whitelist
			sender_blacklist

			notify_admin_newvirus
			notify_admin_virus
			notify_admin_spam
			notify_admin_banned_file
			notify_admin_bad_header
	) ],
);




BEGIN {
	import Amavis::Util qw(do_log);

	# Use cluebringer modules
	use cbp::config;
	use cbp::dblayer;
	use cbp::policies;
}



sub new {
	my($class,$conn,$msginfo) = @_;
	my($self) = bless {}, $class;

	# Forge configuration
	$self->{'inifile'}{'database'}{'dsn'} = $DB_dsn;
	$self->{'inifile'}{'database'}{'username'} = $DB_user;
	$self->{'inifile'}{'database'}{'password'} = $DB_pass;
	cbp::config::Init($self);

	# Connect to database
	if (!($self->{'dbh'} = DBConnect())) {
		do_log(-1,"policyd/dbconnect: Failed to connect to database '%s'",cbp::dblayer::Error());
		return undef;
	}

	cbp::dblayer::setHandle($self->{'dbh'});

	return $self;
}



sub process_policy {
	my($self,$conn,$msginfo,$pbn) = @_;
  	do_log(-2,"CUSTOM: process_policy");
  	do_log(-2,"CUSTOM: done process_policy");

	# Loop with recipients
    foreach my $r (@{$msginfo->per_recip_data}) {

		# Pull policy
		my $res = getPolicy($msginfo->client_addr,$msginfo->sender,$r->recip_addr);
		if (!$res) {
			db_log(-1,"policyd/process_policy: Failed to get policy for triplet [%s,%s,%s]",$msginfo->client_addr,$msginfo->sender,$r->recip_addr);
			next;
		}

		# Start with a blank policy
		my %amavisPolicy = ();


		# Loop with priorities
		foreach my $priority (sort {$b <=> $a} keys %{$res}) {
					
			do_log(-2,"CUSTOM POLICY priority $priority");

			# Loop with policies
			foreach my $policyID (@{$res->{$priority}}) {
					do_log(-2,"CUSTOM POLICY   => policy $policyID");

					# Grab amavis policyID
					my $amavisDBPolicy = $self->getAmavisPolicy($policyID);
	
					# If no amavis policyID, next...
					if (!$amavisDBPolicy) {
						do_log(-2,"CUSTOM POLICY no amavis policy for ID '$policyID'");
						next;
					}


					use Data::Dumper;
					do_log(-2,"CUSTOM POLICY for (%s;%s;%s)",$msginfo->client_addr,$msginfo->sender,$r->recip_addr);
					do_log(-2,"CUSTOM POLICY dump: ".Dumper($amavisDBPolicy));

					# Loop with variable types
					foreach my $vartype (keys %policyOptions) {

							do_log(-2,"CUSTOM POLICY     => ".Dumper($vartype));

						# _m - 0 (ignore)
						# _m - 1 (inherit)
						# _m - 2 (merge)
						# _m - 3 (overwrite)


						# Start with checking booleans
						if ($vartype eq "boolean") {

							# Loop with variables
							foreach my $varname (@{$policyOptions{$vartype}}) {
								do_log(-2,"CUSTOM POLICY: boolean     => $varname");

								# We ignore state 0, which is ignore/inherit
								if ($amavisDBPolicy->{$varname."_m"} eq "0") {

								# Mode 2 is overwrite
								} elsif ($amavisDBPolicy->{$varname."_m"} eq "2") {
									$amavisPolicy{$varname} = $amavisDBPolicy->{$varname};

								# All other modes including mode 1 (merge) is invalid
								} else {
									do_log(0,"policyd/process_policy: Mode '%s' for amavis policy '%s' variable '%s'  is invalid as its a boolean",
											$amavisDBPolicy->{$varname."_m"},$policyID,$varname);
								}
							}

						# Floats
						} elsif ($vartype eq "float") {
							# Loop with variables
							foreach my $varname (@{$policyOptions{$vartype}}) {
								do_log(-2,"CUSTOM POLICY: float     => $varname");

								# We ignore state 0, which is ignore/inherit
								if ($amavisDBPolicy->{$varname."_m"} eq "0") {

								# Mode 2 is overwrite
								} elsif ($amavisDBPolicy->{$varname."_m"} eq "2") {
									$amavisPolicy{$varname} = $amavisDBPolicy->{$varname};

								# All other modes including mode 1 (merge) is invalid
								} else {
									do_log(0,"policyd/process_policy: Mode '%s' for amavis policy '%s' variable '%s'  is invalid as its a float",
											$amavisDBPolicy->{$varname."_m"},$policyID,$varname);
								}
							}

						# Text
						} elsif ($vartype eq "text") {
							# Loop with variables
							foreach my $varname (@{$policyOptions{$vartype}}) {
								do_log(-2,"CUSTOM POLICY: text     => $varname");

								# We ignore state 0, which is ignore/inherit
								if ($amavisDBPolicy->{$varname."_m"} eq "0") {

								# Mode 2 is overwrite
								} elsif ($amavisDBPolicy->{$varname."_m"} eq "2") {
									$amavisPolicy{$varname} = $amavisDBPolicy->{$varname};

								# All other modes including mode 1 (merge) is invalid
								} else {
									do_log(0,"policyd/process_policy: Mode '%s' for amavis policy '%s' variable '%s'  is invalid as its a text",
											$amavisDBPolicy->{$varname."_m"},$policyID,$varname);
								}
							}

						# Integers
						} elsif ($vartype eq "integer") {
							# Loop with variables
							foreach my $varname (@{$policyOptions{$vartype}}) {
								do_log(-2,"CUSTOM POLICY: integer     => $varname");

								# We ignore state 0, which is ignore/inherit
								if ($amavisDBPolicy->{$varname."_m"} eq "0") {

								# Mode 2 is overwrite
								} elsif ($amavisDBPolicy->{$varname."_m"} eq "2") {
									$amavisPolicy{$varname} = $amavisDBPolicy->{$varname};

								# All other modes including mode 1 (merge) is invalid
								} else {
									do_log(0,"policyd/process_policy: Mode '%s' for amavis policy '%s' variable '%s'  is invalid as its a integer",
											$amavisDBPolicy->{$varname."_m"},$policyID,$varname);
								}
							}

						# Text list (array)
						} elsif ($vartype eq "textlist") {
							# Loop with variables
							foreach my $varname (@{$policyOptions{$vartype}}) {
								do_log(-2,"CUSTOM POLICY: integer     => $varname");

								# We ignore state 0, which is ignore/inherit
								if ($amavisDBPolicy->{$varname."_m"} eq "0") {

								# Mode 1 is merge
								} elsif ($amavisDBPolicy->{$varname."_m"} eq "1") {
									my @items = split /,/, $amavisDBPolicy->{$varname};

									# If we already have a list, add to end of it
									if (defined($amavisDBPolicy->{$varname})) {
										push(@items,@{$amavisDBPolicy->{$varname}});
									}

									# Loop and get unique
									my %uniqItems = ();
									foreach my $item (@items) {
										$uniqItems{$item} = 1;
									}

									# Only store the key list we have
									$amavisPolicy{$varname} = keys %uniqItems;


								# Mode 2 is overwrite
								} elsif ($amavisDBPolicy->{$varname."_m"} eq "2") {
									$amavisPolicy{$varname} = $amavisDBPolicy->{$varname};

								# All other modes including mode 1 (merge) is invalid
								} else {
									do_log(0,"policyd/process_policy: Mode '%s' for amavis policy '%s' variable '%s'  is invalid as its a text list",
											$amavisDBPolicy->{$varname."_m"},$policyID,$varname);
								}
							}

						}

					}
			}
		}

		do_log(-2,"CUSTOM AMAVIS POLICY     => ".Dumper(\%amavisPolicy));

		# Check bypass
		#
		# Bypass will bypass the check if no other recip needs to be checked, lover means we will
		# send to the recip regardless of the result

		# Check for virus bypass
		if (defined($amavisPolicy{'bypass_virus_checks'})) {
			push(@{$pbn->{'bypass_virus_checks_maps'}},\{
					$r->recip_addr	=> 1
			});
			push(@{$pbn->{'virus_lovers_maps'}},\{
					$r->recip_addr	=> 1
			});
		}
		# Check for banned file/filetype bypass
		if (defined($amavisPolicy{'bypass_banned_checks'})) {
			push(@{$pbn->{'bypass_banned_checks_maps'}},\{
					$r->recip_addr	=> 1
			});
			push(@{$pbn->{'banned_files_lovers_maps'}},\{
					$r->recip_addr	=> 1
			});
		}
		# Check for spam bypass
		if (defined($amavisPolicy{'bypass_spam_checks'})) {
			push(@{$pbn->{'bypass_spam_checks_maps'}},\{
					$r->recip_addr	=> 1
			});
			push(@{$pbn->{'spam_lovers_maps'}},\{
					$r->recip_addr	=> 1
			});
		}
		# Check for header bypass
		if (defined($amavisPolicy{'bypass_header_checks'})) {
			push(@{$pbn->{'bypass_header_checks_maps'}},\{
					$r->recip_addr	=> 1
			});
			push(@{$pbn->{'bad_header_lovers_maps'}},\{
					$r->recip_addr	=> 1
			});
		}

		# Spam levels

		# Check if we have a tag level
		if (defined($amavisPolicy{'spam_tag_level'})) {
			push(@{$pbn->{'spam_tag_level_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_tag_level'}
			});
		}

		# Check if we have a tag2 level
		if (defined($amavisPolicy{'spam_tag2_level'})) {
			push(@{$pbn->{'spam_tag2_level_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_tag2_level'}
			});
		}

		# Check if we have a tag3 level
		if (defined($amavisPolicy{'spam_tag3_level'})) {
			push(@{$pbn->{'spam_tag3_level_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_tag3_level'}
			});
		}

		# Check if we have a kill level
		if (defined($amavisPolicy{'spam_kill_level'})) {
			push(@{$pbn->{'spam_kill_level_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_kill_level'}
			});
		}

		# Check if we have a dsn_cutoff level
		if (defined($amavisPolicy{'spam_dsn_cutoff_level'})) {
			push(@{$pbn->{'spam_dsn_cutoff_level_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_dsn_cutoff_level'}
			});
		}

		# Check if we have a quarantine_cutoff level
		if (defined($amavisPolicy{'spam_quarantine_cutoff_level'})) {
			push(@{$pbn->{'spam_quarantine_cutoff_level_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_quarantine_cutoff_level'}
			});
		}


		# Spam subject stuff

		# Check for spam modifies subject
		if (defined($amavisPolicy{'spam_modifies_subject'})) {
			push(@{$pbn->{'spam_modifies_subj_maps'}},\{
					$r->recip_addr	=> 1
			});
		}

		# Check for spam tag subject
		if (defined($amavisPolicy{'spam_tag_subject'})) {
			push(@{$pbn->{'spam_subject_tag_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_tag_subject'}
			});
		}

		# Check for spam tag2 subject
		if (defined($amavisPolicy{'spam_tag2_subject'})) {
			push(@{$pbn->{'spam_subject_tag2_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_tag2_subject'}
			});
		}

		# Check for spam tag3 subject
		if (defined($amavisPolicy{'spam_tag3_subject'})) {
			push(@{$pbn->{'spam_subject_tag3_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'spam_tag3_subject'}
			});
		}

		# General checks

		# Check if we have a message size limit, if so push it in
		if (defined($amavisPolicy{'max_message_size'})) {
			push(@{$pbn->{'message_size_limit_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'max_message_size'}
			});
		}

		# FIXME
		# Check if we have a list of banned files
		if (defined($amavisPolicy{'banned_files'})) {
#			push(@{$pbn->{'banned_filename_maps'}},\{
#					$r->recip_addr	=> $amavisPolicy{'banned_files'}
#			});
		}


		# Whitelist & blacklist
		
		# Check if we have a list of sender whitelists
		if (defined($amavisPolicy{'sender_whitelist'})) {
			push(@{$pbn->{'per_recip_whitelist_sender_lookup_tables'}},\{
					$r->recip_addr	=> $amavisPolicy{'sender_whitelist'}
			});
		}
		
		# Check if we have a list of sender blacklists
		if (defined($amavisPolicy{'sender_blacklist'})) {
			push(@{$pbn->{'per_recip_blacklist_sender_lookup_tables'}},\{
					$r->recip_addr	=> $amavisPolicy{'sender_blacklist'}
			});
		}


		# Admin notifications
		
		# Check if we have a list of new virus admins
		if (defined($amavisPolicy{'notify_admin_newvirus'})) {
			push(@{$pbn->{'newvirus_admin_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'notify_admin_newvirus'}
			});
		}
		
		# Check if we have a list of virus admins
		if (defined($amavisPolicy{'notify_admin_virus'})) {
			push(@{$pbn->{'virus_admin_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'notify_admin_virus'}
			});
		}
		
		# Check if we have a list of spam admins
		if (defined($amavisPolicy{'notify_admin_spam'})) {
			push(@{$pbn->{'spam_admin_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'notify_admin_spam'}
			});
		}
		
		# Check if we have a list of banned file admins
		if (defined($amavisPolicy{'notify_admin_banned_file'})) {
			push(@{$pbn->{'banned_admin_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'notify_admin_banned_file'}
			});
		}
		
		# Check if we have a list of bad header admins
		if (defined($amavisPolicy{'notify_admin_bad_header'})) {
			push(@{$pbn->{'bad_header_admin_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'notify_admin_bad_header'}
			});
		}


		# Quarantine options
		
		# Check if we must quarantine a virus
		if (defined($amavisPolicy{'quarantine_virus'})) {
			push(@{$pbn->{'virus_quarantine_to_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'quarantine_virus'}
			});
		}

		# Check if we must quarantine a banned file
		if (defined($amavisPolicy{'quarantine_banned_file'})) {
			push(@{$pbn->{'banned_quarantine_to_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'quarantine_banned_file'}
			});
		}

		# Check if we must quarantine a banned header
		if (defined($amavisPolicy{'quarantine_bad_header'})) {
			push(@{$pbn->{'bad_header_quarantine_to_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'quarantine_bad_header'}
			});
		}

		# Check if we must quarantine spam
		if (defined($amavisPolicy{'quarantine_spam'})) {
			push(@{$pbn->{'spam_quarantine_to_maps'}},\{
					$r->recip_addr	=> $amavisPolicy{'quarantine_spam'}
			});
		}


	}

	return $pbn;
};



# Get amavis policy
sub getAmavisPolicy
{
	my ($self,$policyID) = @_;

	
	# Query amavis 
	my $sth = DBSelect("
		SELECT 
			ID,

			bypass_virus_checks, bypass_banned_checks, bypass_spam_checks, bypass_header_checks,
			bypass_virus_checks_m, bypass_banned_checks_m, bypass_spam_checks_m, bypass_header_checks_m,


			spam_tag_level, spam_tag2_level, spam_tag3_level, spam_kill_level, spam_dsn_cutoff_level, spam_quarantine_cutoff_level,
			spam_modifies_subject, spam_tag_subject, spam_tag2_subject, spam_tag3_subject,
			spam_tag_level_m, spam_tag2_level_m, spam_tag3_level_m, spam_kill_level_m, spam_dsn_cutoff_level_m, spam_quarantine_cutoff_level_m,
			spam_modifies_subject_m, spam_tag_subject_m, spam_tag2_subject_m, spam_tag3_subject_m,


			max_message_size, banned_files,
			max_message_size_m, banned_files_m,


			sender_whitelist, sender_blacklist,
			sender_whitelist_m, sender_blacklist_m,


			notify_admin_newvirus, notify_admin_virus, notify_admin_spam, notify_admin_banned_file, notify_admin_bad_header,
			notify_admin_newvirus_m, notify_admin_virus_m, notify_admin_spam_m, notify_admin_banned_file_m, notify_admin_bad_header_m,
		

			quarantine_virus, quarantine_banned_file, quarantine_bad_header, quarantine_spam,
			quarantine_virus_m, quarantine_banned_file_m, quarantine_bad_header_m, quarantine_spam_m


		FROM
			amavis

		WHERE
			PolicyID = ".DBQuote($policyID)."
			AND Disabled = 0
	");
	if (!$sth) {
		do_log(-1,"[QUOTAS] Failed to query amavis: ".cbp::dblayer::Error());
		return;
	}

	my $row = $sth->fetchrow_hashref();

	DBFreeRes($sth);

	return $row;
}




# vim: ts=4
1;
