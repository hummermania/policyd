# Message tracking functions
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


package cbp::tracking;

use strict;
use warnings;

# Exporter stuff
require Exporter;
our (@ISA,@EXPORT,@EXPORT_OK);
@ISA = qw(Exporter);
@EXPORT = qw(
	updateSessionData
	getSessionDataFromRequest
	getSessionDataFromQueueID
);


use cbp::dblayer;
use cbp::logging;
use cbp::policies;
use cbp::system qw(parseCIDR);


# Database handle
my $dbh = undef;

# Our current error message
my $error = "";

# Set current error message
# Args: error_message
sub setError
{
	my $err = shift;
	my ($package,$filename,$line) = caller;
	my (undef,undef,undef,$subroutine) = caller(1);

	# Set error
	$error = "$subroutine($line): $err";
}

# Return current error message
# Args: none
sub Error
{
	my $err = $error;

	# Reset error
	$error = "";

	# Return error
	return $err;
}


# Get session data from mail_id
sub getSessionDataFromQueueID
{
	my ($queueID,$clientAddress,$sender) = @_;
	
	
	# Pull in session data
	my $sth = DBSelect("
		SELECT
			ID,
			Instance, QueueID,
			Timestamp,
			ClientAddress, ClientName, ClientReverseName,
			Protocol,
			EncryptionProtocol, EncryptionCipher, EncryptionKeySize,
			SASLMethod, SASLSender, SASLUsername,
			Helo,
			Sender,
			Size,
			RecipientData
		FROM
			session_tracking
		WHERE
			QueueID = ".DBQuote($queueID)."
			AND ClientAddress = ".DBQuote($clientAddress)."
			AND Sender = ".DBQuote($sender)."
	");
	if (!$sth) {
		return (LOG_ERR,"[TRACKING] Failed to select session tracking info: ".cbp::dblayer::Error());
	}
	my $sessionData = $sth->fetchrow_hashref();
	
	if (!$sessionData) {
		return (LOG_ERR,"[TRACKING] No session data");
	}

	# Pull in decoded policy
	$sessionData->{'_Recipient_To_Policy'} = decodePolicyData($sessionData->{'RecipientData'});

	return $sessionData;
}


# Get session data
# Params:
# 	server, request
sub getSessionDataFromRequest
{
	my ($server,$request) = @_;


	# We must have protocol transport
	if (!defined($request->{'_protocol_transport'})) {
		$server->log(LOG_ERR,"[TRACKING] No protocol transport specified");
		return -1;
	}

	my $sessionData;

	# Check protocol
	if ($request->{'_protocol_transport'} eq "Postfix") {

		# Pull in session data
		my $sth = DBSelect("
			SELECT
				ID,
				Instance, QueueID,
				Timestamp,
				ClientAddress, ClientName, ClientReverseName,
				Protocol,
				EncryptionProtocol, EncryptionCipher, EncryptionKeySize,
				SASLMethod, SASLSender, SASLUsername,
				Helo,
				Sender,
				Size,
				RecipientData
			FROM
				session_tracking
			WHERE
				Instance = ".DBQuote($request->{'instance'})."
		");
		if (!$sth) {
			$server->log(LOG_ERR,"[TRACKING] Failed to select session tracking info: ".cbp::dblayer::Error());
			return -1;
		}
		$sessionData = $sth->fetchrow_hashref();
				
		# If no state information, create everything we need
		if (!$sessionData) {
	
			# Should only track sessions from RCPT
			if ($request->{'protocol_state'} eq "RCPT") {
				DBBegin();
	
				# Record tracking info
				$sth = DBDo("
					INSERT INTO session_tracking 
						(
							Instance,QueueID,
							Timestamp,
							ClientAddress, ClientName, ClientReverseName,
							Protocol,
							EncryptionProtocol,EncryptionCipher,EncryptionKeySize,
							SASLMethod,SASLSender,SASLUsername,
							Helo,
							Sender,
							Size
						)
					VALUES
						(
							".DBQuote($request->{'instance'}).", ".DBQuote($request->{'queue_id'}).",
							".DBQuote($request->{'_timestamp'}).",
							".DBQuote($request->{'client_address'}).", ".DBQuote($request->{'client_name'}).", 
							".DBQuote($request->{'reverse_client_name'}).",
							".DBQuote($request->{'protocol_name'}).",
							".DBQuote($request->{'encryption_protocol'}).", ".DBQuote($request->{'encryption_cipher'}).", 
							".DBQuote($request->{'encryption_keysize'}).",
							".DBQuote($request->{'sasl_method'}).", ".DBQuote($request->{'sasl_sender'}).",
									".DBQuote($request->{'sasl_username'}).",
							".DBQuote($request->{'helo_name'}).",
							".DBQuote($request->{'sender'}).",
							".DBQuote($request->{'size'})."
						)
				");
				if (!$sth) {
					$server->log(LOG_ERR,"[TRACKING] Failed to record session tracking info: ".cbp::dblayer::Error());
					DBRollback();
					return -1;
				}
				$server->log(LOG_DEBUG,"[TRACKING] Recorded tracking information for instance ".$request->{'instance'});
	
				# Grab inserted row ID
				my $rowID = DBLastInsertID('session_tracking','ID');
				if (!$rowID) {
					$server->log(LOG_ERR,"[TRACKING] Failed to get session tracking ID: ".cbp::dblayer::Error());
					DBRollback();
					return -1;
				}
			
				$sessionData->{'ID'} = $rowID;
	
				DBCommit();
			}
	
			$sessionData->{'Instance'} = $request->{'instance'};
			$sessionData->{'QueueID'} = $request->{'queue_id'};
			$sessionData->{'ClientAddress'} = $request->{'client_address'};
			$sessionData->{'ClientName'} = $request->{'client_name'};
			$sessionData->{'ClientReverseName'} = $request->{'reverse_client_name'};
			$sessionData->{'Protocol'} = $request->{'protocol_name'};
			$sessionData->{'EncryptionProtocol'} = $request->{'encryption_protocol'};
			$sessionData->{'EncryptionCipher'} = $request->{'encryption_cipher'};
			$sessionData->{'EncryptionKeySize'} = $request->{'encryption_keysize'};
			$sessionData->{'SASLMethod'} = $request->{'sasl_method'};
			$sessionData->{'SASLSender'} = $request->{'sasl_sender'};
			$sessionData->{'SASLUsername'} = $request->{'sasl_username'};
			$sessionData->{'Helo'} = $request->{'helo_name'};
			$sessionData->{'Sender'} = $request->{'sender'};
			$sessionData->{'Size'} = $request->{'size'};
			$sessionData->{'RecipientData'} = "";
		}
	
		# If we in rcpt, caclulate and save policy
		if ($request->{'protocol_state'} eq 'RCPT') {
			# Get policy
			my $policy = getPolicy($request->{'client_address'},$request->{'sender'},$request->{'recipient'},$request->{'sasl_username'});
			if (!defined($policy)) {
				$server->log(LOG_ERR,"[TRACKING] Failed to retrieve policy: ".cbp::policies::Error());
				return -1;
			}
	
			$sessionData->{'Policy'} = $policy;
			$sessionData->{'Recipient'} = $request->{'recipient'};
	
		# If we in end of message, load policy from data
		} elsif ($request->{'protocol_state'} eq 'END-OF-MESSAGE') {
			$sessionData->{'_Recipient_To_Policy'} = decodePolicyData($sessionData->{'RecipientData'});
			# This must be updated here ... we may of got actual size
			$sessionData->{'Size'} = $request->{'size'};
			# Only get a queue id once we have gotten the message
			$sessionData->{'QueueID'} = $request->{'queue_id'};
		}

	# Check for HTTP protocol transport
	} elsif ($request->{'_protocol_transport'} eq "Postfix") {
		$sessionData->{'ClientAddress'} = $request->{'client_address'};
		$sessionData->{'Helo'} = "";
		$sessionData->{'Sender'} = $request->{'sender'};

		# If we in RCPT state, set recipient
		if ($request->{'protocol_state'} eq "RCPT") {
			$sessionData->{'Recipient'} = $request->{'recipient'};
		}
	}

	# Shovei n various thing not stored in DB
	$sessionData->{'ProtocolState'} = $request->{'protocol_state'};
	$sessionData->{'Timestamp'} = $request->{'_timestamp'};
	$sessionData->{'ParsedClientAddress'} = parseCIDR($sessionData->{'ClientAddress'});

	return $sessionData;
}


# Record session data
# Args:
# 	$server, $sessiondata
sub updateSessionData
{
	my ($server,$sessionData) = @_;

	# Return if we have no ID, this would happen if we don't record rcpt info and jump direct to eom
	return if (!defined($sessionData->{'ID'}));

	# Return if we're not in RCPT state, in this case we shouldn't update the data
	if ($sessionData->{'ProtocolState'} eq 'RCPT') {

		# Get encoded policy data
		my $policyData = encodePolicyData($sessionData->{'Recipient'},$sessionData->{'Policy'});
		# Generate recipient data
		my $recipientData = $sessionData->{'RecipientData'}."/$policyData";

		$server->log(LOG_DEBUG,"[TRACKING] RecipientData = $recipientData");

		# Record tracking info
		my $sth = DBDo("
			UPDATE 
				session_tracking 
			SET
				RecipientData = ".DBQuote($recipientData)." 
			WHERE
				ID = ".DBQuote($sessionData->{'ID'})."
		");
		if (!$sth) {
			$server->log(LOG_ERR,"[TRACKING] Failed to update recipient data in session tracking info: ".cbp::dblayer::Error());
			return -1;
		}
	
	# If we at END-OF-MESSAGE, update size
	} elsif ($sessionData->{'ProtocolState'} eq 'END-OF-MESSAGE') {
		# Record tracking info
		my $sth = DBDo("
			UPDATE 
				session_tracking 
			SET
				QueueID = ".DBQuote($sessionData->{'QueueID'})." ,
				Size = ".DBQuote($sessionData->{'Size'})." 
			WHERE
				ID = ".DBQuote($sessionData->{'ID'})."
		");
		if (!$sth) {
			$server->log(LOG_ERR,"[TRACKING] Failed to update size in session tracking info: ".cbp::dblayer::Error());
			return -1;
		}
	}

	return 0;
}

1;
# vim: ts=4
