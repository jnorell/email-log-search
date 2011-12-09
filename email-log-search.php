#!/usr/bin/php
<?php

/*
 * email-log-search.php:
 *
 *   Read email log records and report those matching given criteria
 *   (login name(s), email address(es) and/or ip address(es))
 *
 *   Usage:  email-log-search.php [-m] (-l login | -e email-addr | -i ip) [...]
 *
 * We count each POP3 connection as a "session", and report (print log records to stdout)
 * sessions matching an ip address or login name.
 *
 * For SMTP, we report each connection from a matching ip address, each message
 * sent by a matching sasl login, and each message that was sent to or from a
 * matching email address.
 *
 * Log formats currently supported:
 *
 *   postfix (2.7.4)
 *   popa3d (1.0.2)
 *
 * Copyright 2011 Jesse Norell <jesse@kci.net>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
 * popa3d log parser
 *
 * This is the log format popa3d produces:
 *
Dec  1 11:59:04 mail popa3d[1234]: Session from aaa.bbb.ccc.ddd
Dec  1 11:59:04 mail popa3d[1234]: Authentication passed for username
Dec  1 11:59:04 mail popa3d[1234]: 0 messages (0 bytes) loaded
Dec  1 11:59:04 mail popa3d[1234]: 0 (0) deleted, 0 (0) left
*/
function parselog_popa3d(&$r) {
	global $logins;
	global $ipaddrs;
	static $sessions = array();
	static $sess_start = 'Session from ';
	static $sess_login = 'Authentication passed for ';
	static $sess_stop = '( deleted|Didn\'t attempt authentication|Connection timed out|Premature disconnect|Authentication failed for )';

	$pid = $r['pid'];
	$log = $r['log'];

	if (! isset($sessions[$pid])) {
		$sessions[$pid] = array();
	}

	if (count($sessions[$pid]) == 0) {
		if (! strncmp($log, $sess_start, strlen($sess_start))) {
			# Session Start
			$sessions[$pid]['ip'] = substr($log,strlen($sess_start));
			$sessions[$pid]['records'][] = $r['record'];
		}
	} else {
		$sessions[$pid]['records'][] = $r['record'];

		if (! strncmp($log, $sess_login, strlen($sess_login))) {
			# Session Login Name
			$l = substr($log,strlen($sess_login));
			$sessions[$pid]['login'] = strtolower($l);
		} else if (preg_match($sess_stop, $log)) {
			# Session Stop
			if (in_array($sessions[$pid]['login'], $logins) ||
			    in_array($sessions[$pid]['ip'], $ipaddrs))
			{
				foreach ($sessions[$pid]['records'] as $rec)
					echo $rec;
			}
			unset($sessions[$pid]);
		}
	}
}

/*
 * postfix log parser
 *
 * Postfix log verbosity can certainly vary, and this may be
 * incomplete for all places messages can be injected,
 * but this is basically what we're looking at handling.
 *
 * Note that using lmtp spam/virus filter, each message gets 2 queue
 * id's, and both are needed to determine the final disposition.
 *
Dec  1 08:50:15 mail postfix/smtpd[4971]: connect from mail.external.net[aaa.bbb.ccc.ddd]
Dec  1 08:50:16 mail postfix/smtpd[4971]: 8F3D22201281: client=mail.external.net[aaa.bbb.ccc.ddd]
Dec  1 08:50:16 mail postfix/cleanup[3712]: 8F3D22201281: message-id=<external-net-msg1234@external.net>
Dec  1 08:50:16 mail postfix/smtpd[4971]: disconnect from mail.external.net[aaa.bbb.ccc.ddd]
Dec  1 08:50:16 mail postfix/qmgr[13241]: 8F3D22201281: from=<some.sender@external.net>, size=68865, nrcpt=1 (queue active)
Dec  1 08:50:32 mail postfix/smtpd[3908]: 989A4A109B12: client=localhost[127.0.0.1]
Dec  1 08:50:32 mail postfix/cleanup[1520]: 989A4A109B12: message-id=<external-net-msg1234@external.net>
Dec  1 08:50:32 mail postfix/qmgr[13241]: 989A4A109B12: from=<some.sender@external.net>, size=69284, nrcpt=1 (queue active)
Dec  1 08:50:32 mail postfix/lmtp[890]: 8F3D22201281: to=<our.user@local.dom>, relay=127.0.0.1[127.0.0.1]:10024, delay=16, delays=0.72/0/0/16, dsn=2.6.0, status=sent (250 2.6.0 Ok, id=14283-03, from MTA: 250 2.0.0 Ok: queued as 989A4A109B12)
Dec  1 08:50:32 mail postfix/qmgr[13241]: 8F3D22201281: removed
Dec  1 08:50:32 mail postfix/local[3878]: 989A4A109B12: to=<our.user@local.dom>, relay=local, delay=0.1, delays=0.06/0/0/0.04, dsn=2.0.0, status=sent (delivered to mailbox)
Dec  1 08:50:32 mail postfix/qmgr[13241]: 989A4A109B12: removed
 *
 * And an SASL login looks like:
 *
Dec  1 11:09:56 mail postfix/smtpd[18630]: 682BE48082C9: client=clientx.domainfoo.com[aa.bb.cc.dd], sasl_method=LOGIN, sasl_username=user_xyz
 *
 * And a non-delivery bounce like:
 *
Dec  1 11:52:31 mail postfix/bounce[2322]: 8FB274412985: sender non-delivery notification: AA0F94412987
 *
*/
function parselog_postfix(&$r) {
	global $logins;
	global $emailaddrs;
	global $ipaddrs;
	global $follow_msgids;
	static $sessions = array();	// smtpd sessions
	static $messages = array();	// postfix queued messages
	static $messageids = array();	// tracked message-ids

	# smtpd
	static $smtpd_connect = '/connect from ([^[]*)\[((\d{1,3}\.){3}\d{1,3})\]/';
	static $smtpd_queuemsg = '/^([[:xdigit:]]+): client=([^[]*)\[((\d{1,3}\.){3}\d{1,3})\]/';
	static $smtpd_disconnect = '/disconnect from ([^[]*)\[((\d{1,3}\.){3}\d{1,3})\]/';
	static $smtpd_sasl_client = '/^([[:xdigit:]]+): client=([^[]*)\[((\d{1,3}\.){3}\d{1,3})\], sasl_method=[^, ]*, sasl_username=([^, ]+)/';

	# qmgr
	static $qmgr_removed = '/^([[:xdigit:]]+): removed/';

	# lmtp
	# potential bug: this also matches delivery to remote postfix servers,
	# so we'll try to track their queueid - harmless?
	static $lmtp_secondary_qid = '/^([[:xdigit:]]+): (to|from)=<([^>]+)>.+status=sent.+ queued as ([[:xdigit:]]+)/';

	# bounce
	static $bounce_secondary_qid = '/^([[:xdigit:]]+): sender .*notification: ([[:xdigit:]]+)/';

	# various
	static $match_to_from = '/^([[:xdigit:]]+): (to|from)=<([^>]+)>/';
	static $match_msgid = '/^([[:xdigit:]]+): message-id=(.+)/';
	static $qmsg_record = '/^([[:xdigit:]]+): (.*)/';

	$daemon = substr($r['service'],strlen("postfix/"));
	$pid = $r['pid'];
	$log = $r['log'];
	$qid = $r['qid'];

	if ($qid) {
		if (! isset($messages[$qid])) {
			$messages[$qid] = array();
			$messages[$qid]['records'] = array();
		}
		$msg =& $messages[$qid];
	} else {
		$msg = null;
	}

	switch($daemon)
	{
	    case 'smtpd':

	if (! isset($sessions[$pid])) {
		$sessions[$pid] = array();
		$sessions[$pid]['records'] = array();
	}

	$sess =& $sessions[$pid];

	if (count($sess) == 0) {
		if (preg_match($smtpd_connect, $log, $m)) {
			# Connect
			$sess['connectip'] = $m[2];
			$sess['records'][] = $r['record'];
			$sess['connect_record'] = $r['record'];
		} else if (preg_match($smtpd_queuemsg, $log, $m)) {
			$sess['records'][] = $r['record'];

			# Message is queued, save id and info
			$sess['qid'] = $qid;
			$sess['qids'][$qid] = $qid;
			$sess['clientip'] = $m[3];
			$msg['clientip'] = $m[3];
			if (isset($sess['connect_record']))
				$msg['records'][] = $sess['connect_record'];
			$msg['records'][] = $r['record'];

			if (preg_match($smtpd_sasl_client, $log, $m)) {
				$sess['sasl_username'] = strtolower($m[5]);
				$msg['sasl_username'] = strtolower($m[5]);
			}
		}
	} else if (preg_match($smtpd_queuemsg, $log, $m)) {
		$sess['records'][] = $r['record'];

		# Message is queued, save id and info
//		if (isset($sess['qid'])) {
//			// got new message in ongoing session
//		}
		$sess['qid'] = $qid;
		$sess['qids'][$qid] = $qid;
		$sess['clientip'] = $m[3];
		$msg['clientip'] = $m[3];
		$msg['records'][] = $r['record'];

		if (preg_match($smtpd_sasl_client, $log, $m)) {
			$sess['sasl_username'] = strtolower($m[5]);
			$msg['sasl_username'] = strtolower($m[5]);
		}
	} else if (isset($sess['connectip'])) {
		$sess['records'][] = $r['record'];

		if (preg_match($smtpd_disconnect, $log, $m)) {
			# Disconnect
			if (isset($sess['qid'])) {
				foreach ($sess['qids'] as $qid)
					$msg['records'][] = $r['record'];
			} else if (in_array($sess['connectip'], $ipaddrs)) {
				# Note if qid is set, the session records will print later
				foreach ($sess['records'] as $rec)
					echo $rec;
			}
			unset($sessions[$qid]);
		}
	}


		break;
	    case 'qmgr':

	if (preg_match($qmgr_removed, $log, $m)) {
		if ($msg != null) {
			$msg['records'][] = $r['record'];

			# potential bug:
			#   if a child qid is removed before the parent's log
			#   entry ties them together, we would miss the child.
			#   in practice, I don't see that in our logs.

			$print_records=0;

			if (isset($msg['clientip'])
			   && in_array($msg['clientip'], $ipaddrs))
			{
				$print_records++;
			} else if (isset($msg['sasl_username'])
			   && in_array($msg['sasl_username'], $logins))
			{
				$print_records++;
			} else if (isset($msg['addrs'])
			   && (count($emailaddrs) > 0))
			{
				foreach ($msg['addrs'] as $addr)
			   		if (in_array($addr, $emailaddrs))
						$print_records++;
			}

			$msgid = (isset($msg['message-id']) ? $msg['message-id'] : null);

			if ($msgid && isset($messageids[$msgid])
				&& isset($messageids[$msgid]['tracked'])
				&& $messageids[$msgid]['tracked'])
			{
					$follow_msgid = true;
			} else {
					$follow_msgid = false;
			}

			if ($print_records || isset($msg['me_too']) || $follow_msgid) {
				if ($msgid) {
					$messageids[$msgid]['tracked'] = true;
					$follow_msgid = true;
				}
					
				foreach ($msg['records'] as $rec)
					echo $rec;
			}

			# flag parent to print (if needed) and remove linkage
			if (isset($msg['parent_qid'])
			    && isset($messages[$msg['parent_qid']]))
			{
				if ($print_records)
					$messages[$msg['parent_qid']]['me_too']=1;
				unset($messages[$msg['parent_qid']]['child_qids'][$qid]);
			}

			# flag child(s) to print (if needed) and remove linkage(s)
			if (isset($msg['child_qids'])) {
				foreach ($msg['child_qids'] as $child_qid) {
					if ($print_records)
						$messages[$child_qid]['me_too']=1;
					unset($messages[$child_qid]['parent_qid']);
				}
			}

			if ($msgid && ! $follow_msgid) {
				unset($messageids[$msgid]);
			}
			unset($messages[$qid]);
			break;
		}
	}

		// no break, fallthrough to next case
	    case 'smtp':
	    case 'cleanup':
	    case 'lmtp':
	    case 'local':
	    case 'pipe':
	    case 'bounce':
	    case 'error':

	if (preg_match($lmtp_secondary_qid, $log, $m)) {
		$qid2 = $m[4];
		$msg['child_qids'][$qid2] = $qid2;
		$messages[$qid2]['parent_qid'] = $qid;
		$msg['addrs'][] = strtolower($m[3]);
		$msg['records'][] = $r['record'];
	} else if (preg_match($bounce_secondary_qid, $log, $m)) {
		$qid2 = $m[2];
		$msg['child_qids'][$qid2] = $qid2;
		$messages[$qid2]['parent_qid'] = $qid;
		$msg['records'][] = $r['record'];
	} else if (preg_match($match_to_from, $log, $m)) {
		$msg['addrs'][] = strtolower($m[3]);
		$msg['records'][] = $r['record'];
	} else if ($follow_msgids
			&& preg_match($match_msgid, $log, $m)) {
		$msg['message-id'] = $m[2];
		$msg['records'][] = $r['record'];
	} else if ($qid) {
		$msg['records'][] = $r['record'];
	}


		break;
	    case 'anvil':
	    case 'scache':
	    case 'pickup':
		break;
	    default:
				die ("ERROR: Don't know what to do with postfix service '$daemon'\n");
		break;
	}
}


/* Main Program */

$usage = "Usage:  $argv[0] [-m] (-l login | -e email-addr | -i ip) [...]\n";
$usage .= "        -m = follow message-ids (catch subsequent re-injection of message)\n";
$usage .= "        -l = match specified login name (pop3 or sasl)\n";
$usage .= "        -d = match specified email address\n";
$usage .= "        -i = match specified ip address\n";
$usage .= "Note: -l matches login names, -e matches email addresses; you may need to use both\n";
$usage .= "(-e email addresses will not match as a login name otherwise).\n";

$shortopts  = "";
$shortopts .= "m";	// Follow Message-IDs
$shortopts .= "l:";	// Login name
$shortopts .= "e:";	// E-Mail Address
$shortopts .= "i:";	// IP Address

$longopts  = array(
    "login:",		// Login name
    "email:",		// E-Mail Address
    "ip:",		// IP Address
);

$logins = array();
$emailaddrs = array();
$ipaddrs = array();
$follow_msgids = false;

$options = getopt($shortopts, $longopts);
is_array($options) || die($usage);

foreach ($options as $opt => $val) {
	switch($opt)
	{
		case 'm':
			$follow_msgids=true;
			break;
		case 'l':
		case 'login':
			if (is_array($val))
				foreach ($val as $v)
					$logins[] = strtolower($v);
			else
				$logins[] = strtolower($val);
			break;
		case 'e':
		case 'email':
			if (is_array($val))
				foreach ($val as $v)
					$emailaddrs[] = strtolower($v);
			else
				$emailaddrs[] = strtolower($val);
			break;
		case 'i':
		case 'ip':
			if (is_array($val))
				$ipaddrs = $val;
			else
				$ipaddrs[] = $val;
			break;
		default:
			die($usage);
	}
}

count($logins) || count($emailaddrs) || count($ipaddrs) || die($usage);

while ($line = fgets(STDIN)) {
	# Common syslog format:  m d t hostname service[pid]: log message
//	$pattern='/^([[:alpha:]]+ +[\d]+ [\d:]+) [\w]+ ([^[]+)(\[([0-9]+)\])?: (.*)/';
//  enchancing the regex to also find a postifx queue id in this preg_match
	$pattern='/^([[:alpha:]]+ +[\d]+ [\d:]+) [\w]+ ([^[]+)(\[([0-9]+)\])?: ((([[:xdigit:]]+): )?.*)/';

	if (! preg_match($pattern, $line, $m)) continue;

	$record = array(
		'service' => $m[2],
		'pid' => $m[4],
		'log' => $m[5],
		'qid' => (isset($m[7]) ? $m[7] : null),
		'record' => $line,
		);

	if ($record['service'] == 'popa3d')
			parselog_popa3d($record);
	else if (! strncmp($record['service'], 'postfix', 7))
	if (! strncmp($record['service'], 'postfix', 7))
			parselog_postfix($record);
}

?>
