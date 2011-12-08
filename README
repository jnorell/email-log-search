email-log-search.php
====================

Read email log records and report those matching any given criteria
(login name(s), email address(es) and/or ip address(es)).

    Usage:  email-log-search.php (-l login | -e email-addr | -i ip) [...]

Copyright 2011 Jesse Norell <jesse@kci.net>

Impetus
-------

We received a subpoena for some email log records, and needed
to parse through a lot more than was practicable manually.
After killing half a day trying to mess with existing log parsing
programs, and also not finding any to handle our POP3 server,
we made more progress by writing one from scratch.

Reporting Search Criteria
-------------------------

We count each POP3 connection as a "session", and report (print log records to stdout)
sessions matching an ip address or login name.

For SMTP, we report each connection from a matching ip address, each message
sent by a matching sasl login, and each message that was sent to or from a
matching email address.

Note that we report when *any* of the given criteria matches.

Log Formats
-----------

Log formats currently supported:

* postfix (2.7.4)
* popa3d (1.0.2)

Use
---

This script reads log file input on stdin, which should be sorted by date,
and writes to stdout.  Eg.:

    cd /var/log
    (zcat `ls -1tr mail.log*.gz`; cat mail.log) | email-log-search.php -e redact1@domainX

Note that syslog doesn't log the year; this script will report log records across
multiple years (remember, you sort them first), but the output won't have enough context
to know what's what, so you'll probably need to clarify that.

If you wish to require searches to match multiple criteria, you could chain together like:

    cat logs | email-log-search.php --ip z.y.x.w | email-log-search.php -e addr@foo.bar

Source
------

You'll generally find the most recent version at:

    https://github.com/jnorell/email-log-search

Subpoena
--------

If useful to anyone, this is the wording of the subpoena we recieved
for "electronically stored information":

    All customer or subscriber account information for the email accounts: redact1@domainX,
    redact2@domainY and/or the domain name domainY (if available) or for any
    related accounts, that falls within any of the following categories:
  
    1. Name,
    2. Address,
    3. Local and long distance telephone toll billing records,
    4. Records of session times and durations,
    5. Length of service (including start date) and types of service utilized,
    6. Telephone or instrument number or other subscriber number or identity, including any
    temporarily assigned network address such as an Internet Protocol address, and
    7. Means and source of payment for such service (including any credit card or bank account
    number).

email-log-search.php was written to find and report email log records (items 4. and 6.).

