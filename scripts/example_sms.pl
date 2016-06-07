#!/usr/bin/perl -w

use strict;
use IO::Socket;               # Socket work

###############################################################################
##
##  example_sms.pl -- simple example script to send
##                    an SMS message via a web cgi
##                    Works with German pitcom powered free SMS sites 
##                    - find one and look at the page source to set the
##                      pitcom variables (see below)
##                    - note that pitcom checks the referer, thus you should
##                      take care to set the proper value 
##
##  NOTE: while the 'big names' have implemented measures to prevent
##        the use of automated scripts, and disallow such scripts
##        explicitely in their TOS (Terms of Service), this is not
##        neccesarily true for smaller websites.
##
##        An example for the latter are German websites providing free
##        SMS (to German nets only) powered by pitcom. 
##        With a suitable query, you may find such sites on (e.g.) Google.
##        At the time of the writing of this script, the sites I found did not
##        disallow the use of scripts, but check for yourself if you are
##        using this.
##
##  usage: example_sms.pl [NR]
##    <NR>    destination phone number
##    message is read from STDIN
##
##    (c) R. Wichmann <support@la-samhna.de> Tue Jul 17  CEST 2001
##        Released under the Gnu Public License version 2.0 or later
##        adapted from archpage ( (c) Rob Muhlestein ) 
##                 and mpage.pl ( (c) David Allen <s2mdalle@titan.vcu.edu> )
##

########################## -- BEGIN CONFIGURATION --

## set to default phone number
     my $NR      = '<default phone number>';

## set to sender
     #my $VON     = '<default sender>';
     my $VON     = 'stupsel';

## set to URL of form page
     my $REFERER = '<default referer>';

## set to cgi script URL without 'http://domain';
     my $PAGE = '<default cgi URL>';

## set to domain where cgi script lives;
     my $DOMAIN = '<default domain>';

## set to 1 if you want to save response
     my $save_response = 1;

## set to 1 for verbose output
     my $verbose = 1;

## set to 1 to enable sending
     my $really_send = 0;


## The PITCOM variables

#my $ID       = '<id>';                                        # gateway-ID
#my $WERBUNG  = '<advertisement>';                             # advertisement
#my $QUITTUNG = '<return page>';                               # return page
#my $USER     = '<customer>';                                  # customer
#my $LIST     = '0';                                           # message type

########################## -- END CONFIGURATION --

$NR = $ARGV[0] if $ARGV[0];

my $message='';
undef $/;
$message=<STDIN>;

$message =~ s/\[EOF\]//g;

## URL encode and remove line breaks
$message =~ s/\n/ /g;
$message =~ s/\r//g;
$message =~s/\s+/ /g;         # Multiple whitespace -> one space

$message  =~ s/([^a-zA-Z0-9-_\.\/])/uc sprintf("%%%02x",ord($1))/eg;
$message  =~ s/%20/+/g;

$WERBUNG  =~ s/([^a-zA-Z0-9-_\.\/])/uc sprintf("%%%02x",ord($1))/eg;
$WERBUNG  =~ s/%20/+/g;
$QUITTUNG =~ s/([^a-zA-Z0-9-_\.\/])/uc sprintf("%%%02x",ord($1))/eg;
$QUITTUNG =~ s/%20/+/g;
$USER     =~ s/([^a-zA-Z0-9-_\.\/])/uc sprintf("%%%02x",ord($1))/eg;
$USER     =~ s/%20/+/g;

## truncate
my $maxChars = 153 - length($WERBUNG) - length($VON);
 
if(length($message) >= $maxChars)
{
    $message =  substr($message, 0, $maxChars);
}


my $NR1 = substr($NR, 0, 4); 
my $NR2 = substr($NR, 4, length($NR)-4); 

my $msglen = length($message);

my $overhead = "ID=$ID&";
$overhead .= "WERBUNG=$WERBUNG&";
$overhead .= "QUITTUNG=$QUITTUNG&";
$overhead .= "USER=$USER&";
$overhead .= "LIST=$LIST&";
$overhead .= "NR1=$NR1&";
$overhead .= "NR2=$NR2&";
$overhead .= "VON=$VON&";
$overhead .= "MESSAGE=$message&";
$overhead .= "CNT=$msglen";

my $smslen = length($overhead);
    
my $llim       = "\r\n";    # At the end of each line.

my $SMS  = "POST $PAGE HTTP/1.0$llim";
$SMS .= "User-Agent: EvilGenius/1.0$llim";
$SMS .= "Referer: $REFERER$llim";
$SMS .= "Accept: */*$llim";
$SMS .= "Content-length: $smslen$llim";
$SMS .= "Content-type: application/x-www-form-urlencoded$llim";
$SMS .= "$llim";
$SMS .= "$overhead";

if ($verbose)
{
    print STDERR " Sending message...\n\n";
    print STDERR "$SMS\n\n";
}

my $document='';

if ($really_send)
{
    my $sock = IO::Socket::INET->new(PeerAddr => $DOMAIN,
				     PeerPort => 'http(80)',
				     Proto    => 'tcp');


    if ($verbose)
    {
	die "Cannot create socket : $!" unless $sock;
    }
    else
    {
	exit (1) unless $sock;
    }
    
    $sock->autoflush();
    $sock->print("$SMS");

    $document = join('', $sock->getlines());
}
else
{
    $document = " really_send was set to 0, SMS not sent";
}

if ($save_response) 
{
    if ($verbose)
    {
	print STDERR "Saving response to tmp.html...\n\n";
    }
    my $status = 0;
    open(TMP,">tmp.html") or $status=1;
    print TMP "$document\n" unless $status;
    close TMP unless $status;
}

if ($document =~ m/SMS wird versendet/g)
{
    if ($verbose)
    {
	print STDERR " SMS successfully sent to $NR.\n";
    }
    exit (0);
}
else
{
    if ($verbose)
    {
	print STDERR " SMS not sent. There was an error.\n";
	print STDERR " Use save_response = 1 to save the response to\n";
	print STDERR " tmp.html in order to see what the server sent back.\n";
    }
    exit (1);
}

    

    
    



















