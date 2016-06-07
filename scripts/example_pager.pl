#!/usr/bin/perl -w
#
#
# Simple program to connect to:
#     http://www2.pagemart.com/cgi-bin/rbox/pglpage-cgi
# and send a page.
#
# Modified 10/21/99 Will O'Brien willo@savvis.net 
# Originally Written by David Allen s2mdalle@titan.vcu.edu
# http://opop.nols.com/
#
#
# Modified by R. Wichmann (read message from stdin)
# <support@la-samhna.de>
#
# - added config variables
# - read MESSAGE from STDIN
#
# This file is released under the terms of the GNU General Public License.
# Please see http://www.gnu.org for more details.
#
# This program still beta, but working better.
#
# Changelog:
# 10/21/99:  Modified original code and get paging to function.
# 10/22/99:  Fixed Error checking.  Checks PIN length, outputs failure message.
#
# REQUIRES MODULES:  strict and IO::Socket
#
# USAGE FROM COMMAND LINE:  echo "message" | example_pager.pl PAGER_PIN 
# Where PAGER_PIN is the PIN of the pager you want to send MESSAGE to.
#
# This program will send the page using 
# www.pagemart.com/cgi-bin/rbox/pglpage-cgi
# and will store the response in LASTRESPONSE.html when the server replies.
#
# If you are looking at this program for examples of code to make it work,
# check out the page{} subroutine below - it is the meat of this program.
##############################################################################

# use Socket;                   # INET
use strict;
use IO::Socket;               # Socket work

my $pagerid = shift;

########################## -- BEGIN CONFIGURATION --

## set to 1 for verbose output
my $verbose = 1;

## set to 1 if you want to save response
my $save_response = 1;

## set to 1 to enable sending
my $really_send = 0;

########################### -- END  CONFIGURATION --

# previous
#my $MESSAGE = join(' ', @ARGV);

my $MESSAGE='';
undef $/;
$MESSAGE=<STDIN>;
$MESSAGE =~ s/\[EOF\]//g;

die "Usage:  echo \"message\" \| example_pager.pl PAGER_ID\n\n" 
    unless $pagerid;
die "Usage:  echo \"message\" \| example_pager.pl PAGER_ID\n\n" 
    unless $MESSAGE;

page($pagerid, $MESSAGE);

if ($verbose) { print "Done.\n"; }
exit(0);

############################################################################

sub page{
    my ($name, $text) = @_;
    my $TRUNCATED = 0;
    my $PAGE = "";  # The text sent to www.pagemart.com - appended later.
    
    $pagerid = $name;

    if ($verbose) { print STDERR "Processing pager ID...\n"; }
    # Eliminate everything but numbers from the pager id
    $pagerid =~ s/[^0-9]//g;
    
    # Check the pager id length and so on.
    if( (((length($pagerid)) < 7)) || ((length($pagerid)) > 10) )
    {
	if ($verbose) {
	    die "Bad pager ID number. A pager id number is 7 or 10 numbers.\n";
	}
	else {
	    exit (1);
	}
    }

    if ($verbose) {
	die "No message specified.\n" unless $text;
    }
    else {
	exit (1) unless $text;
    }


    # This is the format of the message we're going to send via the TCP
    # socket
    # POST /cgi-bin/rbox/pglpage-cgi HTTP/1.0
    # User-Agent: Myprogram/1.00
    # Accept: */*
    # Content-length: 35
    # Content-type: application/x-www-form-urlencoded
    #
    # pin2=6807659&message1=stuff+and+nonsense
    
    if ($verbose) { print STDERR "Processing text of message...\n"; }
    # A bit of string pre-processing
    chomp $text;
    my $strdelim       = "\r\n";    # At the end of each line.
    
    # Compress the text a bit - eliminate redundant characters - this 
    # helps a lot for pages that have multiple spaces and so on.
    $text =~s/\n/ /g;          # Linefeeds are spaces
    $text =~s/\r//g;           # No carriage returns
    $text =~s/\s+/ /g;         # Multiple whitespace -> one space.
    
    if(length($text)>=200)
    {
	$TRUNCATED = "True";
	$text = substr($text, 0, 199);      # 200 Character maximum
    }
    
    my $encodedmessage = urlencode($text);
    
    # The length of the request has to be TOTAL QUERY.  If it's just
    # the length of the string you're sending, it will truncate the 
    # hell out of the page.  So the pager number is length($pagerid)
    # of course the length of the message, and add the length of the
    # parameter flags, (PIN= and ?MSSG=) and you're done.

    my $xxmsg = "pin2=$pagerid&";
    $xxmsg .= "PAGELAUNCHERID=1&";
    $xxmsg .= $encodedmessage;
    
    # my $pagelen=length($encodedmessage)+length("pin2=?message1=")+
    #	length($pagerid)+;

    my $pagelen = length($xxmsg);
    
    # Build the text we send to the server
    $PAGE  = "POST /cgi-bin/rbox/pglpage-cgi HTTP/1.0$strdelim";
    $PAGE .= "User-Agent: Pagent/5.4$strdelim";
    $PAGE .= "Referer: http://www.weblinkwireless.com/productsnservices/sendingmessage/pssm-sendamessage.html$strdelim";
    $PAGE .= "Accept: */*$strdelim";
    $PAGE .= "Content-length: $pagelen$strdelim";
    $PAGE .= "Content-type: application/x-www-form-urlencoded$strdelim";
    $PAGE .= "$strdelim";
    # $PAGE .= "pin2=$pagerid&message1=".$encodedmessage;
    $PAGE .= $xxmsg;

    if ($verbose) { 
	print STDERR "Sending message...\n\n";
	print STDERR "$PAGE\n\n";
    }


    my $document='';

    if ($really_send)
    {
	# Now we send our data.
	# Note that this is just quick and dirty, so I'm using a perl module
	# to do the network dirty work for me.
	my $sock = IO::Socket::INET->new(PeerAddr => 'www2.pagemart.com',
					 PeerPort => 'http(80)',
					 Proto    => 'tcp');

	if ($verbose) { 
	    die "Cannot create socket : $!" unless $sock;
	}
	else {
	    exit (1) unless $sock;
	}
	$sock->autoflush();
	$sock->print("$PAGE");
    
	$document = join('', $sock->getlines());
    }
    else
    {
	$document = " really_send was set to 0, page NOT sent";
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
    
    if($document =~ m/NOT/g)
    {  
	if ($verbose)
	{
	    print STDERR "Page not sent.  There was an error. \n";
	    print STDERR "See tmp.html for what the server sent back to me.\n";
	}
	exit(0);
    } # End if
    else
    {   
	if ($verbose)
	{
	    $document =~ m/(\d{1,4}) character message out of/g;
	    print STDERR "Page sent successfully to $pagerid.\n";
	}
	exit(0);
    } # End else
} # End sub page


############################################################################

sub urlencode{
    my $text    = shift;
    my $input   = $text;
    
    chomp $input;

    # Translate all non-letter non-number characters into their %HEX_VAL
    # and return that string.
    $input =~ s/([^a-zA-Z0-9-_\.\/])/uc sprintf("%%%02x",ord($1))/eg;
    $input =~ s/%20/+/g;

    return $input;
} # End sub urlencode
