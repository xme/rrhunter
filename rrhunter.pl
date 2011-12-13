#!/usr/bin/perl
#
# rrhunter.pl - Rogue IPv6 Router Hunter
# Xavier Mertens <xavier at rootshell dot be>
#
# This script is provided as-is without any warranty.
# You are free to use, modify and distribute this script with no limitations.
# However it'd be great to leave my credits and inform me of any changes you performed.
#
# History
# -------
# 2011/12/13	Created
#
# Todo
# ----
# Fix kernel message: "netlink: 4 bytes leftover after parsing attributes."
#

use strict;
use warnings;
use Getopt::Std;
use Regexp::IPv6 qw($IPv6_re);
use Net::IP;
use Net::Address::IP::Local;
use Net::Frame::Device;
use Net::Write::Layer qw(:constants);
use Net::Write::Layer3;
use Net::Frame::Simple;
use Net::Frame::Layer::IPv6 qw(:consts);
use Net::Frame::Layer::ICMPv6 qw(:consts);
use Net::Frame::Layer::ICMPv6::RouterSolicitation;
use Net::Frame::Dump::Online2;
use POSIX qw(setsid);
use Sys::Syslog;   

my $program = "rrhunter";
my $target = "ff02::1"; # All IPv6 nodes on our link
my $detectedNeighbor;
my $expectedNeighbor;
my $expectedNetwork;
my $debug;
my $time = 60;
my $foreground;
my $daemon;
my $learning;
my $syslogFacility = "daemon";
my $pid;
my $pidFile = "/var/run/".$program.".pid";
my $caught = 0;
my $oDevice;
my $interface = "eth0";
my %opt = ();

# From RFC
my $RTR_MAX_SOLICITATIONS	= 3;
my $RTR_SOLICITATION_INTERVAL	= 1;

$SIG{'TERM'} = \&sigHandler;
$SIG{'INT'}  = \&sigHandler;
$SIG{'KILL'} = \&sigHandler;

sub sigHandler {
	msg("Received signal. Exiting.");
	unlink($pidFile) if (-r $pidFile);
	$caught = 1;
}

# Do not allow multiple running instances!
if (-r $pidFile) {
	open(PIDH, "<$pidFile") || die("Cannot read pid file!");
	my $currentPid = <PIDH>;
	close(PIDH);
	msg("$program already running (PID $currentPid)");
	exit 1;
}

# Process arguments
getopts('hdDfli:n:N:s:t:', \%opt);

if (defined($opt{h})) {
	print <<_HELP_
Usage: $0 [-d] [-D] [-f] [-h] [-l] [-i device] [-N prefix/mask] [-n ipv6addr]
          [-s facility] [-t seconds]
Where:
  -d              : Enable debugging (verbose output)
  -D              : Start in daemon mode
  -f              : Run in foreground (for deamon mode)
  -h              : Display this message
  -i device       : Monitoring interface (default: eth0)
  -l              : Enable learning mode
  -N prefix/mask  : Expected IPv6 subnet (network/subnet)
  -n ipv6Addr     : Expected IPv6 neighbor to be detected (Hex format)
  -s facility     : Syslog Facility (default: daemon)
  -t seconds      : Send RS every x seconds (demon mode)
_HELP_
	;
	exit 1;
}

if (defined($opt{d})) {
	$debug++;
	$foreground++; # Do not detach in debug mode!
	print STDOUT "+++ Debug enabled.\n";
} 

if (defined($opt{D})) {
	$daemon++;
	($debug) && print STDOUT "+++ Starting in daemon mode.\n";
} 

if (defined($opt{f})) {
	$foreground++;
	($debug) && print STDOUT "+++ Do not detach from console.\n";
} 

if (defined($opt{l})) {
	$learning++;
	if (!$daemon) {
		print STDOUT "Learning mode must be used when running as a daemon.\n";
		exit 1;
	}
	($debug) && print STDOUT "+++ Learning mode enabled.\n";
} 

if (defined($opt{N})) {
	if (!($expectedNetwork = new Net::IP($opt{N}))) {
		print STDOUT "Wrong IPv6 network/mask: " . $opt{n} . "\n";
		exit 1;
	}
	($debug) && print STDOUT "+++ Expected IPv6 network: " . $expectedNetwork->short() . "/" . \
			$expectedNetwork->prefixlen() . "\n";
}

if (defined($opt{n})) {
	if ($learning) {
		print STDOUT "Option '-r' and '-l' are mutually exclusive.\n";
		exit 1;
	}
	$expectedNeighbor = $opt{n};
	if ($expectedNeighbor !~ /^$IPv6_re$/) {
		print STDOUT "Wrong IPv6 address format: $expectedNeighbor.\n";
		exit 1;
	}
	($debug) && print STDOUT "+++ Expected IPv6 neighbor: $expectedNeighbor\n";
}
else {
	if (!$learning) {
		print STDOUT "No IPv6 neighbor defined.\n";
		exit 1;
	}
}

if (defined($opt{t})) {
	$time = $opt{t};
	if ($time !~ /[0-9]*/) {
		print STDOUT "Wrong time interval: $time\n";
		exit 1;
	}
	if ($time < $RTR_SOLICITATION_INTERVAL) {
		print STDOUT "Time interval cannot be lower than RTR_SOLICITATION_INTERVAL.\n";
		exit 1;
	}
}

if (defined($opt{s})) {
	$syslogFacility = $opt{s};
	# TODO: Validate the facility!
}

if (defined($opt{i})) {
	$interface = $opt{i};
	($debug) && print STDOUT "+++ Using interface $interface.\n";
}

# Get our IPv6 device
if (!($oDevice = Net::Frame::Device->new(dev => $interface))) {
	print STDOUT "Wrong interface: $interface.\n";
	exit 1;
}

# Deamonize if requested
if ($daemon) {
	if (!$foreground) {
		($debug) && print STDOUT "+++ Detaching from console.\n";
		if (!defined($pid = fork)) {
			print STDOUT "Cannot fork!\n";
			exit 1;
		}
		exit(0) if $pid;
		if (POSIX::setsid == -1) {
			print STDOUT "setsid failed!\n";
			exit 1;
		}
		if (!chdir("/")) {
			print STDOUT "Cannot changed working directory to /!\n";
			exit 1;
		}
		close(STDOUT);
		close(STDOUT);
		close(STDIN);
	}

	# Save our pid
	($debug) && print STDOUT "+++ Running with PID $$.\n";
	open(PIDH, ">$pidFile") || die "Cannot write PID file $pidFile: $!";
	print PIDH "$$";
	close(PIDH);

	# Main loop
	($debug) && msg("+++ Main loop started.");
	while(1) {
		SendRSPacket();
		sleep($time);
		# Exit loop if SIG-TERM received
		exit 0 if ($caught == 1);
	}
}
else {
	my $rc = SendRSPacket();
	exit $rc;
}
unlink($pidFile) if (-r $pidFile);
exit 0;

#
# SendRSPacket generates a RS ICMPv6 packet, send it over the wire and 
# listen for a reply.
#
sub SendRSPacket {
	my $rc = 0;

	# Create an IPv6 ICMP packet to ff02::1
	my $ip6 = Net::Frame::Layer::IPv6->new(
		version       => 6,
		trafficClass  => 0,
		flowLabel     => 0,
		nextHeader => NF_IPv6_PROTOCOL_ICMPv6,
		src => $oDevice->ip6,
		dst => $target,
		hopLimit => 255,
		payloadLength => 0,
	);
	$ip6->pack;

	# Create an ICMP Neighbor Solicitation payload
	my $solicit = Net::Frame::Layer::ICMPv6::RouterSolicitation->new(
		reserved => 0,
	);
	$solicit->pack;

	my $icmp = Net::Frame::Layer::ICMPv6->new(
		type => NF_ICMPv6_TYPE_ROUTERSOLICITATION,
	);
	$icmp->pack;

	# Prepare the packet
	my $oWrite = Net::Write::Layer3->new(
		dst => $target,
		family => NW_AF_INET6,
	);

	# Prepare the pcap filter to catch the neighbor response if any.
	my $oDump = Net::Frame::Dump::Online2->new(
		dev    => $oDevice->dev,
		filter => 'icmp6 and dst host ff02::1',
		timeoutOnNext => 3,
	);
	($debug) && msg("+++ Listening on " . $oDevice->dev . ".");
	$oDump->start;

	my $oSimple = Net::Frame::Simple->new(
		layers => [ $ip6, $icmp, $solicit ],
	);

	# Send our stuff!
	$oWrite->open;
	$oSimple->send($oWrite);
	$oWrite->close;
	($debug) && msg("+++ Router Solicitation packet sent!");

	# Now listen for potential router packets and process them
	until($oDump->timeout) {
		if (my $f = $oDump->next) {
			# Get a dump of the ICMPv6 packet and extract the source address
			# The extracted address is converted in IPv6 hex format
			my $pkt = new Net::Frame::Layer::ICMPv6->new(raw => $f->{raw});
			my $buf = substr($pkt->dump, 44, 32);
			my $buf2;
			for (my $i=0, my $j=0; $i<length($buf); $i++) {
				$buf2 = $buf2 . substr($buf, $i, 1); 
				if ($j == 3) {
					$buf2 = $buf2 . ":";
					$j = 0;
				}
				else {
					$j++;
				}
			}
			chop($buf2);
			my $ip = new Net::IP($buf2) or die(Net::IP::Error());
			# We drop our original packet (if we are the source)
			if ($oDevice->ip6 eq $ip->short()) {
				next;
			}
			# Process the detected neighbor
			$rc = processNeighbor($ip->short());
		}
	}
	$oDump->stop;
	return($rc);
}

sub processNeighbor
{
	my $detectedNeighbor = shift || return;
	($debug) && msg("+++ Detected IPv6 neighbor: " . $detectedNeighbor . ".");
	# Learning mode: Save the first detected neighbor
	if ($learning && !$expectedNeighbor) {
		$expectedNeighbor = $detectedNeighbor;
		msg("Learned IPv6 neighbor: $expectedNeighbor");
	}
	else {
		my $ip  = new Net::IP ($detectedNeighbor) or die (Net::IP::Error());
		my $ip2 = new Net::IP ($expectedNeighbor) or die (Net::IP::Error());
		if (Net::IP::ip_bincomp($ip->binip(), 'lt', $ip2->binip()) || 
		    Net::IP::ip_bincomp($ip->binip(), 'gt', $ip2->binip())) {
			msg("Rogue IPv6 neighbor detected: " . $detectedNeighbor . " (Expected: " . $expectedNeighbor . ").");
			return(1);
		}

		# Do we have a valid prefix?
		if ($expectedNetwork) {
			# Get our IPv6 subnet
			my $device = Net::Frame::Device->new(
				dev => $oDevice->dev,
			);
			my $ip  = new Net::IP($device->ip6) or die (Net::IP::Error());
			my $net = new Net::IP($expectedNetwork->short() . "/" . \
					      $expectedNetwork->prefixlen()) or die (Net::IP::Error());
			if ($ip->overlaps($net) == $IP_NO_OVERLAP) {
				msg("Unexpected IPv6 address detected: " . $ip->short() . \ " (Expected: " . $expectedNetwork->short() . "/" .  $expectedNetwork->prefixlen() . ").");
			}
		}
	}
	return(0);
}

sub msg {
	my $string = shift or return(0);
	if ($foreground || !$daemon) {
		print STDOUT $string . "\n";
	}
	else {
		openlog($program, 'pid', $syslogFacility);
		syslog('info', '%s', $string);
		closelog();
	}
}

# Eof
