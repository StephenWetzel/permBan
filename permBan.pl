#!/usr/bin/perl
# by Stephen Wetzel Oct 31 2014
#checks your fail2ban log and checks to see if ips have been banned multiple times.
#if so, it adds them to your hosts.deny file which permanently bans them.

#you should monitor your hosts.deny file to make sure it doesn't get too large.
#you should also rotate your fail2ban log to also ensure it doesn't get too large.


use strict;
use warnings;
#use autodie; #die on file not found

#$|++; #autoflush disk buffer

my $banCutoff = 5; #how many bans from one ip before we make it permanent
my $hostFile = '/etc/hosts.deny';
my $banFile = '/var/log/fail2ban.log';

my @oldBans; #grab these from /etc/hosts.deny
my @newBans; #grab these from /var/log/fail2ban.log
my %ips; #list of all ips from fail2ban.log, with counts of how many times they are in there

#first we need to look at old bands and create array of those and then filter those from the %ips hash
open my $ifile, '<', $hostFile;
my @fileArray = <$ifile>; #load up the input file into an array and we'll work with each line in the foreach
close $ifile;
foreach my $thisLine (@fileArray)
{#go through each line of the input file and look for bans
	#ALL: 123.4.56.789
	if ($thisLine =~ m/ALL: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
	{#has previously banned ip
		push (@oldBans, $1); #add this old ban to the list
		#print "\nOld Ban: $1";
	}
}

open $ifile, '<', $banFile;
@fileArray = <$ifile>; #load up the input file into an array and we'll work with each line in the foreach
close $ifile;
foreach my $thisLine (@fileArray)
{#go through each line of the input file and look for bans
	#2014-10-30 04:50:15,322 fail2ban.actions: WARNING [ssh] Ban 123.4.56.789
	if ($thisLine =~ m/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} fail2ban.actions: WARNING \[\w+\] Ban (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
	{#has ip to be banned
		my $thisIp = $1;
		if (!grep(/^$thisIp$/, @oldBans)) 
		{#not in list of previous bans
			
			#print "\nNew IP: $thisIp\n";
			#print "old bans: @oldBans\n";
			
			$ips{$1}++;
		}
	}
}

foreach my $ip (keys %ips)
{#go through the ips and see if count is greater than our limit
	if ($ips{$ip} >= $banCutoff)
	{#ban this ip
		push @newBans, $ip;
	}
}

open my $ofile, '>>', $hostFile;
foreach my $thisBan (@newBans)
{
	#ALL: 123.4.56.789
	
	print $ofile "ALL: $thisBan\n";
	print time . " ALL: $thisBan\n";
}
close $ofile;
#print "\nDone\n\n";
