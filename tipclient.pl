#!/usr/bin/perl

## Threat Intelligence Project client v1.0 Dev
## tip@rootedyour.com

# Copyright (C) 2010 The rootedyour.com Team

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

use strict;
use warnings;
use Net::IP;
use IO::Socket;
use Socket;
use IO::Socket::SSL qw();
use SnortUnified qw(:ALL);
use Sys::Hostname;
use Digest::MD5(qw(md5_hex));
use Getopt::Long qw(:config no_ignore_case bundling);

my ($termdebug,$file,%config);
my $obf_cidr="0";
my $obf_pkts=0;
my $configfile=0;
my $localtest=0;

tipper();

#read options at runtime
GetOptions ( "t=s" => \$file,
			"C=s" => \$obf_cidr,
                        "P!" => \$obf_pkts,
                        "c=s" => \$configfile,
                        "v!" => \$termdebug,
                        "T!" => \$localtest,
                        "help|?" => sub { help() });
print "\n\nFlag Debug Information:\n" if $termdebug;                        
print "\tTemplat file is: $file\n" if $file && $termdebug;
print "\tCIDR Blocks to be OBFuscated $obf_cidr\n" if $obf_cidr && $termdebug;
print "\tObfuscate Payload Flag is Set\n" if $obf_pkts && $termdebug;
print "\tVerbose Flag is Set\n" if $termdebug;
print "\tLocal test only - No server connection is set\n" if $localtest && $termdebug;
print "\tConfig files is $configfile\n" if $termdebug;
print "\tSleeping.....\n" if $termdebug;

my $record = undef;
my $ufdata;
my @event;


my $uffile = undef;
my $old_uffile = undef;
my $client = undef;

my ($v_mode, $buf, $data_send, $flags, $dbg_pkt, $pkt_data);

# Set some defaults for the config (based on current hardcoded values).
$config{'server'}='rootedyour.com';
$config{'port'}='9000';
$config{'template'}='./snort.log';
$config{'tip_network'}="tip_network";
$config{'tip_user'}="tip_user";
$config{'obf_cidr'}=0;

# Read a config file
if ( $configfile ) {
	open my $config, '<', $configfile or die "Unable to open config file $configfile $!";
    	while(<$config>) {
        	chomp; 
        	if ( $_ =~ m/^[a-zA-Z]/) {
                	(my $key, my @value) = split /=/, $_;
                	$config{$key} = join '=', @value;
        	}    
    	}    
	close $config;
}

if ($termdebug) {
	print "
\t- Config file: TIP Server		$config{'server'}
\t- Config file: TIP Port		$config{'port'}
\t- Config file: Unified Template	$config{'template'}  
\t- Config file: TIP User		$config{'tip_user'}
\t- Config file: TIP network		$config{'tip_network'}
\t- Config file: Obfuscated networks	$config{'obf_cidr'}
";
	if ($file) {
		print "* template set on command line - $file trumps $config{'template'} \n";
	}
	if ($obf_cidr) {
		print "* Obf_cidr set on command line - $obf_cidr trumps $config{'obf_cidr'}\n";
	}
}



unless ($file) { 
	$file=$config{'template'};
}
unless ($obf_cidr) {
	$obf_cidr=$config{'obf_cidr'};
}

sleep(5) if $termdebug;

$uffile = &get_latest_file($file) || die "no files matching $file - $!\n";

print "about to open $uffile \n";
$ufdata = openSnortUnified($uffile) || die "unable to open $uffile $!\n";

while (1) {
  $old_uffile = $uffile;
  $uffile = &get_latest_file($file) || die "no files to get";
  
  if ( $old_uffile ne $uffile ) {
    closeSnortUnified();
    $ufdata = openSnortUnified($uffile) || die "cannot open $uffile";
  }

  &read_records($client);
}

sub help {
	
print<<__EOT;
	
Usage ./tipclient.pl -t <unified2 template name> -C <cidr to obfuscate> -Pv
	
-t <unified2 template name> (the base path and template name of your unified2 files) 
-c <config file> 	Filename of a config file 
-C <cidr block> specify what <cidr block> to obfuscate, you can speficy
   multiple entries, they must be comma separated and not contain a space
-P Obfuscate the payload
-v run in verbose (debug) mode.
-T run in local-test mode. Does not connect to a server. Added for debugging and development.
__EOT
exit(0);
}

sub tipper {

print<<__EOT;


## Threat Intelligence Project client v1.0 Dev ##
   Copyright (C) 2010 The rootedyour.com Team
	     http://www.rootedyour.com/tip
	          tip\@rootedyour.com
__EOT
}

sub read_records() {
	$client=shift;
  while ( $record = readSnortUnifiedRecord() ) {
    
    foreach my $field ( @{$record->{'FIELDS'}} ) {
        if ( $field ne 'pkt' ) {
            print("$field:" . $record->{$field} . "\n") if ($termdebug && $field ne "sip" && $field ne "dip");
            if ($obf_cidr ne "0" && $field eq "sip") { $record->{$field} = obf_cidr($record->{$field}); } 
            print("$field:" . inet_ntoa(pack('N', $record->{$field})) . "\n") if ($termdebug && $field eq "sip");
            if ($obf_cidr ne "0" && $field eq "dip") { $record->{$field} = obf_cidr($record->{$field}); } 
            print("$field:" . inet_ntoa(pack('N', $record->{$field})) . "\n") if ($termdebug && $field eq "dip");
            push (@event,$record->{$field});
        }elsif ($field eq "pkt") {
			$pkt_data=unpack("H*",$record->{'pkt'}) unless $obf_pkts;
			$pkt_data="5041434b45542044415441204f4d4954544544" if $obf_pkts;
			$dbg_pkt=print_format_packet($record->{'pkt'}) unless $obf_pkts;
			$dbg_pkt="PACKET DATA OMITTED" if $obf_pkts;
			print ("$field:\n$dbg_pkt\n") if $termdebug;
			push (@event,$pkt_data);
		}
    }
    if ($event[22] && $event[22] ne "") {
		my $p_event = pack("s s l l s s s s s l l s s s s s s l l l s s a*",@event);
		my $md5sum = md5_hex( $p_event );
		$p_event = $md5sum.$p_event;
		data_sender($p_event,$client);
		@event=();
	}
  }

  print("Exited while. Deadreads is $UF->{'DEADREADS'}.\n") if $debug;
  
  return 0;
}

closeSnortUnified();

# Make packet debug output pretty!
sub print_format_packet($) {
    my $data = $_[0];
    my $buff = '';
    my $hex = '';
    my $ascii = '';
    my $len = length($data);
    my $count = 0;
    my $ret = "";

    for (my $i = 0;$i < length($data);$i += 16) {
       $buff = substr($data,$i,16);
       $hex = join(' ',unpack('H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2 H2',$buff));
       $ascii = unpack('a16', $buff);
       $ascii =~ tr/A-Za-z0-9;:\"\'.,<>[]\\|?\/\`~!\@#$%^&*()_\-+={}/./c;
       $ret = $ret . sprintf("%.4X: %-50s%s\n", $count, $hex, $ascii);
       $count += length($buff);
    }
  return $ret;
}

# Obfuscate specified CIDR block!
sub obf_cidr {
	my $target = shift;
	my ($ip,$quad_address);
	my @obf_cidrs = split(/,/,$obf_cidr);
	foreach $obf_cidr(@obf_cidrs) {
		chomp($obf_cidr);
		$ip = new Net::IP ($obf_cidr);
		# The old method used to check if an IP was in a CIDR was taking way too long (I gave up after a couple of minutes of waiting).
		# This method looks for the high and low values and checks if the target is within range.
		my $first_ip=$ip->ip();
		my @octets = split(/\./, $first_ip);
		my $long_first_ip = ($octets[0]*1<<24)+($octets[1]*1<<16)+($octets[2]*1<<8)+($octets[3]);
		my $long_last_ip=$ip->last_int();	
		if ( ($target le $long_last_ip) && ($target ge $long_first_ip) ) {
			# Data type decision here required. Do we want to keep ip address' as a decimal?
			# This will create limitations with obf, and in future maybe hostnames would be needed
			# Not making this change until someone else says go.
			# my $obf_seed=$config{'tip_user'} . $config{'tip_network'} . $target;
			# return md5_hex($obf_seed);
			return "0";
		}
	}
	return $target;
}

# Convert quad IP to decimal IP
sub ip_todec {
	my $ip_address = shift;
	my @octets = split(/\./, $ip_address);
	my $DEC = ($octets[0]*1<<24)+($octets[1]*1<<16)+($octets[2]*1<<8)+($octets[3]);
	return $DEC;
}

sub server_connect {
	my $func=shift;
	# Check to make sure that we were not accidentally run in the wrong
	# directory:
	if ($func==0) {
		unless (-d "certs") {
		    if (-d "../certs") {
			chdir "..";
		    } else {
			die "Your certs need to be under the certs path right now!!\n";
		    }
		}
		
		$client = IO::Socket::SSL->new( PeerAddr => "$config{'server'}",
						   PeerPort => "$config{'port'}",
						   Proto    => 'tcp',
						   SSL_use_cert => 1,
						   SSL_verify_mode => 0x01,
						   SSL_passwd_cb => sub { return "opossum" },
						 ) || warn "unable to create socket: ", &IO::Socket::SSL::errstr, "\n";
			
		# check server cert.
		my ($subject_name, $issuer_name, $cipher);
		if( ref($client) eq "IO::Socket::SSL") {
		    $subject_name = $client->peer_certificate("subject");
		    $issuer_name = $client->peer_certificate("issuer");
		    $cipher = $client->get_cipher();
		}
		warn "cipher: $cipher.\n", "server cert:\n", 
		    "\t '$subject_name' \n\t '$issuer_name'.\n\n" if $termdebug && $cipher;
		
		return $client;   
		 
	}
	if ($func==1) {$client->close();}	
}
	
sub get_latest_file($) {
  my $filemask = shift;
  my @ls = <$filemask*>;
  my $len = @ls;
  my $uf_file = "";

  if ($len) {
    # Get the most recent file
    my @tmparray = sort{$b cmp $a}(@ls);
    $uf_file = shift(@tmparray);
  } else {
    $uf_file = undef;
  }
  return $uf_file;
}

# Send the prepared data to the server!
sub data_sender {
	unless ($localtest) {
		$client = server_connect(0);
		my $data_send = shift;

		unless ($client->errstr) {
			syswrite($client,$data_send,length($data_send));
			sysread($client,$buf,128);
			print "Checksum Verify: $buf\n" if ($termdebug && $buf eq 1);
			die "Checksum epic FAIL! $buf\n" unless $buf eq 1;
		}
		server_connect(1);
	}
}

__END__
