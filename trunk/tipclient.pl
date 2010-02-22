#!/usr/bin/perl

## Threat Intelligence Project client v1.0
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
use IO::Socket::SSL;
use SnortUnified qw(:ALL);
use Sys::Hostname;
use Digest::MD5(qw(md5_hex));


my ($v_mode, $sock, $buf, $data_send, $flags, $dbg_pkt, $pkt_data);

my $file = shift;
my $record = undef;
my $ufdata;
my @event;

# Send debug output to stdout
my $termdebug=1;

# obf ip address range info, this must be a valid cidr noted block!
my $obf_cidr="0";

# ofb payloads/pkts
my $obf_pkts=0;

unless ($file) { die "You need to define a unified template!\n"; }

my $uffile = undef;
my $old_uffile = undef;

$uffile = &get_latest_file($file) || die "no files matching $file - $!\n";
$ufdata = openSnortUnified($uffile) || die "unable to open $uffile $!\n";

while (1) {
  $old_uffile = $uffile;
  $uffile = &get_latest_file($file) || die "no files to get";
  
  if ( $old_uffile ne $uffile ) {
    closeSnortUnified();
    $ufdata = openSnortUnified($uffile) || die "cannot open $uffile";
  }

  &read_records();
}

sub read_records() {
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
    if ($record->{'sig_id'} && $record->{'protocol'}) {
		my $p_event = pack("s s l l s s s s s l l s s s s",@event);
		my $md5sum=md5_hex( $p_event );
		$p_event="EVENT:$md5sum".$p_event;
		data_sender($p_event);
		@event=();
	}elsif($record->{'pkt_len'}) {
		my $p_event = pack("s s l l l s s a*",@event);
		my $md5sum=md5_hex( $p_event );
		$p_event="PACKET:$md5sum".$p_event;
		data_sender($p_event);
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
	my $ip = new Net::IP ($obf_cidr);
	my $new_target = $target;
	do {
		my $quad_address = $ip->ip();
		$quad_address = ip_todec($quad_address);
		if ($target == $quad_address) { 
			$new_target = '0';
		}
	} while (++$ip);
	return $new_target;
}

# Convert quad IP to decimal IP
sub ip_todec {
	my $ip_address = shift;
	my @octets = split(/\./, $ip_address);
	my $DEC = ($octets[0]*1<<24)+($octets[1]*1<<16)+($octets[2]*1<<8)+($octets[3]);
	return $DEC;
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
	
	my $data_send = shift;
	
	# Check to make sure that we were not accidentally run in the wrong
	# directory:
	unless (-d "certs") {
	    if (-d "../certs") {
		chdir "..";
	    } else {
		die "Your certs need to be under the certs path right now!!\n";
	    }
	}
	
	if(!($sock = IO::Socket::SSL->new( PeerAddr => 'rootedyour.com',
					   PeerPort => '9000',
					   Proto    => 'tcp',
					   SSL_use_cert => 1,
					   SSL_verify_mode => 0x01,
					   SSL_passwd_cb => sub { return "opossum" },
					 ))) {
	    warn "unable to create socket: ", &IO::Socket::SSL::errstr, "\n" if $termdebug;
	    exit(0);
	} else {
	    warn "connect ($sock).\n" if ($IO::Socket::SSL::DEBUG);
	}
	
	# check server cert.
	my ($subject_name, $issuer_name, $cipher);
	if( ref($sock) eq "IO::Socket::SSL") {
	    $subject_name = $sock->peer_certificate("subject");
	    $issuer_name = $sock->peer_certificate("issuer");
	    $cipher = $sock->get_cipher();
	}
	warn "cipher: $cipher.\n", "server cert:\n", 
	    "\t '$subject_name' \n\t '$issuer_name'.\n\n" if $termdebug;
	
	
	syswrite($sock,$data_send,length($data_send));
	sysread($sock,$buf,128);
	die "Checksum epic FAIL!\n" unless $buf eq 1;
	$sock->close();
}

__END__
