#!/usr/bin/perl -I..

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
use IO::Socket;
use IO::Socket::SSL;
use SnortUnified qw(:ALL);
use SnortUnified::MetaData(qw(:ALL));
use SnortUnified::TextOutput(qw(:ALL));
use Sys::Hostname;
use Digest::MD5(qw(md5_hex));

my ($v_mode, $sock, $buf, $data_send, $flags);

my $file = shift;
my $record = undef;
my $ufdata;
my @event;

unless ($file) { die "You need to define a unified template!\n"; }

my $sids = get_snort_sids("/home/jj/Documents/Development/threatintel/alerts/sid-msg.map",
                       "/home/jj/Documents/Development/threatintel/alerts/gen-msg.map");
my $class = get_snort_classifications("/home/jj/Documents/Development/threatintel/alerts/classification.config");

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
            print("$field:" . $record->{$field} . "\n");
            push (@event,$record->{$field});
        }elsif ($field eq "pkt") {
			my $pkt_data = unpack("H*",$record->{'pkt'});
			print ("$field:$pkt_data\n");
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
	
	if(!($sock = IO::Socket::SSL->new( PeerAddr => 'localhost',
					   PeerPort => '9000',
					   Proto    => 'tcp',
					   SSL_use_cert => 1,
					   SSL_verify_mode => 0x01,
					   SSL_passwd_cb => sub { return "opossum" },
					 ))) {
	    warn "unable to create socket: ", &IO::Socket::SSL::errstr, "\n";
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
	    "\t '$subject_name' \n\t '$issuer_name'.\n\n";
	
	
	syswrite($sock,$data_send,length($data_send));
	sysread($sock,$buf,128);
	warn "Checksum Ok\n" if $buf eq 1;
	$sock->close();
}

__END__
