#!/usr/bin/perl

## Threat Intelligence Project servah v1.0 Dev
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
use DBI;
use Digest::MD5(qw(md5_hex));
use POSIX qw(:sys_wait_h);
use Carp;


# Send debug output to stdout
my $tdebug=1;

# Set our database connection information (mysql only)
my $dbname = 'snort';
my $dbhost = 'localhost';
my $dbuname = 'snorty';
my $dbpass = 'secret';

# Build or database connection to mysql, enable auto reconnect if the 
# server goes away and throw a warn
my $dbh = DBI->connect("DBI:mysql:database=$dbname;host=$dbhost",
						"$dbuname","$dbpass",
						{PrintError=>1, mysql_auto_reconnect => 1, mysql_connect_timeout=>30}) or carp DBI->errstr;

if($ARGV[0] && $ARGV[0] eq "DEBUG") { $IO::Socket::SSL::DEBUG = 1; } 

my ($sock, $s, $v_mode,$data_read,$maxlen,$flags);
my ($md5sum, $remote_md5);
my $check=0;
my @d_read=undef;

start_sock();
#$SIG{CHLD}= \&REAPER;
while (1) {
	carp "waiting for next connection.\n" if $tdebug;
	while(($s = $sock->accept())) {
		#my $pid = fork;
		my $pid = 0;
		#die "fork: $!" unless defined $pid;
		#print "Pid: $pid\n" if $tdebug;
		if ($pid == 0) {
			my ($peer_cert, $subject_name, $issuer_name, $date, $str);
			if( ! $s ) {
				carp "error: ", $sock->errstr, "\n";
				next;
			}
			my ($client_port,$client_address) = sockaddr_in($s->peername);
			$client_address = inet_ntoa($client_address);
			carp "connection opened ($s) from $client_address\n" if $tdebug;
			
			if( ref($sock) eq "IO::Socket::SSL") {
				$subject_name = $s->peer_certificate("subject");
				$issuer_name = $s->peer_certificate("issuer");
			}
			
			#warn "\t subject: '$subject_name'.\n";
			#warn "\t issuer: '$issuer_name'.\n";
			
			sysread($s,$data_read,2048);
			
			$data_read=~/^\w{32}/;
			$remote_md5=$&;
			$data_read=~s/^\w{32}//;
			$md5sum = md5_hex( $data_read );
			@d_read=unpack("a32 a32 I I L L L I I I I L L I I s s s s L L L s s a*",$data_read);
			print "\n\n\n****EVENT DATA****\n",
			    "sensor_name:$d_read[0]\n",
			    "sensor_interface:$d_read[1]\n",
				"sensor_id:$d_read[2]\n",
				"event_id:$d_read[3]\n",
				"tv_sec:$d_read[4]\n",
				"tv_usec:$d_read[5]\n",
				"sig_id:$d_read[6]\n",
				"sig_gen:$d_read[7]\n",
				"sig_rev:$d_read[8]\n",
				"class:$d_read[9]\n",
				"pri:$d_read[10]\n",
				"sip:$d_read[11]\n",
				"dip:$d_read[12]\n",
				"sp:$d_read[13]\n",
				"dp:$d_read[14]\n",
				"protocol:$d_read[15]\n",
				"pkt_action:$d_read[16]\n",
				"****PACKET DATA****\n",
				"sensor_id:$d_read[17]\n",
				"event_id:$d_read[18]\n",
				"tv_sec:$d_read[19]\n",
				"pkt_sec:$d_read[20]\n",
				"pkt_usec:$d_read[21]\n",
				"linktype:$d_read[22]\n",
				"pkt_len:$d_read[23]\n",
				"pkt:\n".print_format_packet(pack("H*",$d_read[24])) if $tdebug;
			
			print "remote md5: $remote_md5\n",
				"local md5: $md5sum\n",
				"****END DATA****\n\n\n" if $tdebug;
			
			$date = localtime();
			if ($md5sum eq $remote_md5) { $check = 1; }
			syswrite($s,$check,length($check));
			#close($s);
			#undef $s;
			print "connection closed.\n" if $tdebug;
			print "Writing mysql Data\n" if $tdebug;
					
			# check for our sensor and interface values, create if they don't exist
			my $sth = $dbh->prepare("SELECT sid, hostname FROM sensor where hostname = '$d_read[0]' and interface = '$d_read[1]'");
			$sth->execute();
			my @data = $sth->fetchrow_array();
			my $sensorid=$data[0];
			unless ($data[1]) {
				$dbh->do("INSERT INTO sensor (hostname,interface,detail,encoding) VALUES ('$d_read[0]','$d_read[1]',1,0)") or errorkill($dbh->errstr);
				$sth = $dbh->prepare("SELECT sid FROM sensor where hostname = '$d_read[0]' and interface = '$d_read[1]'");
				$sth->execute();
				$sensorid = $sth->fetchrow_array();
			}
			my $cid = getcid($sensorid);
			
			my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($d_read[20]);
			$year=$year+1900;
			$mon=$mon+1;
			
			# Insert event and iphdr info (for every packet)
			$dbh->do("INSERT INTO event (sid,cid,signature,timestamp) VALUES ('$sensorid','$cid','$d_read[6]','$year-$mon-$mday $hour:$min:$sec')") or errorkill($dbh->errstr);
			$dbh->do("INSERT INTO iphdr (sid,cid,ip_src,ip_dst,ip_proto) VALUES ('$sensorid','$cid','$d_read[11]','$d_read[12]','$d_read[15]')") or errorkill($dbh->errstr);
			
			my $proto;
			
			# TCP packet info
			if ($d_read[15] == 6){
				$dbh->do("INSERT INTO tcphdr (sid,cid,tcp_sport,tcp_dport,tcp_flags) VALUES ('$sensorid','$cid','$d_read[13]','$d_read[14]',0)") or errorkill($dbh->errstr);
				# tag hash population
				$proto="TCP";
			}
			
			# UDP packet info
			elsif($d_read[15] == 17){
				$dbh->do("INSERT INTO udphdr (sid,cid,udp_sport,udp_dport) VALUES ('$sensorid','$cid','$d_read[13]','$d_read[14]'')") or errorkill($dbh->errstr);
				# tag hash population
				$proto="UDP";
			}
			
			# ICMP packet info
			elsif($d_read[15] == 1){
				$dbh->do("INSERT INTO icmphdr (sid,cid,icmp_type,icmp_code) VALUES ('$sensorid','$cid','$d_read[13]','$d_read[14]'')") or errorkill($dbh->errstr);
				# tag hash population
				$proto="ICMP";
			}
			
			# Unsupported packet type by snort schema 107
			else {
				print "\n\n!!!!!!!!!!!!UNSUPPORTED PACKET TYPE: $d_read[15]\n\n" if $tdebug;
			}		
			
			my $pkthex=unpack("H*", $d_read[24]);
			# It's a regular packet associated with a regular event!
			$dbh->do("INSERT INTO data (sid,cid,data_payload) VALUES ('$sensorid','$cid','$pkthex')") or errorkill($dbh->errstr);
			$dbh->do("UPDATE sensor SET last_cid = '$cid' WHERE sid = '$sensorid'") or errorkill($dbh->errstr);
			
			#exit(0);
		}
	}
}

sub REAPER {
1 until (-1 == waitpid(-1,WNOHANG));
$SIG{CHLD} = \&REAPER;
}

sub start_sock {
	# Build our listening socket for the server itself to receive data from the
	# tip client
	$sock = IO::Socket::SSL->new( Listen => 5,
					   LocalAddr => 'localhost',
					   LocalPort => 9000,
					   Proto     => 'tcp',
					   Reuse     => 1,
					   SSL_verify_mode => 0x01,
					   SSL_passwd_cb => sub {return "bluebell"},
					   SSL_cipher_list => 'AES256-SHA',
					 );
					 
	if(!$sock ) {
	    carp "unable to create socket: ", &IO::Socket::SSL::errstr, "\n";
	    exit(0);
	}else{ print "socket created: $sock.\n" if $tdebug; }
	return $sock;
}

# Generate an updated cid
sub getcid {
	my $sensorid = shift;
	my $sth = $dbh->prepare("SELECT MAX(cid) from event where sid = $sensorid");
	my $cid;
	$sth->execute();
	if ($sth) {
		$cid = $sth->fetchrow_array();
		$cid++;
	}else{
		$cid = 1;
	}
	print "\ncid: $cid" if $tdebug;
	return $cid;
}

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

sub insert_event {
	
}
$sock->close();

__END__
