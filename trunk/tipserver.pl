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
						{PrintError=>1, mysql_auto_reconnect => 1}) or carp DBI->errstr;

if($ARGV[0] && $ARGV[0] eq "DEBUG") { $IO::Socket::SSL::DEBUG = 1; } 

my ($sock, $s, $v_mode,$data_read,$maxlen,$flags);
my ($md5sum, $remote_md5);
my $check=0;
my @d_read;

start_sock();
$SIG{CHLD}= \&REAPER;
while (1) {
	carp "waiting for next connection.\n" if $tdebug;
	while(($s = $sock->accept())) {
		my $pid = fork;
		die "fork: $!" unless defined $pid;
		print "Pid: $pid\n" if $tdebug;
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
			@d_read=unpack("I I L L L I I I I L L I I s s s s L L L s s a**",$data_read);
			print "\n\n\n****EVENT DATA****\n",
				"sensor_id:$d_read[0]\n",
				"event_id:$d_read[1]\n",
				"tv_sec:$d_read[2]\n",
				"tv_usec:$d_read[3]\n",
				"sig_id:$d_read[4]\n",
				"sig_gen:$d_read[5]\n",
				"sig_rev:$d_read[6]\n",
				"class:$d_read[7]\n",
				"pri:$d_read[8]\n",
				"sip:$d_read[9]\n",
				"dip:$d_read[10]\n",
				"sp:$d_read[11]\n",
				"dp:$d_read[12]\n",
				"protocol:$d_read[13]\n",
				"pkt_action:$d_read[14]\n",
				"****PACKET DATA****\n",
				"sensor_id:$d_read[15]\n",
				"event_id:$d_read[16]\n",
				"tv_sec:$d_read[17]\n",
				"pkt_sec:$d_read[18]\n",
				"pkt_usec:$d_read[19]\n",
				"linktype:$d_read[20]\n",
				"pkt_len:$d_read[21]\n",
				"pkt:\n".print_format_packet(pack("H*",$d_read[22])) if $tdebug;
			
			print "remote md5: $remote_md5\n",
				"local md5: $md5sum\n",
				"****END DATA****\n\n\n" if $tdebug;
			
			$date = localtime();
			if ($md5sum eq $remote_md5) { $check = 1; }
			syswrite($s,$check,length($check));
			close($s);
			undef $s;
			print "connection closed.\n" if $tdebug;
			exit(0);
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
