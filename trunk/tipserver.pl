#!/usr/bin/perl

## Threat Intelligence Project servah v1.0
## cummingsj@gmail.com

# Copyright (C) 2010 JJ Cummings

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
use Digest::MD5(qw(md5_hex));

if($ARGV[0] eq "DEBUG") { $IO::Socket::SSL::DEBUG = 1; } 

my ($sock, $s, $v_mode,$data_read,$maxlen,$flags);
my ($md5sum, $remote_md5);
my $check=0;
my @d_read;

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
    warn "unable to create socket: ", &IO::Socket::SSL::errstr, "\n";
    exit(0);
}else{ warn "socket created: $sock.\n"; }

while (1) {
  warn "waiting for next connection.\n";
  
  while(($s = $sock->accept())) {
      my ($peer_cert, $subject_name, $issuer_name, $date, $str);
      
      if( ! $s ) {
	  warn "error: ", $sock->errstr, "\n";
	  next;
      }
      
      warn "connection opened ($s).\n";
      
      if( ref($sock) eq "IO::Socket::SSL") {
	  $subject_name = $s->peer_certificate("subject");
	  $issuer_name = $s->peer_certificate("issuer");
      }
      
      warn "\t subject: '$subject_name'.\n";
      warn "\t issuer: '$issuer_name'.\n";
      
      sysread($s,$data_read,2048);
      
      if ($data_read=~/^EVENT:/) {
		$data_read=~s/^EVENT://;
		$data_read=~/^\w{32}/;
		$remote_md5=$&;
		$data_read=~s/^\w{32}//;
		$md5sum = md5_hex( $data_read );
		@d_read=unpack("s s l l s s s s s l l s s s s",$data_read);
	  }elsif ($data_read=~/^PACKET:/) {
		$data_read=~s/^PACKET://;
		$data_read=~/^\w{32}/;
		$remote_md5=$&;
		$data_read=~s/^\w{32}//;
		$md5sum = md5_hex( $data_read );
		@d_read=unpack("s s l l l s s a*",$data_read);
	  }
      warn "\t data read: '@d_read'.\n",
		"\t remote md5: $remote_md5\n",
		"\t local md5: $md5sum\n";
  
      $date = localtime();
      if ($md5sum eq $remote_md5) { $check = 1; }
		syswrite($s,$check,length($check));
      close($s);
      warn "\t connection closed.\n";
  }
}


$sock->close();

warn "loop exited.\n";
__END__
