#
# PFLog.pm
# NetPacket::PFLog
#
# Decodes OpenBSD's pflog(4) packets
#
# Copyright (c) 2003-2014 Joel Knight <knight.joel@gmail.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#
# $jwk: PFLog.pm,v 1.39 2014/02/02 00:35:51 jwk Exp $

package NetPacket::PFLog;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use NetPacket;
use NetPacket::IP;
use NetPacket::IPv6;
use Socket;

my $myclass;
BEGIN {
	$myclass = __PACKAGE__;
	$VERSION = "0.03";
}
sub Version () { "$myclass v$VERSION" }

BEGIN {
	@ISA = qw(Exporter NetPacket);

	@EXPORT = qw(
	);

	@EXPORT_OK = qw(
		pflog_strip
		DLT_PFLOG
		PFLOG_HDRLEN
	);

	%EXPORT_TAGS = (
		ALL	=> [@EXPORT, @EXPORT_OK],
		strip	=> [qw(pflog_strip)],
		DLT	=> [qw(DLT_PFLOG)],
	);
}

#  data link type for pflog in the pcap dump
use constant DLT_PFLOG => 117;

#  maximum size of the header (in bytes) in the pcap dump
use constant PFLOG_HDRLEN => 100;

#  packet filter constants (src/sys/net/pfvar.h)
my %PF_DIR = (
	1 => "in",
	2 => "out"
);
my %PF_ACTION = (
	0 => "pass",
	1 => "block",
	2 => "scrub"
);
my %PF_REASON = (
	0 => "match",
	1 => "bad-offset",
	2 => "fragment",
	3 => "short",
	4 => "normalize",
	5 => "memory",
	6 => "bad-timestamp",
	7 => "congestion",
	8 => "ip-options",
	9 => "proto-cksum",
	10 => "state-mismatch",
	11 => "state-insert",
	12 => "state-limit",
	13 => "src-limit",
	14 => "syn-proxy"
);

#  decode(packet, parent_packet, additional_data)
#  create a new NetPacket::PFLog object. decode the pflog header
#  from 'packet' and assign each field to the object.
#  return the NetPacket::PFLog object.
sub decode {
	my $class = shift;
	my ($pkt, $parent, @rest) = @_;
	my $self = {};

	my ($len, $af, $action, $reason, $ifname, $ruleset, $rulenr, 
		$subrulenr, $uid, $pid, $rule_uid, $rule_pid, $dir,
		$rewritten, $naf, $pad, @src_addr, @dst_addr,
		$src_port, $dst_port, $data);

	$self->{_parent} = $parent;
	$self->{_frame} = $pkt;

	# based on pfloghdr struct in:
	# [OpenBSD]/src/sys/net/if_pflog.h r1.24
	if (defined $pkt) {
		($len, $af, $action, $reason, $ifname, $ruleset, $rulenr, 
			$subrulenr, $uid, $pid, $rule_uid, $rule_pid, $dir,
			$rewritten, $naf, $pad, @src_addr[0..3], @dst_addr[0..3],
			$src_port, $dst_port, $data) =
			unpack("CCCCa16a16NNIiIiCCCaN4N4nna*", $pkt);

		#  strip trailing NULs
		$ifname =~ s/\W//g;
		$ruleset =~ s/\W//g;

		$self->{len} = $len;
		$self->{af} = $af;
		$self->{action} = $PF_ACTION{$action};
		$self->{reason} = $PF_REASON{$reason};
		$self->{ifname} = $ifname;
		$self->{ruleset} = $ruleset;
		$self->{rulenr} = $rulenr;
		$self->{subrulenr} = $subrulenr;
		$self->{uid} = $uid;
		$self->{pid} = $pid;
		$self->{rule_uid} = $rule_uid;
		$self->{rule_pid} = $rule_pid;
		$self->{dir} = $PF_DIR{$dir};
		$self->{rewritten} = $rewritten;
		$self->{naf} = $naf;
		$self->{pad} = $pad;
		SWITCH: {
			($af == 2) && do {
				$self->{src_ip} = NetPacket::IP::to_dotquad($src_addr[0]);
				$self->{dst_ip} = NetPacket::IP::to_dotquad($dst_addr[0]);
			};
			($af == 24) && do {
				$self->{src_ip} = NetPacket::IPv6::int_to_hexstr(@src_addr);
				$self->{dst_ip} = NetPacket::IPv6::int_to_hexstr(@dst_addr);
			};
		}
		$self->{src_port} = $src_port;
		$self->{dst_port} = $dst_port;

		$self->{data} = $data;
	}

	bless ($self, $class);
	return $self;
}

# make an alias
undef &pflog_strip;
*pflog_strip = \&strip;

# strip header from packet and return the data contained in it
sub strip {
	my ($pkt, @rest) = @_;

	my $pflog_obj = NetPacket::PFLog->decode($pkt);
	return $pflog_obj->{data};
}   

#  encode(ip_pkt)
#  re-encapsulate an already decapsulated pflog packet
sub encode {
	my $class = shift;
	my $self = shift;
	my $ip = $_[0];

	#  convert these items back into the integers from whence they came
	my %rev_DIR = reverse %PF_DIR;
	my %rev_ACTION = reverse %PF_ACTION;
	my %rev_REASON = reverse %PF_REASON;

	my $dir = $rev_DIR{$self->{dir}};
	my $action = $rev_ACTION{$self->{action}};
	my $reason = $rev_REASON{$self->{reason}};

	my (@src_ip, @dst_ip);

	SWITCH: {
		($self->{af} == 2) && do {
			$src_ip[0] = unpack("N", inet_aton($self->{src_ip}));
			$dst_ip[0] = unpack("N", inet_aton($self->{dst_ip}));
		};
		($self->{af} == 24) && do {
			@src_ip = NetPacket::IPv6::hexstr_to_int($self->{src_ip});
			@dst_ip = NetPacket::IPv6::hexstr_to_int($self->{dst_ip});
		};
	}

	# [OpenBSD]/src/sys/net/if_pflog.h r1.24
	my $packet = pack("CCCCa16a16NNIiIiCCCaN4N4nna*",
		$self->{len}, $self->{af}, $action, $reason, $self->{ifname}, 
		$self->{ruleset}, $self->{rulenr}, $self->{subrulenr},
		$self->{uid}, $self->{pid}, $self->{rule_uid},
		$self->{rule_pid}, $dir, $self->{rewritten},
		$self->{naf}, $self->{pad}, @src_ip[0..3], @dst_ip[0..3], 
		$self->{src_port}, $self->{dst_port}, $ip);

	return $packet;
}

1;

__END__


=head1 NAME

C<NetPacket::PFLog> - Assembling and disassembling OpenBSD's Packet
Filter log header.

=head1 SYNOPSIS

  use NetPacket::PFLog;

  $pfl_obj = NetPacket::PFLog->decode($raw_pkt);
  $pfl_pkt = NetPacket::PFLog->encode();
  $pfl_data = NetPacket::PFLog::strip($raw_pkt);

=head1 DESCRIPTION

C<NetPacket::PFLog> provides a set of routines for assembling and
disassembling the header attached to packets logged by OpenBSD's
Packet Filter.  

=head2 Methods

=over

=item C<NetPacket::PFLog-E<gt>decode([RAW PACKET])>

Decode the raw packet data given and return an object containing
instance data.  This method will quite happily decode garbage input. It
is the responsibility of the programmer to ensure valid packet data is
passed to this method.

=item C<NetPacket::PFLog-E<gt>encode()>

Return a PFLog packet encoded with the instance data specified.

=back

=head2 Functions

=over

=item C<NetPacket::PFLog::strip([RAW PACKET])>

Return the actual packet logged by Packet Filter that the PFLog header
is describing. This data is suitable to be used as input for other
C<NetPacket::*> modules.

This function is equivalent to creating an object using the
C<decode()> constructor and returning the C<data> field of that
object.

=back

=head2 Instance data

The instance data for the C<NetPacket::PFLog> object consists of
the following fields:

=over

=item len

The length of the pflog header.

=item af

The Address Family which denotes if the packet is IPv4 or IPv6.

=item action

The action (block, pass, match, nat, etc) that was taken on the packet.

=item reason

The reason that the action was taken.

=item ifname

The name of the interface the packet was passing through.

=item ruleset

The name of the subruleset that the matching rule is a member of. If
the value is empty, the matching rule is in the main ruleset.

=item rulenr

The rule number that the packet matched.

=item subrulenr

The rule number in the subruleset that the packet matched. The value
will be 2^32-1 if the packet matched in the main ruleset only.

=item uid

The uid of the local process that generated the packet that was logged, if
applicable.

=item pid

The pid of the local process that generated the packet that was logged, if
applicable.

=item rule_uid

The uid of the process that inserted the rule that caused the packet to be
logged.

=item rule_pid

The pid of the process that inserted the rule that caused the packet to be
logged.

=item dir

The direction the packet was travelling through the interface.

=item rewritten

A boolean that indicates whether a NAT function was performed on this packet. If B<rewritten> has a non-zero value, the B<src_ip>, B<dst_ip>, B<src_port> and B<dst_port> attributes contain the pre-NAT addresses and TCP/UDP ports. The post-NAT addresses and ports can be found in the encapsulated IP header.

=item naf

If B<rewritten> is non-zero, B<naf> indicates which Address Family the encapsulated IP header has been translated to.

=item pad

Padding data.

=item src_ip

The IP address where the packet originated. If B<rewritten> is non-zero, this attribute contains the original, pre-NAT IP address.

The format of the value of this attribute is dependent on the Address Family (B<af>) of the packet.

=item dst_ip

The IP address that the packet is addressed to. If B<rewritten> is non-zero, this attribute contains the original, pre-NAT IP address.

The format of the value of this attribute is dependent on the Address Family (B<af>) of the packet.

=item src_port

The source TCP/UDP port. If B<rewritten> is non-zero, this attribute contains the original, pre-NAT source port.

=item dst_port

The destination TCP/UDP port. If B<rewritten> is non-zero, this attribute contains the original, pre-NAT destination port.

=item data

The actual IPv4 or IPv6 packet that was logged by Packet Filter.

=back

=head2 Exports

=over

=item default

none

=item exportable

Data Link Type:

  DLT_PFLOG

Strip function:

  pflog_strip

=item tags

The following tags can be used to export certain items:

=over

=item C<:DLT>

DLT_PFLOG

=item C<:strip>

The function C<pflog_strip>

=item C<:ALL>

All the above exportable items

=back

=back

=head1 EXAMPLE

The following prints the action, direction, interface name, and
reason:

  #!/usr/bin/perl -w

  use strict;
  use Net::PcapUtils;
  use NetPacket::PFLog;

  sub process_pkt {
      my ($user, $hdr, $pkt) = @_;

      my $pfl_obj = NetPacket::PFLog->decode($pkt);
      print("$pfl_obj->{action} $pfl_obj->{dir} ");
      print("on $pfl_obj->{ifname} ($pfl_obj->{reason})\n");
  }

  Net::PcapUtils::loop(\&process_pkt, FILTER => 'ip or ip6');

=head1 TODO

Nothing at this time.

=head1 COPYRIGHT

Copyright (c) 2003-2014 Joel Knight <knight.joel@gmail.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

=head1 AUTHOR

Joel Knight E<lt>knight.joel@gmail.comE<gt>

http://www.packetmischief.ca/netpacket-perl-module-enhancements/

=cut

