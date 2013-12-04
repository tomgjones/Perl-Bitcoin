package Bitcoin::Address;

=head1 NAME

Bitcoin::Address - a Bitcoin Address.

=head1 SYNOPSIS

=head1 DESCRIPTION

A Bitcoin::Address represents a Bitcoin address, and it stringifies
to the Base 58 address string as commonly used in Bitcoin client
software.

=head2 from_keyhash($keyhash_without_version)

Constructor.  $keyhash_without_version is the hash of the key as a
byte string, without the network version byte included.  Currently, only
main net addresses are supported.

=cut

use bytes;
use feature 'say';
use overload '""' => 'to_string';
use strict;

use Bitcoin::Util qw(base58 add_2sha256chk);
use Class::InsideOut qw(id register private);
use IO::Pipe;
use Rhash;

private addr => my %addr;
private keyhash => my %keyhash;
private keyhashbytes => my %keyhashbytes;
private netversion => my %netversion;

sub from_keyhash {
    my ($class, $keyhash_without_version) = @_;
    my $self = register $class;
    my $id = id $self;

    $netversion{$id} = 0x00; # Main net
    defined($keyhash_without_version) or die;

    $keyhash{$id} = chr($netversion{$id}) . $keyhash_without_version;
    $keyhashbytes{$id} = [split("", $keyhash{$id})];
    return $self;
}

sub to_string {
    my ($self) = @_;
    my $id = id $self;

    return base58(add_2sha256chk($keyhash{$id}));
}

1;
