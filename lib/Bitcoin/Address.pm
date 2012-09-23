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
use Digest::SHA256;
use IO::Pipe;

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

    my $sha256er = Digest::SHA256::new(256);
    my $first_sha256 = $sha256er->hash($keyhash{$id});
    $first_sha256 = Bitcoin::Util::sha256($keyhash{$id});

    open(my $hash_fh, ">", "/tmp/hash");
    print $hash_fh $keyhash{$id};
    if (length($first_sha256) > 32) {
        warn "working round Digest::SHA256 bug\n";
        substr($first_sha256, 32, length($first_sha256) - 32, "");
    }

    my $checksum = $sha256er->hash($first_sha256);
    $checksum = Bitcoin::Util::sha256(Bitcoin::Util::sha256($keyhash{$id}));

    if (length($checksum) > 32) {
        warn "working round Digest::SHA256 bug\n";
        substr($checksum, 32, length($checksum) - 32, "");
    }

    my $rawaddr = $keyhash{$id} . substr($checksum, 0, 4);

    $rawaddr = add_2sha256chk($keyhash{$id});
    return base58($rawaddr);
}

1;
