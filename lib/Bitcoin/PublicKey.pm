package Bitcoin::PublicKey;

=head1 NAME

Bitcoin::PublicKey - Bitcoin public key.

=head1 SYNOPSIS

    use Bitcoin::PublicKey;
    my $pub = Bitcoin::PublicKey-new(

=head1 DESCRIPTION

=head2 new($n)

Constructor.  $n is a big integer which is an encoding of the
elliptic curve point associated with this key (FIXME: need to
give more detail on the encoding - it's basically what you
get when treating Crypt::EC::PointFp->encode()'s return value
as a big-endian integer.)

=head2 address

Returns a Bitcoin::Address object representing the address associated
with this public key.

=head2 keyhash

Returns the Bitcoin hash of this public key as a byte string.  It's
the ripemd160 of the sha256 of the key, as defined by the Bitcoin
protocol.

=cut

use bytes;
use feature 'say';
use strict;

use Bitcoin::Address;
use Bitcoin::Util qw(sha256 int2binstr);
use Class::InsideOut qw(id register private);
use Rhash;

private n => my %n;

sub new {
    my ($class, $n) = @_;
    my $self = register($class);
    my $id = id $self;
    
    $n{$id} = $n;

    return $self;
}

sub address {
    my ($self) = @_;
    my $id = id $self;
    return Bitcoin::Address->from_keyhash($self->keyhash);
}

sub keyhash {
    my ($self) = @_;
    my $id = id $self;
    my $keybinstr = int2binstr($n{$id});
    my $digest = pack('H*', Rhash::msg(Rhash::RIPEMD160, sha256($keybinstr)));
    return $digest;
}

1;
