package Bitcoin::Key;

=head1 NAME

Bitcoin::Key - Bitcoin private key.

=head1 SYNOPSIS

    use Bitcoin::Key;
    my $key = Bitcoin::Key->new;   # Random
    say $key->wif;

    use bignum;
    my $key2 = Bitcoin::Key->new(
        value => 0x83fe950f8abecbd6e938172563290baec27f093625f61eabc874923651990926
    );

=head1 DESCRIPTION

A Bitcoin::Key represents a private key in Bitcoin.  It stringifies
to its representation in Wallet Import Format, which is a Base 58 
string format for the private key commonly used in Bitcoin software.

=head2 new(), new(value => $n), new(wif => $str)

Constructor.  If a big integer $n is given with name "value", it 
is used as the value of 
the 256 bit private key.  If wif is given, this should be a string
in the wallet import / export format.  If neither of these is given, 
a random private key is
generated.

=head2 wif

Returns the private key in Wallet Import Format.

=head2 as_binstr

Returns the private key as a big-endian byte string (so in base 256).

=head2 public_key

Returns a Bitcoin::PublicKey, which represents the public key associated
with this private key.

=head2 address

Returns the address of this keypair as a Base 58 string.

=head2 

=head2 

=cut

use bignum;
use bytes;
use feature 'say';
use overload '""' => 'to_string';
use strict;

use Bitcoin::PublicKey;
use Bitcoin::Util qw(add_2sha256chk int2binstr binstr2int base58 base58_decode rm_2sha256chk);
use Class::InsideOut qw(id private readonly register);
use Crypt::Random::Source qw(get_strong);
use Crypt::EC::CurveFp;
use Params::Validate qw(validate SCALAR);
use Readonly;

Readonly my $MIN => 0x1;
# NOTE: http://bitcoin.stackexchange.com/questions/3609/can-an-sha256-hash-be-used-as-an-ecdsa-private-key
# has a different value for this.  Need to check.
Readonly my $MAX 
    => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBAAEDCE6_AF48A03B_BFD25E8C_D0364141;

my %EC_PARAMS = (
    p => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a => 0,
    b => 7,
    n => 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
);

my $curve = Crypt::EC::CurveFp->new(@EC_PARAMS{qw(p a b)});

$EC_PARAMS{G} = $curve->decode_point_hex("04"
    . "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    . "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

# Private key as a bignum integer.
readonly key => my %key;

sub new {
    my $class = shift;
    my @init_args = @_;
    my %init_args = @_;

    my $self = register($class);
    my $id = id $self;
    no bignum;
    validate(@init_args, {key => 0, wif => 0});
    use bignum;

    if (exists($init_args{key})) {
	if ($init_args{key} > $MAX) {
	    die "key value too large\n";
	}
	if ($init_args{key} < $MIN) {
	    die "key value too small\n";
	}
warn "key: " . $init_args{key};
        $key{$id} = delete $init_args{key};
    }
    elsif (exists($init_args{wif})) {
        my $wif = delete $init_args{wif};

	my $binstr = rm_2sha256chk(base58_decode($wif));
	if (substr($binstr, 0, 1, "") ne chr(0x80)) {
            die "not 0x80 at start of address string\n";
	}
	$key{$id} = binstr2int($binstr);
    }
    # FIXME: put this after checking for invalid params, so that we don't
    # delay on reading /dev/random if there's no point.
    else {
        $key{$id} = binstr2int(get_strong(32));
    }
    if (keys %init_args) {
        die "only one of key or wif may be given to Bitcoin::Key->new: "
            . join(" ", keys %init_args) . "\n";
    }
    $self->chk_range;
    return $self;
}

# Private.
sub chk_range {
    my ($self) = @_;
    my $id = id $self;

    if ($key{$id} > $MAX or $key{$id} < $MIN) {
        die "$key{$id} not in range; aborting\n";
    }
}

# Returns a string.
sub address {
    my ($self) = @_;
    my $id = id $self;

    return $self->public_key->address;
}

sub public_key {
    my ($self) = @_;
    my $id = id $self;

    my $pubkey_point = $EC_PARAMS{G}->multiply($key{$id});

    return Bitcoin::PublicKey->new(
        binstr2int(
            join("", map { chr($_) } 
                     $EC_PARAMS{G}->multiply($key{$id})->encode(0)
            )
        )
    );
}

sub wif {
    my ($self) = @_;

    return base58(add_2sha256chk(chr(0x80) . $self->as_binstr));
}

# "Compressed" - copied from bitaddress JS, not sure where this is
# specified though.
sub wif_comp {
    my ($self) = @_;

    return base58(add_2sha256chk(chr(0x80) . $self->as_binstr . chr(0x01)));
}

sub as_binstr {
    my ($self) = @_;

    return int2binstr($self->key);
}

sub to_string {
    my ($self) = @_;
    return $self->wif;
}


1;
