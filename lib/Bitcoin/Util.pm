package Bitcoin::Util;

# These utility functions are private to this distribution, so we
# don't document them with POD, so as not to give the impression that
# they're public interfaces.  Interfaces are described as code comments
# instead.

use base 'Exporter';
use bignum;
use bytes;
use feature 'say';
use strict;

use Data::Dumper;
use File::Slurp qw(read_file);
use IO::Pipe;
use Rhash;

our @EXPORT_OK = qw(add_2sha256chk rm_2sha256chk sha256
    int2binstr binstr2int base58  base58_decode validate_2sha256chk);

# Add the Bitcoin-style 32 bit checksum based on the first 4 bytes of a
# double sha256 of the input data, given as a byte string, and return
# the result.
sub add_2sha256chk {
    my ($binstr) = @_;

    return $binstr . substr(sha256(sha256($binstr)), 0, 4);
}

# Inverse of add_2sha256chk.  Raises exception if the checksum is wrong.
sub rm_2sha256chk {
    my ($binstr) = @_;

    my $checksum = substr(sha256(sha256(substr($binstr, 0, -4))), 0, 4);
    if ($checksum eq substr($binstr, -4)) {
	return substr($binstr, 0, -4);
    }
    # FIXME: Think about what type we want the exception to be (interface)
    else {
	say "checksum: $checksum, substr binstr: " . substr($binstr,-4);
	die "invalid checksum\n";
    }
}


# This is just here to work around the return value length bug in 
# Digest::SHA256.  Returns the sha256 of the input byte string, as
# a byte string.  We should probably look at RHash as we may then
# be able to use a module directly instead of wrapping it in our own
# utility function like this.
sub sha256 {
    my ($binstr) = @_;
    return pack('H*', Rhash::msg(Rhash::SHA256, $binstr));
}

# Returns a byte string representing the big integer given as input.
# The output byte string can be thought of as a base 256 big endian large
# integer.
sub int2binstr {
    my ($int) = @_;
    my $str = "";
    while ($int > 0) {
	$str = chr($int % 256) . $str;
	$int >>= 8;
    }
    return $str;
}

# Inverse of int2binstr
sub binstr2int {
    my ($binstr) = @_;

    my $n = 0;
    my $i = 0;
    
    while (length($binstr)) {
        my $char = substr($binstr, length($binstr) - 1, 1, "");
        $n = $n + Math::BigInt->new(ord($char)) * Math::BigInt->new(256) ** $i;
        $i++;
    }
    return $n;
}


# takes a binary string, returns the base58 encoding, Bitcoin style
sub base58 {
    my ($binstr) = @_;

    my $p_encoded_b58 = IO::Pipe->new;
    if (fork) {
	$p_encoded_b58->reader;
	my $encoded_b58 = <$p_encoded_b58>;
	chomp $encoded_b58;
	wait;
	return $encoded_b58;
    }
    else {
	my $p_raw = IO::Pipe->new;
	if (fork) {
	    close STDOUT;
	    $p_raw->writer;
	    print $p_raw $binstr;
	    close $p_raw;
	    wait;
	    exit ($? >> 8);
	}
	else {
	    $p_raw->reader;
	    $p_encoded_b58->writer;
	    open(STDIN, "<&" . fileno($p_raw)) or die;
	    open(STDOUT, ">&" . fileno($p_encoded_b58)) or die;
	    exec("b58") or die "b58: $!\n";
	}
	die;
    }
    die;
}

# Inverse of base58.
sub base58_decode {
    my ($b58str) = @_;

    my $p_decoded_b58 = IO::Pipe->new;
    if (fork) {
	$p_decoded_b58->reader;
	my $decoded_b58 = read_file($p_decoded_b58);
	wait;
	if ($?) {
	    warn "b58-dec exited: " . ($?>>8) . "\n";
	    exit($?>>8);
	}
	return $decoded_b58;
    }
    else {
	my $p_b58 = IO::Pipe->new;
	if (fork) {
	    close STDOUT;
	    $p_b58->writer;
	    print $p_b58 $b58str;
	    close $p_b58;
	    wait;
	    exit ($? >> 8);
	}
	else {
	    $p_b58->reader;
	    $p_decoded_b58->writer;
	    open(STDIN, "<&" . fileno($p_b58)) or die;
	    open(STDOUT, ">&" . fileno($p_decoded_b58)) or die;
	    exec("b58-dec") or die "b58-dec: $!\n";
	}
	die;
    }
    die;

}

1;
