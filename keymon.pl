use Modern::Perl;
use IO::Socket;
use Digest::SHA qw(sha1 sha256);
use Time::HiRes qw/time/;

# XXX
use IO::Socket::Socks;
use Crypt::CTR;
use Crypt::OpenSSL::AES;
use Crypt::OpenSSL::Random;

## Usage: 
## perl keymon.pl mtproxy_addr mtproxy_port socks_addr socks_port
##

my %keys = (
    14101943622620965665 => 'Original 2014',
    847625836280919973 => '2017-1',
    1562291298945373506 => '2017-2',
    12587166101702965583 => '2017-3',
    6491968696586960280 => '2017-4',
);

my @servers = qw(
149.154.175.54
149.154.167.51
149.154.175.100
149.154.167.91
91.108.56.180
);
my ($mtproxy_host, $mtproxy_port, $secret, $socks_host, $socks_port) = @ARGV;

sub pack_req_pq
{
    #my $hash = 0x60469778;
    my $hash = 0xbe7e8ef1;
    my @nonce;

    local $_;

    push @nonce, int(rand(256)) for 1..16;

    return pack("L<C16", $hash, @nonce);
}

sub unpack_res_pq
{
    my $data = shift;
    my @fp;
    
    local $_;

    my $tag = unpack("L<", substr($data, 0, 4));
    die "Bad server response: $tag" unless $tag == 0x05162463;

    #say unpack "H*", $data;

    # skip tag, nonce and server nonce
    $data = substr($data, 36);
    
    # pq is bytes, a little more complex
    my ($len, $str) = unpack "C a3", substr($data, 0, 4);
    if ($len == 254) {
        $len = unpack("L<", $str."\0");
        $len += 7;
        $len &= ~3;
    }
    else {
        $len += 4;
        $len &= ~3;
    }
    #say "pq len is $len";
    #skip pq and vector tag
    $data = substr($data, $len+4);
    
    # vector size
    my $count = unpack("L<", substr($data, 0, 4));
    say "$count fingerprints";
    $data = substr($data, 4);

    while ($count--) {
        push @fp, unpack("Q<", substr($data, 0, 8));
        $data = substr($data, 8);
    }
    return @fp;
}

sub msgid
{
    my $time = time;
    my $hi = int( $time );
    my $lo = int ( ( $time - $hi ) * 2**32 );
    return unpack( "Q<", pack( "(LL)<", $lo, $hi ) );
}

sub mtproto_send
{
    my ($sock, $data, $first) = @_;

    my $datalen = length($data);
    my $pkglen = $datalen + 20;

    $sock->send(pack("L", 0xeeeeeeee)) if $first;
    $sock->send(pack("(LQQL)<", $pkglen, 0, msgid(), $datalen) . $data);
}

sub mtproto_recv
{
    my $sock = shift;
    my ($len, $data);

    $sock->recv($len, 4);
    $len = unpack "L<", $len;
    say "recvd $len";
    die "mtproto error" if $len < 16;
    $sock->recv($data, $len);
    $len = unpack("L<", substr($data, 16, 4));
    return substr($data, 20, $len);
}

sub mtproxy_init
{
    my ($secret, $padded, $dc) = @_;

    my $initpak = Crypt::OpenSSL::Random::random_pseudo_bytes(64);
    my $rev = reverse $initpak;
    
    my $enc_k = substr($initpak, 8, 32);
    my $enc_iv = substr($initpak, 40, 16);
    my $dec_k = substr($rev, 8, 32);
    my $dec_iv = substr($rev, 40, 16);
    
    $enc_k = sha256($enc_k . $secret);
    $dec_k = sha256($dec_k . $secret);

    my $enc = Crypt::CTR->new(
        -key => $enc_k,
        -iv => $enc_iv,
        -cipher => 'Crypt::OpenSSL::AES'
    );
    my $dec = Crypt::CTR->new(
        -key => $dec_k,
        -iv => $dec_iv,
        -cipher => 'Crypt::OpenSSL::AES'
    );

    $initpak = substr($initpak, 0, 56) . ($padded ? "\xdd\xdd\xdd\xdd" : "\xef\xef\xef\xef") . pack("s<", $dc ) . "\0\0";
    my $encpak = $enc->encrypt($initpak);
    $initpak = substr($initpak, 0, 56) . substr($encpak, 56, 8);

    return ($initpak, $enc, $dec);
}

sub mtproxy_send
{
    my ($sock, $data, $padded, $enc) = @_;

    my $pkg;
    if ($padded) {
        my $pad = Crypt::OpenSSL::Random::random_pseudo_bytes(int(rand(16)));
        my $len = length($data);
        my $pkglen = $len + 20 + length($pad);
        $pkg = pack("(LQQL)<", $pkglen, 0, msgid(), $len) . $data . $pad;
    }
    else {
        my $len = length($data);
        my $pkglen = int($len + 20 + 3 / 4);
        my $padlen = -length($data) % 4;
        my $lenpak;
        if ($pkglen >= 0x7f) {
            $lenpak = "\x7f" . substr(pack("L<", $pkglen), 0, 3);
        }
        else {
            $lenpak = pack("C", $pkglen);
        }
        $pkg = $lenpak . pack("(QQL)<", 0, msgid(), $len) . $data . "\0" x $padlen;
    }
    say "sending encrypted ". length($pkg) ." bytes";
    $sock->send($enc->encrypt($pkg));
}

sub mtproxy_recv
{
    my ($sock, $padded, $dec) = @_;
    my ($len, $data);

    if ($padded) {
        $sock->recv($len, 4);
        $len = $dec->decrypt($len);
        $len = unpack("L<", $len);
    }
    else {
        $sock->recv($len, 1);
        $len = $dec->decrypt($len);
        $len = unpack("C", $len);
        if ( $len == 0x7f ) {
            $sock->recv($len, 3);
            $len = $dec->decrypt($len);
            $len = unpack("L<", $len . "\0");
        }
    }
    $sock->recv($data, $len);
    $data = $dec->decrypt($data);
    $len = unpack("L<", substr($data, 16, 4));
    say "recvd and decrypted $len bytes";
    return substr($data, 20, $len);
}

say "Direct";
for my $dc (@servers) {
    my $sock = IO::Socket::Socks->new(
        ProxyAddr => $socks_host,
        ProxyPort => $socks_port,
        ConnectAddr => $dc,
        ConnectPort => 443
    ) or die "proxy error";

    say "connected to $dc";
    mtproto_send($sock, pack_req_pq(), 1);
    say "req_pq sent";
    my @fp = unpack_res_pq(mtproto_recv($sock));
    $sock->close;

    for (@fp) {
        say $_, " - ", $keys{$_} // '!unknown!';
    }
}

say "Proxy";
my $padded = 0;
if ($secret =~ /^dd/) {
    $padded = 1;
    $secret = substr($secret, 2);
}

$secret = pack("H*", $secret);

for my $dc (1..5) {
    my $sock = IO::Socket::INET->new(
        PeerAddr => $mtproxy_host,
        PeerPort => $mtproxy_port
    ) or die "connect error";

    say "connected to $mtproxy_host";
    say "sending to dc#$dc";
    my ($init, $enc, $dec) = mtproxy_init($secret, $padded, $dc);
    $sock->send($init);
    mtproxy_send($sock, pack_req_pq(), $padded, $enc);
    my $ans = mtproxy_recv($sock, $padded, $dec);
    my @fp = unpack_res_pq($ans);
    $sock->close;
    for (@fp) {
        say $_, " - ", $keys{$_} // '!unknown!';
    }
}

