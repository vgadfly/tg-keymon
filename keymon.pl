use Modern::Perl;
use IO::Socket;
use Digest::SHA qw(sha1 sha256);
use Time::HiRes qw/time/;

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

my @servers = qw( 149.154.175.50 149.154.167.51 149.154.175.100 149.154.167.91 149.154.171.5 );

my ($mtproxy_host, $mtproxy_port, $socks_host, $socks_port) = @ARGV;

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

use IO::Socket::Socks;

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
