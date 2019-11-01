use Modern::Perl;
use MTProto;
use Telegram::Help::GetConfig;
use Telegram::InvokeWithLayer;
use Telegram::InitConnection;

use IO::Socket::Socks;

use AnyEvent;
use AnyEvent::Handle;

use Data::Dumper;

my @bootstrap = qw( 149.154.175.50 149.154.167.51 149.154.175.100 149.154.167.91 149.154.171.5 );

my ($app_id, $api_hash, $proxy_addr, $proxy_port) = @ARGV;

die "api_hash required" unless defined $api_hash;

my $cv = AE::cv;
my $getconfig = Telegram::Help::GetConfig->new;
$getconfig = Telegram::InitConnection->new(
        api_id => $app_id,
        device_model => 'IBM PC/AT',
        system_version => 'DOS 6.22',
        app_version => '0.4.18',
        system_lang_code => 'en',
        lang_pack => '',
        lang_code => 'en',
        query => $getconfig
);
$getconfig = Telegram::InvokeWithLayer->new( layer => 91, query => $getconfig );

for my $dc (@bootstrap) {
    my $sock = IO::Socket::Socks->new(
        ProxyAddr => $proxy_addr,
        ProxyPort => $proxy_port,
        ConnectAddr => $dc,
        ConnectPort => 443
    ) or die "proxy error";

    my $mt = MTProto->new( socket => AnyEvent::Handle->new( fh => $sock ) );
    $mt->invoke( [ $getconfig ] );
    $mt->reg_cb( message => sub {
            my ($mtobj, $m) = @_;
            $m = $m->{object};
            if ($m->isa('MTProto::RpcResult')) {
                $cv->send if $m->{result}->isa('MTProto::RpcError');
                
                if ($m->{result}->isa('Telegram::Config')) {
                    for (@{$m->{result}{dc_options}}) {
                        say "$_->{id} : $_->{ip_address}:$_->{port}", 
                            unpack( "H*", $_->{secret} // ''), 
                            (defined $_->{static}) ? ' static' : '' ;
                    }
                }
                undef $mt;
                $cv->send;
            }
        } 
    );
    $mt->start_session;
    last;
}

$cv->recv;

