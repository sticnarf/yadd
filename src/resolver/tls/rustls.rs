use super::*;

use lazy_static::lazy_static;
use rustls::ClientConfig;
use trust_dns_rustls::TlsClientStream;
use trust_dns_rustls::TlsClientStreamBuilder;

lazy_static! {
    static ref RUSTLS_CONFIG: ClientConfig = {
        let mut config = rustls::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config
    };
}

impl TcpDnsStreamBuilder for TlsDnsStreamBuilder {
    type Connect = Box<dyn Future<Item = TlsClientStream, Error = ProtoError> + Send>;
    type Stream = TlsClientStream;

    fn with_timeout(
        &self,
        timeout: Duration,
    ) -> (Self::Connect, Box<dyn ClientStreamHandle + 'static + Send>) {
        // TODO: Timeout is ignored because TlsClientStreamBuilder does not support a timeout
        // TODO: Avoid cloning: https://github.com/bluejekyll/trust-dns/issues/618
        let (stream, handle) = TlsClientStreamBuilder::with_client_config(RUSTLS_CONFIG.clone())
            .build(self.name_server, self.host.clone());
        (stream, Box::new(handle))
    }
}
