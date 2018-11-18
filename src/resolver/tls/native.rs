use super::*;

use trust_dns_native_tls::TlsClientStream;
use trust_dns_native_tls::TlsClientStreamBuilder;

impl TcpDnsStreamBuilder for TlsDnsStreamBuilder {
    type Connect = Box<dyn Future<Item = TlsClientStream, Error = ProtoError> + Send>;
    type Stream = TlsClientStream;

    fn with_timeout(
        &self,
        timeout: Duration,
    ) -> (Self::Connect, Box<dyn ClientStreamHandle + 'static + Send>) {
        // TODO Timeout is ignored because TlsClientStreamBuilder does not support a timeout
        let (stream, handle) =
            TlsClientStreamBuilder::new().build(self.name_server, self.host.clone());
        (stream, Box::new(handle))
    }
}
