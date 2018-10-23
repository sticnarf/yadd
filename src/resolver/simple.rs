use super::Resolver;

use std::net::SocketAddr;
use tokio::runtime::current_thread;
use trust_dns::client::ClientFuture;
use trust_dns::op::Query;
use trust_dns::udp::UdpClientStream;
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::dns_multiplexer::DnsMultiplexerSerialResponse;
use trust_dns_proto::xfer::dns_request::DnsRequestOptions;
use trust_dns_proto::xfer::OneshotDnsResponseReceiver;

#[derive(Clone)]
pub struct SimpleUdpResolver {
    server_addr: SocketAddr,
}

impl Resolver<OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>> for SimpleUdpResolver {
    fn new(server_addr: SocketAddr) -> Self {
        SimpleUdpResolver { server_addr }
    }

    fn query(&self, query: Query) -> OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse> {
        let (stream, handle) = UdpClientStream::new(self.server_addr);
        let (bg, mut handle) = ClientFuture::new(stream, handle, None);
        let dns_options = DnsRequestOptions {
            expects_multiple_responses: false,
        };
        current_thread::spawn(bg);
        handle.lookup(query, dns_options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    use tokio::prelude::*;
    use tokio::runtime::current_thread;
    use trust_dns::rr::{Name, RecordType};

    #[test]
    fn sync_query() {
        let mut runtime = current_thread::Runtime::new().expect("Unable to create tokio runtime");
        let expected: IpAddr = [1, 1, 1, 1].into();
        let response = runtime
            .block_on(future::lazy(|| {
                let resolver = SimpleUdpResolver::new(([1, 1, 1, 1], 53).into());
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver.query(query)
            })).expect("Unable to get response");
        assert!(
            response.answers()
                .iter()
                .flat_map(|record| record.rdata().to_ip_addr())
                .any(|ip| ip == expected);
        );

        // Run a second time
        let response = runtime
            .block_on(future::lazy(|| {
                let resolver = SimpleUdpResolver::new(([1, 1, 1, 1], 53).into());
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver.query(query)
            })).expect("Unable to get response");
        assert!(
            response.answers()
                .iter()
                .flat_map(|record| record.rdata().to_ip_addr())
                .any(|ip| ip == expected);
        );
    }
}
