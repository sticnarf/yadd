use super::Resolver;
use LOGGER;

use slog::debug;
use std::net::SocketAddr;
use trust_dns::client::BasicClientHandle;
use trust_dns::client::ClientFuture;
use trust_dns::op::Query;
use trust_dns::udp::UdpClientStream;
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::dns_multiplexer::DnsMultiplexerSerialResponse;
use trust_dns_proto::xfer::dns_request::DnsRequestOptions;
use trust_dns_proto::xfer::OneshotDnsResponseReceiver;

#[derive(Clone)]
pub struct SimpleUdpResolver {
    handle: BasicClientHandle<DnsMultiplexerSerialResponse>,
}

impl Resolver<OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>> for SimpleUdpResolver {
    fn new(server_addr: SocketAddr) -> Self {
        let (stream, handle) = UdpClientStream::new(server_addr);
        let (bg, handle) = ClientFuture::new(stream, handle, None);
        debug!(LOGGER, "Initialized");
        tokio::spawn(bg);
        SimpleUdpResolver { handle }
    }

    fn query(&mut self, query: Query) -> OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse> {
        let dns_options = DnsRequestOptions {
            expects_multiple_responses: false,
        };
        self.handle.lookup(query, dns_options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    use tokio::prelude::*;
    use tokio::runtime::Runtime;
    use trust_dns::rr::{Name, RecordType};

    #[test]
    fn sync_query() {
        let mut runtime = Runtime::new().expect("Unable to create a tokio runtime");
        let expected: IpAddr = [1, 1, 1, 1].into();
        let resolver: SimpleUdpResolver = runtime
            .block_on(future::lazy(|| {
                future::ok::<SimpleUdpResolver, ()>(SimpleUdpResolver::new(
                    ([1, 1, 1, 1], 53).into(),
                ))
            })).unwrap();
        let mut resolver2 = resolver.clone();
        let response = runtime
            .block_on(future::lazy(move || {
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver2.query(query)
            })).expect("Unable to get response");
        assert!(
            response.answers()
                .iter()
                .flat_map(|record| record.rdata().to_ip_addr())
                .any(|ip| ip == expected);
        );

        // Run a second time
        let mut resolver2 = resolver.clone();
        let response = runtime
            .block_on(future::lazy(move || {
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver2.query(query)
            })).expect("Unable to get response");
        assert!(
            response.answers()
                .iter()
                .flat_map(|record| record.rdata().to_ip_addr())
                .any(|ip| ip == expected);
        );
    }
}
