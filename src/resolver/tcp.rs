use super::Resolver;
use LOGGER;

use slog::debug;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::prelude::*;
use tokio::timer::Timeout;
use trust_dns::client::{BasicClientHandle, ClientFuture};
use trust_dns::tcp::TcpClientStream;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::Query;
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::DnsRequestOptions;
use trust_dns_proto::xfer::DnsResponse;
use trust_dns_proto::xfer::{DnsMultiplexerSerialResponse, OneshotDnsResponseReceiver};

#[derive(Clone)]
pub struct SimpleTcpResolver {
    server_addr: SocketAddr,
    timeout: Duration,
}

impl Resolver for SimpleTcpResolver {
    type ResponseFuture = OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>;

    fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self {
        SimpleTcpResolver {
            server_addr,
            timeout,
        }
    }

    fn query(&mut self, query: Query) -> Self::ResponseFuture {
        let server_addr = self.server_addr;
        let (connect, handle) = TcpClientStream::new(server_addr);
        let connect = connect.map(move |stream| {
            debug!(LOGGER, "TCP connection to {} established.", server_addr);
            stream
        });
        let (bg, mut handle) =
            ClientFuture::with_timeout(Box::new(connect), handle, self.timeout, None);
        tokio::spawn(bg);
        let dns_options = DnsRequestOptions {
            expects_multiple_responses: false,
        };
        handle.lookup(query, dns_options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::thread;
    use tokio::runtime::Runtime;
    use trust_dns::rr::{Name, RecordType};

    #[test]
    fn sync_query() {
        let mut runtime = Runtime::new().expect("Unable to create a tokio runtime");
        let expected: IpAddr = [1, 1, 1, 1].into();
        let resolver: SimpleTcpResolver = runtime
            .block_on(future::lazy(|| {
                future::ok::<SimpleTcpResolver, ()>(SimpleTcpResolver::new(
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
            response
                .answers()
                .iter()
                .flat_map(|record| record.rdata().to_ip_addr())
                .any(|ip| ip == expected)
        );

        thread::sleep(Duration::from_secs(1));

        // Run a second time.
        // There once was a problem that the server would only respond to the first request.
        let mut resolver2 = resolver.clone();
        let response = runtime
            .block_on(future::lazy(move || {
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver2.query(query)
            })).expect("Unable to get response");
        assert!(
            response
                .answers()
                .iter()
                .flat_map(|record| record.rdata().to_ip_addr())
                .any(|ip| ip == expected)
        );
    }
}
