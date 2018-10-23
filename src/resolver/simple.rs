use super::Resolver;

use std::net::SocketAddr;
use trust_dns::client::{BasicClientHandle, ClientFuture, ClientStreamHandle};
use trust_dns::op::Query;
use trust_dns::rr::dnssec::Signer;
use trust_dns::rr::{Name, RecordType};
use trust_dns::udp::UdpClientStream;
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::dns_multiplexer::{
    DnsMultiplexer, DnsMultiplexerConnect, DnsMultiplexerSerialResponse,
};
use trust_dns_proto::xfer::dns_request::DnsRequestOptions;
use trust_dns_proto::xfer::OneshotDnsResponseReceiver;

#[derive(Clone)]
struct SimpleUdpResolver {
    handle: BasicClientHandle<DnsMultiplexerSerialResponse>,
}

impl
    Resolver<
        DnsMultiplexerConnect<UdpClientStream, Signer>,
        DnsMultiplexer<UdpClientStream, Signer, Box<ClientStreamHandle>>,
        DnsMultiplexerSerialResponse,
        OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>,
    > for SimpleUdpResolver
{
    fn new(
        addr: SocketAddr,
    ) -> (
        ClientFuture<
            DnsMultiplexerConnect<UdpClientStream, Signer>,
            DnsMultiplexer<UdpClientStream, Signer, Box<ClientStreamHandle>>,
            DnsMultiplexerSerialResponse,
        >,
        Self,
    ) {
        let (stream, handle) = UdpClientStream::new(addr);
        let (bg, handle) = ClientFuture::new(stream, handle, None);
        (bg, SimpleUdpResolver { handle })
    }

    fn query(
        &mut self,
        name: Name,
        query_type: RecordType,
    ) -> OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse> {
        let query = Query::query(name, query_type);
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
    use tokio::runtime::Runtime;
    use trust_dns::rr::{Name, RecordType};

    #[test]
    fn sync_query() {
        let mut runtime = Runtime::new().unwrap();
        let (bg, mut client) = SimpleUdpResolver::new(([1, 1, 1, 1], 53).into());
        runtime.spawn(bg);
        let query = client.query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
        let response = runtime.block_on(query).unwrap();
        let answers = response.answers();
        let expected: IpAddr = [1, 1, 1, 1].into();
        assert!(
            answers
                .iter()
                .flat_map(|record| record.rdata().to_ip_addr())
                .any(|ip| ip == expected)
        )
    }
}
