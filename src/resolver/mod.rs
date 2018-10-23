use std::net::SocketAddr;
use tokio::prelude::*;
use trust_dns::client::ClientFuture;
use trust_dns::op::DnsResponse;
use trust_dns::rr::{Name, RecordType};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::DnsRequestSender;

trait Resolver<SenderFuture, Sender, Response, ResponseFuture>: Clone + Send + Sync
where
    SenderFuture: Future<Item = Sender, Error = ProtoError> + 'static + Send,
    Sender: DnsRequestSender<DnsResponseFuture = Response> + 'static,
    Response: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
    ResponseFuture: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    fn new(addr: SocketAddr) -> (ClientFuture<SenderFuture, Sender, Response>, Self);

    fn query(&mut self, name: Name, query_type: RecordType) -> ResponseFuture;
}

mod simple;
