use std::net::SocketAddr;
use std::time::Duration;
use tokio::prelude::*;
use trust_dns::op::{DnsResponse, Query};
use trust_dns_proto::error::ProtoError;

pub trait Resolver<ResponseFuture>: Clone + Send + Sync
where
    ResponseFuture: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send,
{
    fn new(server_addr: SocketAddr) -> Self {
        Self::with_timeout(server_addr, Duration::from_secs(2))
    }

    fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self;

    fn query(&mut self, query: Query) -> ResponseFuture;
}

pub mod simple;
