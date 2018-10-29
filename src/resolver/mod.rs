use tokio::prelude::*;
use trust_dns::op::{DnsResponse, Query};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::DnsRequestOptions;

pub trait Resolver: Clone + Send + Sync {
    type ResponseFuture: Future<Item = DnsResponse, Error = ProtoError> + 'static + Send;
    fn query(&mut self, query: Query) -> Self::ResponseFuture;
}

const DNS_OPTIONS: DnsRequestOptions = DnsRequestOptions {
    expects_multiple_responses: false,
};

pub mod mix;
pub mod tcp;
pub mod udp;
