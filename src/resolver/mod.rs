use tokio::prelude::*;
use trust_dns::op::{DnsResponse, Query};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::DnsRequestOptions;

pub trait Resolver: Send + Sync {
    fn query(
        &self,
        query: Query,
    ) -> Box<Future<Item = DnsResponse, Error = ProtoError> + 'static + Send>;
}

const DNS_OPTIONS: DnsRequestOptions = DnsRequestOptions {
    expects_multiple_responses: false,
};

pub mod tcp;
pub mod udp;
