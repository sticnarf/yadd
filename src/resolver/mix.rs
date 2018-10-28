use super::*;
use LOGGER;

use tokio::prelude::*;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::DnsResponse;

#[derive(Clone)]
pub struct MixedResolver<C, F>
where
    C: Resolver,
    F: Resolver,
{
    china: C,
    foreign: F,
}

impl<C, F> MixedResolver<C, F>
where
    C: Resolver,
    F: Resolver,
{
    pub fn new(china: C, foreign: F) -> Self {
        MixedResolver { china, foreign }
    }
}

impl<C, F> Resolver for MixedResolver<C, F>
where
    C: Resolver,
    F: Resolver,
{
    type ResponseFuture = Box<Future<Item = DnsResponse, Error = ProtoError> + 'static + Send>;

    fn query(&mut self, query: Query) -> Self::ResponseFuture {
        unimplemented!()
    }
}
