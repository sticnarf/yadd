use super::*;
use crate::LOGGER;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

use failure::Error;
use ipnet::Ipv4Net;
use iprange::{IpNet, IpRange};
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
    china_ip: IpRange<Ipv4Net>,
}

impl<C, F> MixedResolver<C, F>
where
    C: Resolver,
    F: Resolver,
{
    fn parse_chnroutes<P, N>(path: P) -> Result<IpRange<N>, Error>
    where
        P: AsRef<Path>,
        N: IpNet + FromStr,
    {
        let f = File::open(path)?;
        let reader = BufReader::new(f);
        Ok(reader
            .lines()
            .flat_map(|l| l)
            .filter(|line| !line.starts_with("#"))
            .flat_map(|l| l.parse::<N>())
            .collect())
    }

    pub fn new<P: AsRef<Path>>(china: C, foreign: F, china_ip_path: P) -> Result<Self, Error> {
        Ok(MixedResolver {
            china,
            foreign,
            china_ip: Self::parse_chnroutes(china_ip_path)?,
        })
    }
}

impl<C, F> Resolver for MixedResolver<C, F>
where
    C: Resolver,
    F: Resolver,
{
    type ResponseFuture = Box<dyn Future<Item = DnsResponse, Error = ProtoError> + 'static + Send>;

    fn query(&mut self, _query: Query) -> Self::ResponseFuture {
        unimplemented!()
    }
}
