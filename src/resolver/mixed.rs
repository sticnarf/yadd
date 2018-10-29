use super::*;
use crate::LOGGER;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use failure::Error;
use ipnet::Ipv4Net;
use iprange::{IpNet, IpRange};
use slog::debug;
use tokio::prelude::*;
use trust_dns::rr::RData;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::xfer::DnsResponse;

#[derive(Clone)]
pub struct MixedResolver<C, A>
where
    C: Resolver,
    A: Resolver,
{
    china: C,
    abroad: A,
    china_ip: Arc<IpRange<Ipv4Net>>,
}

impl<C, A> MixedResolver<C, A>
where
    C: Resolver,
    A: Resolver,
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

    pub fn new<P: AsRef<Path>>(china: C, abroad: A, china_ip_path: P) -> Result<Self, Error> {
        Ok(MixedResolver {
            china,
            abroad,
            china_ip: Arc::new(Self::parse_chnroutes(china_ip_path)?),
        })
    }
}

enum ResultSource {
    China,
    Abroad,
}

fn is_china_response(resp: &DnsResponse, china_ip: Arc<IpRange<Ipv4Net>>) -> bool {
    let answers = resp.answers();
    answers
        .iter()
        .filter_map(|rec| match rec.rdata() {
            RData::A(ip) => Some(china_ip.contains(ip)),
            _ => None,
        })
        .next()
        .unwrap_or(false)
}

impl<C, F> Resolver for MixedResolver<C, F>
where
    C: Resolver,
    F: Resolver,
{
    type ResponseFuture = Box<dyn Future<Item = DnsResponse, Error = ProtoError> + 'static + Send>;

    fn query(&mut self, query: Query) -> Self::ResponseFuture {
        let china_ip = self.china_ip.clone();
        let china_resolve = self.china.clone().query(query.clone()).and_then(|resp| {
            if is_china_response(&resp, china_ip) {
                Ok((resp, ResultSource::China))
            } else {
                Err("Invalid response from china".into())
            }
        });
        let abroad_resolve = self
            .abroad
            .clone()
            .query(query)
            .map(|resp| (resp, ResultSource::Abroad));

        let resolve_future = china_resolve.select(abroad_resolve).then(|res| match res {
            Ok(((china_resp, ResultSource::China), abroad_future)) => {
                debug!(LOGGER, "Got china IP from server in china. Use it");
                // Ignore abroad future
                let _ = tokio::spawn(abroad_future.map(|_| ()).map_err(|_| ()));
                Box::new(future::ok(china_resp))
                    as Box<Future<Item = DnsResponse, Error = ProtoError> + Send>
            }
            Ok(((abroad_resp, ResultSource::Abroad), china_future)) => {
                debug!(LOGGER, "IP from abroad got first.");
                Box::new(china_future.then(|res| match res {
                    Ok((china_resp, ResultSource::China)) => {
                        debug!(LOGGER, "Got china IP from server in china. Use it");
                        Ok(china_resp)
                    }
                    Ok((_, ResultSource::Abroad)) => unreachable!(),
                    Err(_) => {
                        debug!(
                            LOGGER,
                            "Resolving from china server failed. Use ip from abroad"
                        );
                        Ok(abroad_resp)
                    }
                }))
            }
            Err((e, other_future)) => {
                debug!(LOGGER, "First query failed: {}", e);
                Box::new(other_future.map(|(resp, source)| {
                    match source {
                        ResultSource::China => debug!(LOGGER, "Use ip from china"),
                        ResultSource::Abroad => debug!(LOGGER, "Use ip from abroad"),
                    }
                    resp
                }))
            }
        });
        Box::new(resolve_future)
    }
}
