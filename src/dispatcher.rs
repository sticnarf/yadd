use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crate::config::{Config, NetworkType, Rule, RuleAction, UpstreamConfig};
use crate::ip::IpRange;
use crate::resolver::{Resolver, SimpleTcpResolver, SimpleUdpResolver};
use crate::{Transpose, STDERR};

use slog::{debug, error};
use tokio::prelude::*;
use trust_dns::op::{DnsResponse, Query};
use trust_dns::serialize::binary::{BinDecoder, BinEncodable};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::header::Header;
use trust_dns_proto::op::header::MessageType;
use trust_dns_proto::rr::record_data::RData;
use trust_dns_proto::rr::RrsetRecords;
use trust_dns_server::authority::{AuthLookup, LookupRecords, MessageResponseBuilder, Queries};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};

#[derive(Clone)]
pub struct Dispatcher {
    resolvers: Arc<HashMap<String, Box<Resolver>>>,
    ranges: Arc<HashMap<String, IpRange>>,
    rules: Arc<Vec<Rule>>,
}

impl Dispatcher {
    pub fn new(config: Config) -> Self {
        let resolvers: HashMap<_, _> = config
            .upstreams
            .iter()
            .map(|(name, UpstreamConfig { address, network })| {
                (
                    name.to_owned(),
                    match network {
                        NetworkType::Tcp => {
                            Box::new(SimpleTcpResolver::new(*address)) as Box<Resolver>
                        }
                        NetworkType::Udp => Box::new(SimpleUdpResolver::new(*address)),
                    },
                )
            })
            .collect();

        Dispatcher {
            resolvers: Arc::new(resolvers),
            ranges: config.ranges,
            rules: config.rules,
        }
    }

    fn check_response(&self, name: &str, resp: &DnsResponse) -> RuleAction {
        let answers = resp.answers();
        for rule in &*self.rules {
            if rule.upstreams.iter().any(|s| s == name) {
                let is_match = rule.ranges.iter().any(|range_pattern| {
                    let range_name = range_pattern.trim_start_matches('!');
                    let toggle = (range_pattern.len() - range_name.len()) % 2 == 1;
                    let range = self.ranges.get(range_name);
                    range
                        .map(|range| {
                            answers
                                .iter()
                                .filter_map(|rec| match rec.rdata() {
                                    RData::A(ip) => Some(range.contains((*ip).into())),
                                    RData::AAAA(ip) => Some(range.contains((*ip).into())),
                                    _ => None,
                                })
                                .next()
                                .unwrap_or(false)
                                ^ toggle
                        })
                        .unwrap_or(false)
                });
                if is_match {
                    return rule.action;
                }
            }
        }
        RuleAction::Accept
    }
}

impl Resolver for Dispatcher {
    fn query(
        &self,
        query: Query,
    ) -> Box<Future<Item = DnsResponse, Error = ProtoError> + 'static + Send> {
        let tasks: Vec<_> = self
            .resolvers
            .iter()
            .map(|(name, resolver)| {
                let name1 = name.to_owned();
                let name2 = name.to_owned();
                resolver
                    .query(query.clone())
                    .map(move |resp| (name1, resp))
                    .map_err(move |e| (name2, e))
            })
            .collect();

        fn process_all<A>(
            dispatcher: Dispatcher,
            tasks: future::SelectAll<A>,
        ) -> Box<Future<Item = DnsResponse, Error = ProtoError> + 'static + Send>
        where
            A: Future<Item = (String, DnsResponse), Error = (String, ProtoError)> + 'static + Send,
        {
            Box::new(tasks.then(|res| match res {
                Ok(((name, resp), _, remaining)) => match dispatcher.check_response(&name, &resp) {
                    RuleAction::Accept => {
                        // Ignore the remaining future
                        tokio::spawn(future::join_all(remaining).map(|_| ()).map_err(|_| ()));
                        debug!(STDERR, "Use result from {}", name);
                        Box::new(future::ok(resp))
                    }
                    RuleAction::Drop => process_all(dispatcher, future::select_all(remaining)),
                },
                Err(((name, e), _, remaining)) => {
                    error!(STDERR, "{}: {}", name, e);
                    if remaining.len() > 0 {
                        process_all(dispatcher, future::select_all(remaining))
                    } else {
                        Box::new(future::err(e))
                    }
                }
            }))
        }

        process_all(self.clone(), future::select_all(tasks))
    }
}

impl RequestHandler for Dispatcher {
    fn handle_request<R: ResponseHandler + 'static>(
        &self,
        request: &Request<'_>,
        response_handle: R,
    ) -> io::Result<()> {
        debug!(STDERR, "Received request: {:?}", request.message);

        // We ignore all queries expect the first one.
        // Although it is not standard conformant, it should just work in the real world.
        let query = request
            .message
            .queries()
            .iter()
            .map(|q| q.original().clone())
            .next();

        // Save raw query bytes. This will be copied to the question section of the response.
        let query_bytes = query.clone().map(|q| q.to_bytes());

        // Query for result
        let dispatcher = self.clone();
        let result_future =
            future::lazy(move || query.map(move |q| dispatcher.query(q))).then(|res| match res {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    error!(STDERR, "Resolve error: {}", e);
                    Ok(None)
                }
            });

        // Build response header
        let mut header = Header::new();
        header.set_message_type(MessageType::Response);
        header.set_id(request.message.id());

        let send_future = result_future
            .and_then(move |resp| {
                // Copy the question section
                let query_bytes = Transpose::transpose(query_bytes)?;
                let queries = Transpose::transpose(query_bytes.as_ref().map(|bytes| {
                    let mut decoder = BinDecoder::new(bytes);
                    Queries::read(&mut decoder, 1)
                }))?;
                let mut builder = MessageResponseBuilder::new(queries.as_ref());

                // Put answers into the response
                if let Some(ref resp) = resp {
                    let answers = resp.answers();
                    builder.answers(AuthLookup::Records(LookupRecords::RecordsIter(
                        RrsetRecords::RecordsOnly(answers.iter()),
                    )));
                }

                let message = builder.build(header);
                Ok(response_handle.send_response(message)?)
            })
            .map_err(|e: ProtoError| error!(STDERR, "{}", e));

        tokio::spawn(send_future);
        Ok(())
    }
}
