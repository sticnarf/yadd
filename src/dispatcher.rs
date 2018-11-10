use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crate::config::Domains;
use crate::config::Upstream;
use crate::config::{Config, Rule, RuleAction};
use crate::ip::IpRange;
use crate::resolver::tcp::{
    SimpleTcpDnsStreamBuilder, SimpleTcpResolver, TlsDnsStreamBuilder, TlsResolver,
};
use crate::resolver::udp::SimpleUdpResolver;
use crate::resolver::Resolver;
use crate::{Transpose, STDERR};

use slog::{debug, error};
use tokio::prelude::*;
use trust_dns::op::{DnsResponse, Query};
use trust_dns::serialize::binary::{BinDecoder, BinEncodable};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::header::Header;
use trust_dns_proto::op::header::MessageType;
use trust_dns_proto::op::response_code::ResponseCode;
use trust_dns_proto::rr::record_data::RData;
use trust_dns_proto::rr::RrsetRecords;
use trust_dns_server::authority::{AuthLookup, LookupRecords, MessageResponseBuilder, Queries};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};

#[derive(Clone)]
pub struct Dispatcher {
    defaults: Arc<Vec<String>>,
    resolvers: Arc<HashMap<String, Arc<Resolver>>>,
    domains: Arc<HashMap<String, Domains>>,
    ranges: Arc<HashMap<String, IpRange>>,
    rules: Arc<Vec<Rule>>,
}

impl Dispatcher {
    pub fn new(config: Config) -> Self {
        let resolvers: HashMap<_, _> = config
            .upstreams
            .iter()
            .map(|(name, upstream)| {
                (
                    name.to_owned(),
                    match upstream {
                        Upstream::TcpUpstream { address } => Arc::new(SimpleTcpResolver::new(
                            SimpleTcpDnsStreamBuilder::new(*address),
                        ))
                            as Arc<Resolver>,
                        Upstream::UdpUpstream { address } => {
                            Arc::new(SimpleUdpResolver::new(*address))
                        }
                        Upstream::TlsUpstream { address, tls_host } => Arc::new(TlsResolver::new(
                            TlsDnsStreamBuilder::new(*address, tls_host.clone()),
                        )),
                    },
                )
            })
            .collect();

        Dispatcher {
            defaults: Arc::new(config.default_upstreams),
            resolvers: Arc::new(resolvers),
            domains: Arc::new(config.domains),
            ranges: Arc::new(config.ranges),
            rules: Arc::new(config.rules),
        }
    }

    fn check_response(&self, domain: &str, upstream_name: &str, resp: &DnsResponse) -> RuleAction {
        let answers = resp.answers();

        // Drop empty response
        if answers.is_empty() {
            return RuleAction::Drop;
        }

        let check_upstream = |rule: &Rule| {
            rule.upstreams
                .as_ref()
                .map(|u| u.iter().any(|s| s == upstream_name))
                .unwrap_or(true)
        };

        let check_ranges = |rule: &Rule| {
            rule.ranges
                .as_ref()
                .map(|r| {
                    r.iter().any(|range_pattern| {
                        // Process the leading `!`
                        let range_name = range_pattern.trim_start_matches('!');
                        let toggle = (range_pattern.len() - range_name.len()) % 2 == 1;

                        // See if the range contains the IP
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
                                    ^ toggle // toggle result according to the number of !
                            })
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(true) // No ranges field means matching all ranges
        };

        let check_domains = |rule: &Rule| {
            rule.domains
                .as_ref()
                .map(|d| {
                    d.iter().any(|domains_pattern| {
                        // Process the leading `!`
                        let domains_tag = domains_pattern.trim_start_matches('!');
                        let toggle = (domains_pattern.len() - domains_pattern.len()) % 2 == 1;

                        let domains = self.domains.get(domains_tag);
                        domains
                            .map(|domains| domains.regex_set.is_match(domain) ^ toggle)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(true) // No domains field means matching all domains
        };

        self.rules
            .iter()
            .find(|rule| check_upstream(rule) && check_ranges(rule) && check_domains(rule))
            .map(|rule| rule.action)
            .unwrap_or(RuleAction::Accept)
    }

    fn dispatch(&self, query: &Query) -> Vec<(&str, Arc<Resolver>)> {
        let name = query.name().to_ascii();
        // Find domains section which has an upstream field and matches the name
        let result = self
            .domains
            .iter()
            .filter(|(_, domains)| domains.upstreams.is_some())
            .find(|(_, domains)| domains.regex_set.is_match(&name));
        if let Some((tag, domains)) = result {
            debug!(STDERR, "Query {} matches {}", name, tag);
            domains
                .upstreams
                .as_ref()
                .unwrap()
                .iter()
                .filter_map(|u| self.resolvers.get(u).map(|v| (u.as_str(), v.clone())))
                .collect()
        } else {
            debug!(
                STDERR,
                "No domain specific setting matches for {}. Use defaults.", name
            );
            // If no domains section matches, use defaults
            self.defaults
                .iter()
                .filter_map(|u| self.resolvers.get(u).map(|v| (u.as_str(), v.clone())))
                .collect()
        }
    }
}

impl Resolver for Dispatcher {
    fn query(
        &self,
        query: Query,
    ) -> Box<Future<Item = DnsResponse, Error = ProtoError> + 'static + Send> {
        let resolvers = self.dispatch(&query);
        let tasks: Vec<_> = resolvers
            .into_iter()
            .map(|(name, resolver)| {
                let domain = query.name().to_ascii();
                let name1 = name.to_owned();
                let name2 = name.to_owned();
                resolver
                    .query(query.clone())
                    .map(move |resp| (domain, name1, resp))
                    .map_err(move |e| (name2, e))
            })
            .collect();

        fn process_all<A>(
            dispatcher: Dispatcher,
            tasks: future::SelectAll<A>,
        ) -> Box<Future<Item = DnsResponse, Error = ProtoError> + 'static + Send>
        where
            A: Future<Item = (String, String, DnsResponse), Error = (String, ProtoError)>
                + 'static
                + Send,
        {
            Box::new(tasks.then(|res| match res {
                Ok(((domain, name, resp), _, remaining)) => {
                    match dispatcher.check_response(&domain, &name, &resp) {
                        RuleAction::Accept => {
                            // Ignore the remaining future
                            tokio::spawn(future::join_all(remaining).map(|_| ()).map_err(|_| ()));
                            debug!(STDERR, "Use result from {}", name);
                            Box::new(future::ok(resp))
                        }
                        RuleAction::Drop => process_all(dispatcher, future::select_all(remaining)),
                    }
                }
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
        let id = request.message.id();
        let op_code = request.message.op_code();
        let mut header = Header::new();
        header.set_message_type(MessageType::Response);
        header.set_id(id);

        let send_future = result_future
            .and_then(move |resp| {
                // Copy the question section
                let query_bytes = Transpose::transpose(query_bytes)?;
                let queries = Transpose::transpose(query_bytes.as_ref().map(|bytes| {
                    let mut decoder = BinDecoder::new(bytes);
                    Queries::read(&mut decoder, 1)
                }))?;
                let mut builder = MessageResponseBuilder::new(queries.as_ref());

                let message = if let Some(ref resp) = resp {
                    // Put answers into the response
                    let answers = resp.answers();
                    builder.answers(AuthLookup::Records(LookupRecords::RecordsIter(
                        RrsetRecords::RecordsOnly(answers.iter()),
                    )));
                    builder.build(header)
                } else {
                    // No answer available (Usually due to bad network condition)
                    builder.error_msg(id, op_code, ResponseCode::ServFail)
                };

                Ok(response_handle.send_response(message)?)
            })
            .map_err(|e: ProtoError| error!(STDERR, "{}", e));

        tokio::spawn(send_future);
        Ok(())
    }
}
