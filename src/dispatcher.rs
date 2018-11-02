use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crate::config::{Config, NetworkType, ResolverConfig, Rule};
use crate::ip::IpRange;
use crate::resolver::{Resolver, SimpleTcpResolver, SimpleUdpResolver};
use crate::{Transpose, STDERR, STDOUT};

use slog::{debug, error};
use tokio::prelude::*;
use trust_dns::serialize::binary::{BinDecoder, BinEncodable};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::header::Header;
use trust_dns_proto::op::header::MessageType;
use trust_dns_proto::rr::RrsetRecords;
use trust_dns_server::authority::{AuthLookup, LookupRecords, MessageResponseBuilder, Queries};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};

pub struct Dispatcher {
    resolvers: Arc<HashMap<String, Box<Resolver>>>,
    ranges: Arc<HashMap<String, IpRange>>,
    rules: Arc<Vec<Rule>>,
}

impl Dispatcher {
    pub fn new(config: Config) -> Self {
        let resolvers: HashMap<_, _> = config
            .resolvers
            .iter()
            .map(|(name, ResolverConfig { address, network })| {
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
}

impl RequestHandler for Dispatcher {
    fn handle_request<R: ResponseHandler + 'static>(
        &self,
        request: &Request<'_>,
        response_handle: R,
    ) -> io::Result<()> {
        debug!(STDERR, "Received request: {:?}", request.message);
        // let mut resolver = self.mixed.clone();
        // // We ignore all queries expect the first one.
        // // Although it is not standard conformant, it should just work in the real world.
        // let query = request
        //     .message
        //     .queries()
        //     .iter()
        //     .map(|q| q.original().clone())
        //     .next();
        // let query_bytes = query.clone().map(|q| q.to_bytes());

        // let result_future =
        //     future::lazy(move || query.map(move |q| resolver.query(q))).then(|res| match res {
        //         Ok(resp) => Ok(resp),
        //         Err(e) => {
        //             error!(STDERR, "Resolve error: {}", e);
        //             Ok(None)
        //         }
        //     });

        // // Build response header
        // let mut header = Header::new();
        // header.set_message_type(MessageType::Response);
        // header.set_id(request.message.id());

        // let send_future = result_future
        //     .and_then(move |resp| {
        //         // Copy the question section
        //         let query_bytes = Transpose::transpose(query_bytes)?;
        //         let queries = Transpose::transpose(query_bytes.as_ref().map(|bytes| {
        //             let mut decoder = BinDecoder::new(bytes);
        //             Queries::read(&mut decoder, 1)
        //         }))?;
        //         let mut builder = MessageResponseBuilder::new(queries.as_ref());
        //         if let Some(ref resp) = resp {
        //             let answers = resp.answers();
        //             builder.answers(AuthLookup::Records(LookupRecords::RecordsIter(
        //                 RrsetRecords::RecordsOnly(answers.iter()),
        //             )));
        //         }
        //         let message = builder.build(header);
        //         Ok(response_handle.send_response(message)?)
        //     })
        //     .map_err(|e: ProtoError| error!(STDERR, "{}", e));

        // tokio::spawn(send_future);
        Ok(())
    }
}
