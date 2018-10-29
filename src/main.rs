#![feature(nll)]

use crate::resolver::tcp::SimpleTcpResolver;
use crate::resolver::udp::SimpleUdpResolver;
use crate::resolver::Resolver;

use std::io;

use lazy_static::lazy_static;
use slog::Logger;
use slog::{debug, error, info};
use tokio;
use tokio::net::udp::UdpSocket;
use tokio::prelude::*;
use trust_dns::serialize::binary::{BinDecoder, BinEncodable};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::header::Header;
use trust_dns_proto::op::header::MessageType;
use trust_dns_proto::rr::RrsetRecords;
use trust_dns_server;
use trust_dns_server::authority::{AuthLookup, LookupRecords, MessageResponseBuilder, Queries};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};

lazy_static! {
    static ref LOGGER: Logger = init_logger();
}

struct ChinaDnsHandler {
    udp: SimpleUdpResolver,
    tcp: SimpleTcpResolver,
}

impl ChinaDnsHandler {
    fn new() -> Self {
        let udp = SimpleUdpResolver::new(([223, 5, 5, 5], 53).into());
        let tcp = SimpleTcpResolver::new(([1, 1, 1, 1], 53).into());
        ChinaDnsHandler { udp, tcp }
    }
}

impl RequestHandler for ChinaDnsHandler {
    fn handle_request<R: ResponseHandler + 'static>(
        &self,
        request: &Request<'_>,
        response_handle: R,
    ) -> io::Result<()> {
        debug!(LOGGER, "Received request: {:?}", request.message);
        let mut resolver = self.tcp.clone();
        // We ignore all queries expect the first one.
        // Although it is not standard conformant, it should just work in the real world.
        let query = request
            .message
            .queries()
            .iter()
            .map(|q| q.original().clone())
            .next();
        let query_bytes = query.clone().map(|q| q.to_bytes());

        let result_future =
            future::lazy(move || query.map(move |q| resolver.query(q))).then(|res| match res {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    error!(LOGGER, "Resolve error: {}", e);
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
                if let Some(ref resp) = resp {
                    let answers = resp.answers();
                    builder.answers(AuthLookup::Records(LookupRecords::RecordsIter(
                        RrsetRecords::RecordsOnly(answers.iter()),
                    )));
                }
                let message = builder.build(header);
                Ok(response_handle.send_response(message)?)
            })
            .map_err(|e: ProtoError| error!(LOGGER, "{}", e));

        tokio::spawn(send_future);
        Ok(())
    }
}

fn main() {
    let udp =
        UdpSocket::bind(&([127, 0, 0, 1], 5353).into()).expect("Unable to bind 127.0.0.1:5353");
    info!(LOGGER, "Listening UDP: 127.0.0.1:5353");
    //    trust_dns_server::logger::debug();

    let future = future::lazy(move || {
        let server = trust_dns_server::ServerFuture::new(ChinaDnsHandler::new());
        server.register_socket(udp);
        future::empty()
    });

    tokio::run(future);
}

fn init_logger() -> Logger {
    use sloggers::terminal::*;
    use sloggers::types::*;
    use sloggers::Build;
    TerminalLoggerBuilder::new()
        .level(Severity::Debug)
        .build()
        .expect("Unable to create logger")
}

// Wait for #47338 to be stable
trait Transpose {
    type Output;
    fn transpose(self) -> Self::Output;
}

impl<T, E> Transpose for Option<Result<T, E>> {
    type Output = Result<Option<T>, E>;

    fn transpose(self) -> Self::Output {
        match self {
            Some(Ok(x)) => Ok(Some(x)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }
}

mod resolver;
