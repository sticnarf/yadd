extern crate tokio;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate trust_dns_server;

use resolver::simple::SimpleUdpResolver;
use resolver::Resolver;
use std::io;
use tokio::net::udp::UdpSocket;
use tokio::prelude::*;
use tokio::runtime::current_thread;
use trust_dns_proto::op::header::Header;
use trust_dns_proto::rr::RrsetRecords;
use trust_dns_server::authority::{AuthLookup, LookupRecords, MessageResponseBuilder};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};

struct ChinaDnsHandler {
    simple: SimpleUdpResolver,
}

impl ChinaDnsHandler {
    fn new() -> Self {
        let resolver = SimpleUdpResolver::new(([1, 1, 1, 1], 53).into());
        ChinaDnsHandler { simple: resolver }
    }
}

impl RequestHandler for ChinaDnsHandler {
    fn handle_request<'q, 'a, R: ResponseHandler + 'static>(
        &'a self,
        request: &'q Request,
        response_handle: R,
    ) -> io::Result<()> {
        let id = request.message.id();
        let resolver = self.simple.clone();
        let queries: Vec<_> = request
            .message
            .queries()
            .iter()
            .map(|query| (query.original().clone(), resolver.clone()))
            .collect();
        let results_future = future::join_all(
            queries
                .into_iter()
                .map(|(query, resolver)| resolver.query(query)),
        ).map_err(|e| {
            eprintln!("Resolve error: {:?}", e);
            e.into()
        });
        let send_future = results_future
            .and_then(move |responses| {
                let mut builder = MessageResponseBuilder::new(None);
                for mut resp in &responses {
                    let answers = resp.answers();
                    builder.answers(AuthLookup::Records(LookupRecords::RecordsIter(
                        RrsetRecords::RecordsOnly(answers.iter()),
                    )));
                }
                let mut header = Header::new();
                header.set_id(id);
                let message = builder.build(header);
                response_handle.send_response(message)
            }).map_err(|e| {
                eprintln!("Send error: {:?}", e);
            });
        current_thread::spawn(send_future);
        Ok(())
    }
}

fn main() {
    let mut runtime = current_thread::Runtime::new().expect("Unable to create tokio runtime");
    let udp =
        UdpSocket::bind(&([127, 0, 0, 1], 5353).into()).expect("Unable to bind 127.0.0.1:5353");
    let future = future::lazy(|| {
        let server = trust_dns_server::ServerFuture::new(ChinaDnsHandler::new());
        server.register_socket(udp);
        future::empty()
    });
    runtime.spawn(future);
    if let Err(e) = runtime.run() {
        eprintln!("{:?}", e);
    }
}

mod resolver;
