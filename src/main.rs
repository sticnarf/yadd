use std::fmt::Display;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::path::Path;
use std::process::exit;

use crate::config::{Config, ConfigBuilder};
use crate::resolver::mixed::MixedResolver;
use crate::resolver::tcp::SimpleTcpResolver;
use crate::resolver::udp::SimpleUdpResolver;
use crate::resolver::Resolver;

use clap::{App, Arg};
use failure::{Error, Fail};
use lazy_static::lazy_static;
use slog::{crit, debug, error, info};
use slog::{o, Drain, Logger};
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
    static ref STDOUT: Logger = stdout_logger();
    static ref STDERR: Logger = stderr_logger();
}

struct ChinaDnsHandler<C, F>
where
    C: Resolver,
    F: Resolver,
{
    mixed: MixedResolver<C, F>,
}

impl<C, F> ChinaDnsHandler<C, F>
where
    C: Resolver,
    F: Resolver,
{
    fn new<P: AsRef<Path>>(
        china_resolver: C,
        foreign_resolver: F,
        chnroutes_path: P,
    ) -> ChinaDnsHandler<C, F> {
        let mixed = MixedResolver::new(china_resolver, foreign_resolver, chnroutes_path).unwrap();
        ChinaDnsHandler { mixed }
    }
}

impl<C, A> RequestHandler for ChinaDnsHandler<C, A>
where
    C: Resolver + 'static,
    A: Resolver + 'static,
{
    fn handle_request<R: ResponseHandler + 'static>(
        &self,
        request: &Request<'_>,
        response_handle: R,
    ) -> io::Result<()> {
        debug!(STDERR, "Received request: {:?}", request.message);
        let mut resolver = self.mixed.clone();
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

trait ShouldSuccess {
    type Item;

    fn unwrap_or_log(self) -> Self::Item;

    fn unwrap_or_log_with<D: Display>(self, description: D) -> Self::Item;
}

impl<T> ShouldSuccess for Result<T, Error> {
    type Item = T;

    fn unwrap_or_log(self) -> T {
        self.unwrap_or_else(|e| {
            crit!(STDERR, "{}", e);
            debug!(STDERR, "{:?}", e.backtrace());
            exit(1);
        })
    }

    fn unwrap_or_log_with<D: Display>(self, description: D) -> T {
        self.unwrap_or_else(|e| {
            crit!(STDERR, "{}: {}", description, e);
            debug!(STDERR, "{:?}", e.backtrace());
            exit(1);
        })
    }
}

fn main() {
    let conf = config().unwrap_or_log();
    println!("{:?}", conf);
    // let bind = UdpSocket::bind(&conf.bind_addr)
    //     .unwrap_or_log_with(format!("Unable to bind {}", conf.bind_addr));
    // info!(STDOUT, "Listening on UDP: {}", conf.bind_addr);
    // // trust_dns_server::logger::debug();

    // let future = future::lazy(move || {
    //     let china_resolver = SimpleUdpResolver::new(conf.china_dns_addr);
    //     let foreign_resolver = SimpleUdpResolver::new(conf.foreign_dns_addr);
    //     let resolver = ChinaDnsHandler::new(china_resolver, foreign_resolver, &conf.chnroutes_path);
    //     let server = trust_dns_server::ServerFuture::new(resolver);
    //     server.register_socket(bind);
    //     future::empty()
    // });

    // tokio::run(future);
}

fn config() -> Result<Config, Error> {
    let matches = App::new("Yet Another DNS Dispatcher")
        .version("0.2.0-dev")
        .author("Yilin Chen <sticnarf@gmail.com>")
        .arg(
            Arg::with_name("config")
                .long("conf")
                .short("c")
                .takes_value(true)
                .required(true)
                .value_name("CONFIG_FILE")
                .default_value("config.toml")
                .help("Specify the config file"),
        )
        .get_matches();
    let config_path = matches
        .value_of("config")
        .expect("CONFIG_FILE argument not found");
    let mut file = File::open(config_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let builder: ConfigBuilder = toml::from_str(&content)?;
    builder.build()
}

fn stdout_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    Logger::root(drain, o!())
}

fn stderr_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build();
    let drain = std::sync::Mutex::new(drain).fuse();

    Logger::root(drain, o!())
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

mod config;
mod ip;
mod resolver;
