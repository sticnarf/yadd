use std::fmt::Display;
use std::fs::File;
use std::io::prelude::*;
use std::process::exit;

use crate::config::{Config, ConfigBuilder};
use crate::dispatcher::Dispatcher;

use clap::{App, Arg};
use failure::Error;
use lazy_static::lazy_static;
use slog::{crit, debug, info};
use slog::{o, Drain, Logger};
use tokio;
use tokio::net::udp::UdpSocket;
use tokio::prelude::*;

lazy_static! {
    static ref STDOUT: Logger = stdout_logger();
    static ref STDERR: Logger = stderr_logger();
}

fn main() {
    let conf = config().unwrap_or_log();
    debug!(STDERR, "{:?}", conf);

    let bind =
        UdpSocket::bind(&conf.bind).unwrap_or_log_with(format!("Unable to bind to {}", conf.bind));
    info!(STDOUT, "Listening on UDP: {}", conf.bind);
    // // trust_dns_server::logger::debug();

    let future = future::lazy(move || {
        let resolver = Dispatcher::new(conf);
        let server = trust_dns_server::ServerFuture::new(resolver);
        server.register_socket(bind);
        future::empty::<(), ()>()
    });

    tokio::run(future);
}

fn config() -> Result<Config, Error> {
    let matches = App::new("Yet Another DNS Dispatcher")
        .version("0.2.3")
        .author("Yilin Chen <sticnarf@gmail.com>")
        .arg(
            Arg::with_name("config")
                .long("config")
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

trait ShouldSuccess {
    type Item;

    fn unwrap_or_log(self) -> Self::Item;

    fn unwrap_or_log_with<D: Display>(self, description: D) -> Self::Item;
}

impl<T, F> ShouldSuccess for Result<T, F>
where
    F: Into<Error>,
{
    type Item = T;

    fn unwrap_or_log(self) -> T {
        self.unwrap_or_else(|e| {
            let e: Error = e.into();
            crit!(STDERR, "{}", e);
            debug!(STDERR, "{:?}", e.backtrace());
            exit(1);
        })
    }

    fn unwrap_or_log_with<D: Display>(self, description: D) -> T {
        self.unwrap_or_else(|e| {
            let e: Error = e.into();
            crit!(STDERR, "{}: {}", description, e);
            debug!(STDERR, "{:?}", e.backtrace());
            exit(1);
        })
    }
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
mod dispatcher;
mod ip;
mod resolver;
