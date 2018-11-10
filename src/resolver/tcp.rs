use super::*;
use self::ConnectionState::*;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::STDERR;

use lock_api::{RwLock, RwLockReadGuard};
use parking_lot::RawRwLock;
use slog::{debug, error, warn};
use std::fmt::Debug;
use std::marker::PhantomData;
use tokio::timer::Delay;
use trust_dns::client::ClientStreamHandle;
use trust_dns::client::{BasicClientHandle, ClientFuture};
use trust_dns::tcp::TcpClientStream;
use trust_dns_native_tls::TlsClientStream;
use trust_dns_native_tls::TlsClientStreamBuilder;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::error::ProtoErrorKind;
use trust_dns_proto::op::Query;
use trust_dns_proto::tcp::TcpClientConnect;
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::DnsClientStream;
use trust_dns_proto::xfer::DnsResponse;
use trust_dns_proto::xfer::{DnsMultiplexerSerialResponse, OneshotDnsResponseReceiver};

pub trait TcpDnsStreamBuilder: Clone + Debug + Sync + Send + 'static {
    type Connect: Future<Item = Self::Stream, Error = ProtoError> + Send;
    type Stream: DnsClientStream + Sync + Send + 'static;
    fn with_timeout(
        &self,
        timeout: Duration,
    ) -> (Self::Connect, Box<dyn ClientStreamHandle + 'static + Send>);
}

#[derive(Clone, Debug)]
pub struct SimpleTcpDnsStreamBuilder {
    name_server: SocketAddr,
}

impl SimpleTcpDnsStreamBuilder {
    pub fn new(name_server: SocketAddr) -> Self {
        SimpleTcpDnsStreamBuilder { name_server }
    }
}

impl TcpDnsStreamBuilder for SimpleTcpDnsStreamBuilder {
    type Connect = TcpClientConnect;
    type Stream = TcpClientStream<tokio_tcp::TcpStream>;
    fn with_timeout(
        &self,
        timeout: Duration,
    ) -> (Self::Connect, Box<dyn ClientStreamHandle + 'static + Send>) {
        TcpClientStream::with_timeout(self.name_server, timeout)
    }
}

#[derive(Clone, Debug)]
pub struct TlsDnsStreamBuilder {
    name_server: SocketAddr,
    host: String,
}

impl TlsDnsStreamBuilder {
    pub fn new(name_server: SocketAddr, host: String) -> Self {
        TlsDnsStreamBuilder { name_server, host }
    }
}

impl TcpDnsStreamBuilder for TlsDnsStreamBuilder {
    type Connect = Box<dyn Future<Item = TlsClientStream, Error = ProtoError> + Send>;
    type Stream = TlsClientStream;

    fn with_timeout(
        &self,
        timeout: Duration,
    ) -> (Self::Connect, Box<dyn ClientStreamHandle + 'static + Send>) {
        // TODO Timeout is ignored because TlsClientStreamBuilder does not support a timeout
        let (stream, handle) =
            TlsClientStreamBuilder::new().build(self.name_server, self.host.clone());
        (stream, Box::new(handle))
    }
}

pub struct TcpResolver<B: TcpDnsStreamBuilder> {
    builder: B,
    timeout: Duration,
    state: Arc<RwLock<RawRwLock, ConnectionState>>,
    phantom: PhantomData<B>,
}

impl<B: TcpDnsStreamBuilder + Clone> Clone for TcpResolver<B> {
    fn clone(&self) -> Self {
        TcpResolver {
            builder: self.builder.clone(),
            timeout: self.timeout,
            state: self.state.clone(),
            phantom: PhantomData,
        }
    }
}

pub enum ConnectionState {
    NotConnected,
    Connecting(BasicClientHandle<DnsMultiplexerSerialResponse>),
    Connected(BasicClientHandle<DnsMultiplexerSerialResponse>),
}

impl<B: TcpDnsStreamBuilder> TcpResolver<B> {
    pub fn new(builder: B) -> Self {
        Self::with_timeout(builder, Duration::from_secs(5))
    }

    pub fn with_timeout(builder: B, timeout: Duration) -> Self {
        TcpResolver {
            builder,
            timeout,
            state: Arc::new(RwLock::new(NotConnected)),
            phantom: PhantomData,
        }
    }

    fn connect(&self) {
        let mut state_ref = self.state.write();
        match &*state_ref {
            NotConnected => {
                let builder = self.builder.clone();
                let (connect, handle) = builder.with_timeout(self.timeout / 2);
                let state = self.state.clone();
                let stream = connect.map(move |stream| {
                    debug!(STDERR, "TCP connection to {:?} established.", builder);
                    let mut state = state.write();
                    match &mut *state {
                        Connecting(handle) => {
                            *state = Connected(handle.clone());
                        }
                        _ => {
                            warn!(
                                STDERR,
                                "Weird ConnectionState! Change it back to NotConnected"
                            );
                            *state = NotConnected;
                        }
                    }
                    stream
                });

                let (bg, handle) =
                    ClientFuture::with_timeout(Box::new(stream), handle, self.timeout, None);
                *state_ref = Connecting(handle);

                let state = self.state.clone();
                let builder = self.builder.clone();
                let bg = bg.and_then(move |()| {
                    debug!(STDERR, "TCP connection to {:?} closed", builder);
                    *state.write() = NotConnected;
                    future::empty()
                });

                tokio::spawn(bg);
            }
            _ => {}
        }
        task::current().notify()
    }
}

impl<B: TcpDnsStreamBuilder> Resolver for TcpResolver<B> {
    fn query(
        &self,
        query: Query,
    ) -> Box<Future<Item = DnsResponse, Error = ProtoError> + 'static + Send> {
        let resolver: Self = self.clone();
        Box::new(TcpResponse {
            resolver,
            query,
            deadline: Delay::new(Instant::now() + self.timeout),
            resp_future: None,
        })
    }
}

pub type SimpleTcpResolver = TcpResolver<SimpleTcpDnsStreamBuilder>;

pub type TlsResolver = TcpResolver<TlsDnsStreamBuilder>;

pub struct TcpResponse<B: TcpDnsStreamBuilder> {
    resolver: TcpResolver<B>,
    query: Query,
    deadline: Delay,
    resp_future: Option<OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>>,
}

impl<B: TcpDnsStreamBuilder> Future for TcpResponse<B> {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.deadline.poll() {
            Ok(Async::Ready(_)) => {
                // put unfinished task to background
                if let Some(resp_future) = self.resp_future.take() {
                    let _ = tokio::spawn(resp_future.map(|_| ()).map_err(|_| ()));
                }
                // Timeout indicates a connection is actually closed.
                // (maybe no, but anyway we don't care)
                let state = self.resolver.state.read();
                if let Connected(_) = &*state {
                    drop(state);
                    *self.resolver.state.write() = NotConnected;
                }
                return Err(ProtoErrorKind::Timeout.into());
            }
            Err(e) => return Err(e.into()),
            _ => {}
        }

        match self
            .resp_future
            .as_mut()
            .map(|resp_future| resp_future.poll())
        {
            Some(Ok(Async::Ready(resp))) => {
                debug!(STDERR, "TcpResponse ready.");
                Ok(Async::Ready(resp))
            }
            Some(Ok(Async::NotReady)) => {
                debug!(STDERR, "TcpResponse still not ready.");
                Ok(Async::NotReady)
            }
            Some(Err(e)) => {
                let state = self.resolver.state.read();
                match &*state {
                    Connecting(_) => {
                        drop(state);
                        debug!(
                                STDERR,
                                "Lookup error occurrs when connection is not established. Reset connection. {}", e
                            );
                        self.resp_future = None;
                        *self.resolver.state.write() = NotConnected;
                        task::current().notify();
                        Ok(Async::NotReady)
                    }
                    _ => {
                        error!(STDERR, "Lookup error: {}. Will retry.", e);
                        self.resp_future = None;
                        task::current().notify();
                        Ok(Async::NotReady)
                    }
                }
            }
            None => {
                let mut state = self.resolver.state.read();
                match &*state {
                    NotConnected => {
                        debug!(STDERR, "Not connected. Try to connect.");
                        RwLockReadGuard::unlocked(&mut state, || {
                            self.resolver.connect();
                        });
                        Ok(Async::NotReady)
                    }
                    Connecting(handle) | Connected(handle) => {
                        let mut resp_future =
                            handle.clone().lookup(self.query.clone(), DNS_OPTIONS);
                        match resp_future.poll() {
                            Ok(Async::Ready(resp)) => {
                                warn!(STDERR, "Immediately ready. Really?");
                                Ok(Async::Ready(resp))
                            }
                            Ok(Async::NotReady) => {
                                debug!(STDERR, "Not ready. Save it.");
                                self.resp_future = Some(resp_future);
                                Ok(Async::NotReady)
                            }
                            Err(e) => {
                                drop(state);
                                use failure::Fail;
                                error!(
                                    STDERR,
                                    "Reset connection due to immediate lookup error: {:?}",
                                    e.backtrace()
                                );
                                self.resp_future = None;
                                *self.resolver.state.write() = NotConnected;
                                task::current().notify();
                                Ok(Async::NotReady)
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::thread;
    use tokio::runtime::Runtime;
    use trust_dns::rr::{Name, RecordType};

    #[test]
    fn query_sync_simple_tcp() {
        let mut runtime = Runtime::new().expect("Unable to create a tokio runtime");
        let expected: IpAddr = [1, 1, 1, 1].into();
        let resolver: SimpleTcpResolver = runtime
            .block_on(future::lazy(|| {
                future::ok::<SimpleTcpResolver, ()>(SimpleTcpResolver::new(
                    SimpleTcpDnsStreamBuilder::new(([1, 1, 1, 1], 53).into()),
                ))
            }))
            .unwrap();
        let resolver2 = resolver.clone();
        let response = runtime
            .block_on(future::lazy(move || {
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver2.query(query)
            }))
            .expect("Unable to get response");
        assert!(response
            .answers()
            .iter()
            .flat_map(|record| record.rdata().to_ip_addr())
            .any(|ip| ip == expected));

        thread::sleep(Duration::from_secs(1));

        // Run a second time.
        // There once was a problem that the server would only respond to the first request.
        let resolver2 = resolver.clone();
        let response = runtime
            .block_on(future::lazy(move || {
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver2.query(query)
            }))
            .expect("Unable to get response");
        assert!(response
            .answers()
            .iter()
            .flat_map(|record| record.rdata().to_ip_addr())
            .any(|ip| ip == expected));
    }

    #[test]
    fn query_sync_tls() {
        let mut runtime = Runtime::new().expect("Unable to create a tokio runtime");
        let expected: IpAddr = [1, 1, 1, 1].into();
        let resolver: TlsResolver = runtime
            .block_on(future::lazy(|| {
                future::ok::<TlsResolver, ()>(TlsResolver::new(TlsDnsStreamBuilder::new(
                    ([1, 1, 1, 1], 853).into(),
                    "cloudflare-dns.com".to_string(),
                )))
            }))
            .unwrap();
        let resolver2 = resolver.clone();
        let response = runtime
            .block_on(future::lazy(move || {
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver2.query(query)
            }))
            .expect("Unable to get response");
        assert!(response
            .answers()
            .iter()
            .flat_map(|record| record.rdata().to_ip_addr())
            .any(|ip| ip == expected));

        thread::sleep(Duration::from_secs(1));

        // Run a second time.
        // There once was a problem that the server would only respond to the first request.
        let resolver2 = resolver.clone();
        let response = runtime
            .block_on(future::lazy(move || {
                let query =
                    Query::query(Name::from_str("one.one.one.one.").unwrap(), RecordType::A);
                resolver2.query(query)
            }))
            .expect("Unable to get response");
        assert!(response
            .answers()
            .iter()
            .flat_map(|record| record.rdata().to_ip_addr())
            .any(|ip| ip == expected));
    }
}
