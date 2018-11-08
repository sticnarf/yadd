use super::*;
use crate::STDERR;

use self::ConnectionState::*;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use lock_api::{RwLock, RwLockReadGuard};
use parking_lot::RawRwLock;
use slog::{debug, error, warn};
use std::marker::PhantomData;
use tokio::timer::Delay;
use trust_dns::client::ClientStreamHandle;
use trust_dns::client::{BasicClientHandle, ClientFuture};
use trust_dns::tcp::TcpClientStream;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::error::ProtoErrorKind;
use trust_dns_proto::op::Query;
use trust_dns_proto::tcp::TcpClientConnect;
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::DnsClientStream;
use trust_dns_proto::xfer::DnsResponse;
use trust_dns_proto::xfer::{DnsMultiplexerSerialResponse, OneshotDnsResponseReceiver};

pub trait TcpDnsStream: Sync + Send + 'static {
    type Connect: Future<Item = Self::Stream, Error = ProtoError> + Send;
    type Stream: DnsClientStream + Sync + Send + 'static;
    fn with_timeout(
        name_server: SocketAddr,
        timeout: Duration,
    ) -> (Self::Connect, Box<dyn ClientStreamHandle + 'static + Send>);
}

impl TcpDnsStream for TcpClientStream<tokio_tcp::TcpStream> {
    type Connect = TcpClientConnect;
    type Stream = TcpClientStream<tokio_tcp::TcpStream>;
    fn with_timeout(
        name_server: SocketAddr,
        timeout: Duration,
    ) -> (Self::Connect, Box<dyn ClientStreamHandle + 'static + Send>) {
        TcpClientStream::with_timeout(name_server, timeout)
    }
}

pub struct TcpResolver<S: TcpDnsStream> {
    server_addr: SocketAddr,
    timeout: Duration,
    state: Arc<RwLock<RawRwLock, ConnectionState>>,
    phantom: PhantomData<S>,
}

impl<S: TcpDnsStream> Clone for TcpResolver<S> {
    fn clone(&self) -> Self {
        TcpResolver {
            server_addr: self.server_addr,
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

impl<S: TcpDnsStream> TcpResolver<S> {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self::with_timeout(server_addr, Duration::from_secs(5))
    }

    pub fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self {
        TcpResolver {
            server_addr,
            timeout,
            state: Arc::new(RwLock::new(NotConnected)),
            phantom: PhantomData,
        }
    }

    fn connect(&self) {
        let mut state_ref = self.state.write();
        match &*state_ref {
            NotConnected => {
                let server_addr = self.server_addr;
                let (connect, handle) = S::with_timeout(server_addr, self.timeout / 2);
                let state = self.state.clone();
                let stream = connect.map(move |stream| {
                    debug!(STDERR, "TCP connection to {} established.", server_addr);
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
                let bg = bg.and_then(move |()| {
                    debug!(STDERR, "TCP connection to {} closed", server_addr);
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

impl<S: TcpDnsStream> Resolver for TcpResolver<S> {
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

pub type SimpleTcpResolver = TcpResolver<TcpClientStream<tokio_tcp::TcpStream>>;

pub struct TcpResponse<S: TcpDnsStream> {
    resolver: TcpResolver<S>,
    query: Query,
    deadline: Delay,
    resp_future: Option<OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>>,
}

impl<S: TcpDnsStream> Future for TcpResponse<S> {
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
                            "Lookup error occurrs when connection is not established. Reset connection."
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
    fn sync_query() {
        let mut runtime = Runtime::new().expect("Unable to create a tokio runtime");
        let expected: IpAddr = [1, 1, 1, 1].into();
        let resolver: SimpleTcpResolver = runtime
            .block_on(future::lazy(|| {
                future::ok::<SimpleTcpResolver, ()>(SimpleTcpResolver::new(
                    ([1, 1, 1, 1], 53).into(),
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
}
