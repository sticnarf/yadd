use super::*;
use crate::LOGGER;

use self::ConnectionState::*;
use lock_api::{RwLock, RwLockReadGuard};
use parking_lot::RawRwLock;
use slog::{debug, error, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::timer::Delay;
use trust_dns::client::{BasicClientHandle, ClientFuture};
use trust_dns::tcp::TcpClientStream;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::error::ProtoErrorKind;
use trust_dns_proto::op::Query;
use trust_dns_proto::xfer::dns_handle::DnsHandle;
use trust_dns_proto::xfer::DnsResponse;
use trust_dns_proto::xfer::{DnsMultiplexerSerialResponse, OneshotDnsResponseReceiver};

#[derive(Clone)]
pub struct SimpleTcpResolver {
    server_addr: SocketAddr,
    timeout: Duration,
    state: Arc<RwLock<RawRwLock, ConnectionState>>,
}

pub enum ConnectionState {
    NotConnected,
    Connecting(BasicClientHandle<DnsMultiplexerSerialResponse>),
    Connected(BasicClientHandle<DnsMultiplexerSerialResponse>),
}

impl SimpleTcpResolver {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self::with_timeout(server_addr, Duration::from_secs(2))
    }

    pub fn with_timeout(server_addr: SocketAddr, timeout: Duration) -> Self {
        SimpleTcpResolver {
            server_addr,
            timeout,
            state: Arc::new(RwLock::new(NotConnected)),
        }
    }

    fn connect(&self) {
        let mut state_ref = self.state.write();
        match &*state_ref {
            NotConnected => {
                let server_addr = self.server_addr;
                let (connect, handle) = TcpClientStream::new(server_addr);
                let state = self.state.clone();
                let stream = connect.map(move |stream| {
                    debug!(LOGGER, "TCP connection to {} established.", server_addr);
                    let mut state = state.write();
                    match &mut *state {
                        Connecting(handle) => {
                            *state = Connected(handle.clone());
                        }
                        _ => {
                            warn!(
                                LOGGER,
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
                    debug!(LOGGER, "TCP connection to {} closed", server_addr);
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

impl Resolver for SimpleTcpResolver {
    type ResponseFuture = TcpResponse;

    fn query(&mut self, query: Query) -> Self::ResponseFuture {
        TcpResponse {
            resolver: self.clone(),
            query,
            deadline: Delay::new(Instant::now() + self.timeout),
            resp_future: None,
        }
    }
}

pub struct TcpResponse {
    resolver: SimpleTcpResolver,
    query: Query,
    deadline: Delay,
    resp_future: Option<OneshotDnsResponseReceiver<DnsMultiplexerSerialResponse>>,
}

impl Future for TcpResponse {
    type Item = DnsResponse;
    type Error = ProtoError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.deadline.poll() {
            Ok(Async::Ready(_)) => return Err(ProtoErrorKind::Timeout.into()),
            Err(e) => return Err(e.into()),
            _ => {}
        }

        match self
            .resp_future
            .as_mut()
            .map(|resp_future| resp_future.poll())
        {
            Some(Ok(Async::Ready(resp))) => {
                debug!(LOGGER, "TcpResponse ready.");
                Ok(Async::Ready(resp))
            }
            Some(Ok(Async::NotReady)) => {
                debug!(LOGGER, "TcpResponse still not ready.");
                Ok(Async::NotReady)
            }
            Some(Err(e)) => {
                let state = self.resolver.state.read();
                match &*state {
                    Connecting(_) => {
                        drop(state);
                        debug!(
                            LOGGER,
                            "Lookup error occurrs when connection is not established. Reset connection."
                        );
                        self.resp_future = None;
                        *self.resolver.state.write() = NotConnected;
                        Ok(Async::NotReady)
                    }
                    _ => {
                        error!(LOGGER, "Lookup error: {}. Will retry.", e);
                        self.resp_future = None;
                        Ok(Async::NotReady)
                    }
                }
            }
            None => {
                let mut state = self.resolver.state.read();
                match &*state {
                    NotConnected => {
                        debug!(LOGGER, "Not connected. Try to connect.");
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
                                warn!(LOGGER, "Immediately ready. Really?");
                                Ok(Async::Ready(resp))
                            }
                            Ok(Async::NotReady) => {
                                debug!(LOGGER, "Not ready. Save it.");
                                self.resp_future = Some(resp_future);
                                Ok(Async::NotReady)
                            }
                            Err(e) => {
                                error!(LOGGER, "Immediate lookup error: {}", e);
                                Err(e)
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
        let mut resolver2 = resolver.clone();
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
        let mut resolver2 = resolver.clone();
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
