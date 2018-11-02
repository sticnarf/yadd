use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::IpAddr;

#[derive(Debug)]
pub struct IpRange {
    v4: iprange::IpRange<Ipv4Net>,
    v6: iprange::IpRange<Ipv6Net>,
}

impl IpRange {
    pub fn new() -> Self {
        IpRange {
            v4: Default::default(),
            v6: Default::default(),
        }
    }

    pub fn add(&mut self, net: IpNet) {
        match net {
            IpNet::V4(net) => {
                self.v4.add(net);
            }
            IpNet::V6(net) => {
                self.v6.add(net);
            }
        }
    }

    pub fn simplify(&mut self) {
        self.v4.simplify();
        self.v6.simplify();
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(addr) => self.v4.contains(&addr),
            IpAddr::V6(addr) => self.v6.contains(&addr),
        }
    }
}

impl Default for IpRange {
    fn default() -> Self {
        Self::new()
    }
}
