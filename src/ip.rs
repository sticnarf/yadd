use ipnet::{Ipv4Net, Ipv6Net};

#[derive(Debug)]
pub struct IpRange {
    v4: iprange::IpRange<Ipv4Net>,
    v6: iprange::IpRange<Ipv6Net>,
}

impl IpRange {
    fn new() -> Self {
        IpRange {
            v4: Default::default(),
            v6: Default::default(),
        }
    }
}

impl Default for IpRange {
    fn default() -> Self {
        Self::new()
    }
}
