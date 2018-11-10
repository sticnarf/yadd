use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::SocketAddr;

use crate::ip::IpRange;

use failure::{err_msg, Error};
use ipnet::IpNet;
use serde_derive::Deserialize;
use std::net::IpAddr;
use regex::RegexSet;

#[derive(Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub default_upstreams: Vec<String>,
    pub upstreams: HashMap<String, Upstream>,
    pub domains: HashMap<String, Domains>,
    pub ranges: HashMap<String, IpRange>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigBuilder {
    bind: SocketAddr,
    upstreams: HashMap<String, UpstreamConfig>,
    domains: HashMap<String, DomainsConf>,
    ranges: HashMap<String, IpRangeConf>,
    rules: Vec<Rule>,
}

#[derive(Debug)]
pub enum Upstream {
    TcpUpstream {
        address: SocketAddr,
    },
    UdpUpstream {
        address: SocketAddr,
    },
    TlsUpstream {
        address: SocketAddr,
        tls_host: String,
    },
}

impl ConfigBuilder {
    pub fn build(self) -> Result<Config, Error> {
        let mut default_upstreams = Vec::new();

        let upstreams: Result<HashMap<String, Upstream>, Error> = self
            .upstreams
            .into_iter()
            .map(|(key, upstream)| {
                if upstream.default { default_upstreams.push(key.clone()) }
                upstream.build().map(move |upstream| (key, upstream))
            })
            .collect();

        if default_upstreams.is_empty() {
            return Err(err_msg("You must configure at least one default upstream server!"));
        }

        let domains: Result<HashMap<String, Domains>, Error> =  self
            .domains
            .into_iter()
            .map(|(key, domains)| domains.build().map(move |domains| (key, domains)))
            .collect();

        let ranges: Result<HashMap<String, IpRange>, Error> = self
            .ranges
            .into_iter()
            .map(|(key, conf)| {
                let mut range = IpRange::new();
                conf.read_to(&mut range).map(|()| (key, range))
            })
            .collect();

        Ok(Config {
            bind: self.bind,
            default_upstreams,
            upstreams: upstreams?,
            domains: domains?,
            ranges: ranges?,
            rules: self.rules,
        })
    }
}

#[derive(Debug, Deserialize)]
struct UpstreamConfig {
    address: String,
    network: NetworkType,
    #[serde(rename = "tls-host")]
    tls_host: Option<String>,
    #[serde(default = "UpstreamConfig::default_default")]
    default: bool
}

impl UpstreamConfig {
    fn default_default() -> bool {
        true
    }

    fn build(self) -> Result<Upstream, Error> {
        let mut address = self.address.parse::<SocketAddr>();
        if let Err(_) = address {
            address = self
                .address
                .parse::<IpAddr>()
                .map(|addr| SocketAddr::new(addr, self.network.default_port()));
        }
        let address = address.map_err(|_| err_msg(format!("Invalid address: {}", self.address)))?;
        match self.network {
            NetworkType::Tcp => Ok(Upstream::TcpUpstream { address }),
            NetworkType::Udp => Ok(Upstream::UdpUpstream { address }),
            NetworkType::Tls => {
                let tls_host = self.tls_host.ok_or(err_msg("tls-host is missing"))?;
                Ok(Upstream::TlsUpstream { address, tls_host })
            }
        }
    }
}

#[derive(Debug, Deserialize)]
enum NetworkType {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "tls")]
    Tls,
}

impl NetworkType {
    fn default_port(&self) -> u16 {
        match self {
            NetworkType::Tcp | NetworkType::Udp => 53,
            NetworkType::Tls => 853,
        }
    }
}

#[derive(Debug, Deserialize)]
struct IpRangeConf {
    files: Option<Vec<String>>,
    list: Option<Vec<String>>,
}

impl IpRangeConf {
    fn read_to(&self, range: &mut IpRange) -> Result<(), Error> {
        if let Some(files) = &self.files {
            for file in files {
                let file = File::open(file)?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let line = line?;
                    let line = line.trim();
                    if line.is_empty() || line.starts_with("#") {
                        continue;
                    }
                    let ip_net: IpNet = line.parse()?;
                    range.add(ip_net);
                }
            }
        }

        if let Some(list) = &self.list {
            for ip_net in list {
                let ip_net: IpNet = ip_net.trim().parse()?;
                range.add(ip_net);
            }
        }

        range.simplify();
        Ok(())
    }
}

#[derive(Debug)]
pub struct Domains {
    pub regex_set: RegexSet,
    pub upstreams: Option<Vec<String>>
}

#[derive(Debug, Deserialize)]
struct DomainsConf {
    files: Option<Vec<String>>,
    list: Option<Vec<String>>,
    upstreams: Option<Vec<String>>
}

impl DomainsConf {
    fn domain_to_regex_string(domain: &str) -> String {
        let mut regex_str = domain.replace(".", r"\.");
        regex_str.push_str(r"\.?$");
        regex_str
    }

    fn build(self) -> Result<Domains, Error> {
        if self.upstreams.as_ref().map(|u| u.is_empty()).unwrap_or(false) {
            return Err(err_msg("An empty array is not allowed in the upstream field."));
        }

        let mut vec = Vec::new();

        if let Some(files) = &self.files {
            for file in files {
                let file = File::open(file)?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let line = line?;
                    let line = line.trim();
                    if line.is_empty() || line.starts_with("#") {
                        continue;
                    }
                    vec.push(Self::domain_to_regex_string(line));
                }
            }
        }

        if let Some(list) = &self.list {
            for ip_net in list {
                vec.push(Self::domain_to_regex_string(ip_net.trim()));
            }
        }

        Ok(Domains {
            regex_set: RegexSet::new(&vec)?,
            upstreams: self.upstreams
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub upstreams: Option<Vec<String>>,
    pub ranges: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    pub action: RuleAction,
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum RuleAction {
    #[serde(rename = "accept")]
    Accept,
    #[serde(rename = "drop")]
    Drop,
}
