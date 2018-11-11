use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::ip::IpRange;
use crate::Transpose;

use failure::{err_msg, Error};
use ipnet::IpNet;
use regex::RegexSet;
use serde_derive::Deserialize;
use std::net::IpAddr;
use trust_dns_proto::rr::record_type::RecordType;

#[derive(Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub default_upstreams: Vec<String>,
    pub upstreams: HashMap<String, Upstream>,
    pub domains: HashMap<String, Domains>,
    pub ranges: HashMap<String, IpRange>,
    pub request_rules: Vec<RequestRule>,
    pub response_rules: Vec<ResponseRule>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigBuilder {
    bind: SocketAddr,
    upstreams: HashMap<String, UpstreamConfig>,
    domains: Option<HashMap<String, DomainsConf>>,
    ranges: Option<HashMap<String, IpRangeConf>>,
    requests: Option<Vec<RequestRuleConfig>>,
    responses: Option<Vec<ResponseRule>>,
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

        let upstreams = self
            .upstreams
            .into_iter()
            .map(|(key, upstream)| {
                if upstream.default {
                    default_upstreams.push(key.clone())
                }
                upstream.build().map(move |upstream| (key, upstream))
            })
            .collect::<Result<HashMap<_, _>, Error>>()?;

        if default_upstreams.is_empty() {
            return Err(err_msg(
                "You must configure at least one default upstream server!",
            ));
        }

        let domains = self
            .domains
            .unwrap_or_default()
            .into_iter()
            .map(|(key, domains)| domains.build().map(move |domains| (key, domains)))
            .collect::<Result<HashMap<_, _>, Error>>()?;

        let ranges = self
            .ranges
            .unwrap_or_default()
            .into_iter()
            .map(|(key, conf)| {
                let mut range = IpRange::new();
                conf.read_to(&mut range).map(|()| (key, range))
            })
            .collect::<Result<HashMap<_, _>, Error>>()?;

        let request_rules: Vec<RequestRule> = self
            .requests
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.build())
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Config {
            bind: self.bind,
            default_upstreams,
            upstreams,
            domains,
            ranges,
            request_rules,
            response_rules: self.responses.unwrap_or_default(),
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
    default: bool,
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
}

#[derive(Debug, Deserialize)]
struct DomainsConf {
    files: Option<Vec<String>>,
    list: Option<Vec<String>>,
}

impl DomainsConf {
    fn domain_to_regex_string(domain: &str) -> String {
        let mut regex_str = domain.replace(".", r"\.");
        regex_str.push_str(r"\.?$");
        regex_str
    }

    fn build(self) -> Result<Domains, Error> {
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
        })
    }
}

#[derive(Debug, Deserialize)]
struct RequestRuleConfig {
    domains: Option<Vec<String>>,
    types: Option<Vec<String>>,
    upstreams: Vec<String>,
}

impl RequestRuleConfig {
    fn build(self) -> Result<RequestRule, Error> {
        let types = Transpose::transpose(self.types.map(|v| {
            v.iter()
                .map(|t| RecordType::from_str(t))
                .collect::<Result<Vec<_>, _>>()
        }))?;

        Ok(RequestRule {
            domains: self.domains,
            types,
            upstreams: self.upstreams,
        })
    }
}

#[derive(Debug)]
pub struct RequestRule {
    pub domains: Option<Vec<String>>,
    pub types: Option<Vec<RecordType>>,
    pub upstreams: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseRule {
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
