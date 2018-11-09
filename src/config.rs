use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::ip::IpRange;

use failure::{err_msg, Error};
use ipnet::IpNet;
use serde_derive::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub upstreams: Arc<HashMap<String, UpstreamConfig>>,
    pub ranges: Arc<HashMap<String, IpRange>>,
    pub rules: Arc<Vec<Rule>>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigBuilder {
    bind: SocketAddr,
    upstreams: HashMap<String, UpstreamConfig>,
    ranges: HashMap<String, IpRangeConf>,
    rules: Vec<Rule>,
}

impl ConfigBuilder {
    pub fn build(self) -> Result<Config, Error> {
        if self.upstreams.is_empty() {
            return Err(err_msg("You must configure at least one upstream server!"));
        }
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
            upstreams: Arc::new(self.upstreams),
            ranges: Arc::new(ranges?),
            rules: Arc::new(self.rules),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    pub address: SocketAddr,
    pub network: NetworkType,
    #[serde(rename = "tls-host")]
    pub tls_host: Option<String>
}

#[derive(Debug, Deserialize)]
pub enum NetworkType {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "tls")]
    Tls
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

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub upstreams: Vec<String>,
    pub ranges: Vec<String>,
    pub action: RuleAction,
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub enum RuleAction {
    #[serde(rename = "accept")]
    Accept,
    #[serde(rename = "drop")]
    Drop,
}
