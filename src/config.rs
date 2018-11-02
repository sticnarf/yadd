use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::SocketAddr;

use crate::ip::IpRange;

use failure::Error;
use ipnet::IpNet;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ConfigBuilder {
    bind: SocketAddr,
    resolvers: HashMap<String, Resolver>,
    ranges: HashMap<String, IpRangeConf>,
    rules: Vec<Rule>,
}

impl ConfigBuilder {
    pub fn build(self) -> Result<Config, Error> {
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
            resolvers: self.resolvers,
            ranges: ranges?,
            rules: self.rules,
        })
    }
}

#[derive(Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub resolvers: HashMap<String, Resolver>,
    pub ranges: HashMap<String, IpRange>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Resolver {
    address: SocketAddr,
    network: NetworkType,
}

#[derive(Debug, Deserialize)]
pub enum NetworkType {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
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
    resolvers: Vec<String>,
    ranges: Vec<String>,
    action: RuleAction,
}

#[derive(Debug, Deserialize)]
pub enum RuleAction {
    #[serde(rename = "drop")]
    Drop,
}
