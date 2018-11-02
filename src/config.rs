use std::collections::HashMap;
use std::net::SocketAddr;

use crate::ip::IpRange;

use failure::Error;
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
        let ranges: HashMap<String, IpRange> = self
            .ranges
            .into_iter()
            .map(|(key, conf)| unimplemented!())
            .collect();
        Ok(Config {
            bind: self.bind,
            resolvers: self.resolvers,
            ranges,
            rules: self.rules,
        })
    }
}

#[derive(Debug)]
pub struct Config {
    bind: SocketAddr,
    resolvers: HashMap<String, Resolver>,
    ranges: HashMap<String, IpRange>,
    rules: Vec<Rule>,
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
    file: Option<Vec<String>>,
    list: Option<Vec<SocketAddr>>,
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
