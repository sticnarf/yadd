use std::collections::HashMap;
use std::net::SocketAddr;

use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    bind: SocketAddr,
    resolvers: HashMap<String, Resolver>,
    ranges: HashMap<String, IpRangeConf>,
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
pub struct IpRangeConf {
    file: Option<String>,
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
