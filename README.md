# yadd [![Build Status](https://travis-ci.org/sticnarf/yadd.svg?branch=master)](https://travis-ci.org/sticnarf/yadd) [![AppVeyor Status](https://ci.appveyor.com/api/projects/status/github/sticnarf/yadd?branch=master&svg=true)](https://ci.appveyor.com/project/sticnarf/yadd)

Yadd (**Y**et **A**nother **D**NS **D**ispatcher) forwards DNS queries to multiple servers at the same time and decides which result to return by custom rules.

It aims to be fast and flexible but yet easy to use.

## ChinaDNS

For users in China, it is a common use case to prevent DNS spoofing as well as get good CDN IP resolution, which the default configuration is used for.

Just keep the provided `config.toml` and `chnroutes.txt` in the same directory with the yadd executable and run yadd.

This instructs yadd to listen on `127.0.0.1:5300` and forward DNS queries to `119.29.29.29` (DNSPod), `223.5.5.5` (AliDNS) and `208.67.222.222:5353` (OpenDNS).

Yadd will return the result given by DNSPod or AliDNS if it is an IP in China. Otherwise, it will adopt the result from `208.67.222.222:5353` instead.

## Configuration

Yadd has high flexibility.

Belows are explanations for `config.toml` and how you can customize it, part by part.

### Global settings

```toml
bind = "127.0.0.1:5300"
```

It is the address that yadd listens on. Feel free to change it based on your need.

Pay attention that root privilege may be required if you specifies a port below 1024.

### Upstreams

```toml
[upstreams]
  [upstreams.dnspod]
  address = "119.29.29.29:53"
  network = "udp"

  [upstreams.alidns]
  address = "223.5.5.5:53"
  network = "udp"

  [upstreams.opendns]
  address = "208.67.222.222:5353"
  network = "udp"
```

Set up the upstream servers here. DNS queries will be forwarded to all the servers set up here.

The `dnspod` and `opendns` after `upstreams.` are the names of the upstream servers. They will be used later in your rules.

You must specify the port in the `address` attribute, even if it uses the standard port `53`. IPv6 is supported here, for example, you can write `address = "[2001:4860:4860::8888]:53"`.

`network` atrribute supports two options: `udp` and `tcp`. Make sure the DNS server supports TCP if you specify `tcp` here.

Multiplexing is enabled for TCP connections. This means no second connection will be established before the previous one is closed.

### Ranges

```toml
[ranges]
  [ranges.cn]
  files = ["chnroutes.txt"]
```

Set up the IP ranges you want to use later in your rules here.

Like upstreams, the `cn` after `ranges.` is the name of the range.

A `range` supports two ways of configuration.

First is shown above: give an array of files to the `files` attribute. Yadd will load all the files in the array into the range. Each file should contain lines of CIDRs only, except those starting with `#`, which means it is a comment.

The other one is writing CIDRs directly in the configuration file, using the `list` attribute.

You can use the two ways at the same time. Here is an example:

```toml
[ranges]
  [ranges.my-range]
  files = ["chnroutes.txt"]
  list = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

### Rules

```toml
[[rules]]
upstreams = ["dnspod", "alidns"]
ranges = ["!cn"]
action = "drop"
```

Rules are how yadd deals with the responses. If the response is from the specified `upstreams` **and** the response IP is in the `ranges`, yadd will do the corresponding `action`.

`upstreams` is an array of upstream server names which are defined in the upstreams section.

The `ranges` array can contain range names as well as the original range name with a leading `!` for inversion. For instance, `!cn` matches all IP addresses which are not in the `cn` range.

The only effective option for `action` attribute now is `drop`. The first response not dropped is adopted and returned to the client.

More options will be added in later versions.

## Build

The minimum required Rustc version is 1.31 (Rust 2018).
