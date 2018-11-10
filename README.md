# yadd

[![Build Status](https://travis-ci.org/sticnarf/yadd.svg?branch=master)](https://travis-ci.org/sticnarf/yadd) [![AppVeyor Status](https://ci.appveyor.com/api/projects/status/github/sticnarf/yadd?branch=master&svg=true)](https://ci.appveyor.com/project/sticnarf/yadd)

Yadd (**Y**et **A**nother **D**NS **D**ispatcher) forwards DNS queries to multiple servers at the same time and decides which result to return by custom rules.

It aims to be fast and flexible but yet easy to use.

Prebuilt releases are available [here](https://github.com/sticnarf/yadd/releases). 

Because the docs in the master branch may be newer than the release you use, please switch to the corresponding git tag before going on reading.

## Features

* DNS over various protocols
  * UDP
  * TCP
  * *TLS*

* Full control over dispatching
  * Dispatch requests based on domain lists
  * Filter responses based on custom rules (consisting of IP ranges and more)

* Good performance
  * Forward to all upstreams simultaneously
  * TCP connection reuse
  
## Usage

The path of the configuration file is passed using `-c`:

```bash
$ ./yadd -c <CONFIG_FILE>
```

If you ignore `-c`, yadd will load `config.toml`.

*Note: All non-absolute file paths (in the command line arguments and in the config file) are relative to the working directory instead of the location of the executable.*

## Examples

* [ChinaDNS](examples/chinadns.toml) (Users in China should prefer this.)

* [OpenNIC](examples/opennic.toml) (Use OpenNIC DNS for OpenNIC domains and Google DNS for the others.)

* [Template with all configurable settings](examples/template.toml)
  (It is exhaustedly commented. Read it if you want to write your own config file.)

## Build

The minimum required Rustc version is 1.31 (Rust 2018).
