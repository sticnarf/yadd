# yadd

Yadd (**Y**et **A**nother **D**NS **D**ispatcher) forwards DNS queries to multiple servers at the same time and returns the appropriate result. 

In general, we use a local DNS server to get the closest IP for sites in China and a foreign DNS server to prevent DNS spoofing.

## Usage

Keep `chnroutes.txt` in the current directory and run `yadd`.

It will listen on `127.0.0.1:5300` and forwards to `119.29.29.29` (for sites in China) and `208.67.222.222:5353` (for the others) by default.

For more options, please check `yadd --help`. Make sure that GFW does not poison the foreign server.

## Build

The minimum required Rust version is 1.31 (Rust 2018).
