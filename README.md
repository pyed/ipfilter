# ipfilter
[![Go Report Card](https://goreportcard.com/badge/pyed/ipfilter)](https://goreportcard.com/report/pyed/ipfilter)

ipfilter is a middleware for [Caddy](http://caddyserver.com)

# Caddyfile examples

#### Filter clients based on a given IP or range of IPs
```
ipfilter / {
	rule block
	ip 70.1.128.0/19 2001:db8::/122 9.12.20.16
}
```
`caddy` will block any clients with IPs that fall into one of these two ranges `70.1.128.0/19` and `2001:db8::/122` , or a client that has an IP of `9.12.20.16` explicitly.

```
ipfilter / {
	rule allow
	blockpage default.html
	ip 55.3.4.20 2e80::20:f8ff:fe31:77cf
}
```
`caddy` will serve only these 2 IPs, eveyone else will get `default.html`

```
ipfilter / {
	rule block
	prefix_dir blacklisted
}
```
`caddy` will block any client IP that appears as a file name in the
*blacklisted* directory. A relative pathname is relative to the CWD when
`caddy` is started. When putting the blacklisted directory in the web
server document tree you should also add an `internal` directive to
ensure those files are not visible via HTTP GET requests. For example,
`internal /blacklisted/`. You can also specify an absolute pathname to
locate the blacklist directory outside the document tree.

You can create the file in the root of the blacklist directory. This is
known as using a "flat" namespace. For example, *blacklisted/127.0.0.1*
or *blacklisted/2601:647:4601:fa93:1865:4b6c:d055:3f3*. However,
putting thousands of files in a single directory may cause
poor performance of the lookup function. So you can also,
and should, use a "sharded" namespace. This involves creating
the file in a subdirectory based on the first two components
of the address. For example, *blacklisted/127/0/127.0.0.1* or
*blacklisted/2601/647/2601:647:4601:fa93:1865:4b6c:d055:3f3*.

Note that you can also whitelist IP addresses using this mechanism by
specifying `rule allow`. This may be useful when it follows a more general
blocking rule (e.g., by country) and you want to selectively allow some
addresses through but don't want to hardcode the addresses in the Caddy
config file.

This mechanism is most useful when coupled with automated monitoring of your
web server activity to detect signals that your server is under attack from
malware. All your monitoring software has to do is create a file in the
blacklist directory.

At this time the content of the file is ignored. In the future the contents
will probably be read and exposed as a placeholder variable for use in
conjuction with a template to be filled in via the `markdown` directive. So
you should consider putting some explanatory text in the file explaining why
the address was blocked.

#### Filter clients based on their [Country ISO Code](https://en.wikipedia.org/wiki/ISO_3166-1#Current_codes)

filtering with country codes requires a local copy of the Geo database, can be downloaded for free from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/)
```
ipfilter / {
	rule allow
	database /data/GeoLite.mmdb
	country US JP
}
```
with that in your `Caddyfile` caddy will only serve users from the `United States` or `Japan`

```
ipfilter /notglobal /secret {
	rule block
	database /data/GeoLite.mmdb
	blockpage default.html
	country US JP
}
```
having that in your `Caddyfile` caddy will ignore any requests from `United States` or `Japan` to `/notglobal` or `/secret` and it will show `default.html` instead, `blockpage` is optional.

#### Using mutiple `ipfilter` blocks

The `ipfilter` blocks are evaluated for each HTTP request in the order they
appear. The last rule which matches a request is used to decide if the request
is allowed. So in general you will want more general rules (e.g., blacklist an
entire country) to appear before more specific rules (e.g., to whitelist
specific address ranges).

```
ipfilter / {
	rule allow
	ip 32.55.3.10
}

ipfilter /webhook {
	rule allow
	ip 192.168.1.0/24
}
```
You can use as many `ipfilter` blocks as you please, the above says: block everyone but `32.55.3.10`, Unless it falls in `192.168.1.0/24` and requesting a path in `/webhook`.

#### Backward compatibility
`ipfilter` Now support [CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing), and it is the recommended way of specifiying ranges, The old formats of ranging over IPs will get converted to CIDR via [range2CIDRs](https://github.com/pyed/ipfilter/blob/master/range2CIDRs.go) only for the purpose of backward compatibility.
