# ipfilter
[![Go Report Card](https://goreportcard.com/badge/pyed/ipfilter)](https://goreportcard.com/report/pyed/ipfilter)

ipfilter is a middleware for [Caddy](http://caddyserver.com)

# Caddyfile examples

#### filter clients based on a giving IP or range of IPs
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

#### filter clients based on their [Country ISO Code](https://en.wikipedia.org/wiki/ISO_3166-1#Current_codes)

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