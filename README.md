# ipfilter
[![Go Report Card](https://goreportcard.com/badge/pyed/ipfilter)](https://goreportcard.com/report/pyed/ipfilter)

ipfilter is a middleware for [Caddy](http://caddyserver.com)

# Caddyfile examples

#### filter clients based on a giving IP or range of IPs
```
ipfilter / {
	rule block
	ip 192.168 213.42.9.10-50 214.1.1.10
}
```
`caddy` will block any clients with IPs that fall into one of these two ranges `192.168.0.0` to `192.168.255.255` and `213.42.9.10` to `213.42.9.50` , or a client that has an IP of `214.1.1.10` explicitly, ranges are inclusive, which means `213.42.9.50` will get blocked.

```
ipfilter / {
	rule allow
	blockpage default.html
	ip 55.3.4.20 55.3.4.30
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
	ip 131.133.10 155.23.2.0-50
}
```
You can use as many `ipfilter` blocks as you please, the above says: block everyone but `32.55.3.10`, Unless it falls in the range `131.133.10.0`-`131.133.10.255` and requesting a path in `/webhook`