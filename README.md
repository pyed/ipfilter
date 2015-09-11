# ipfilter
ipfilter is a middleware for [Caddy](http://caddyserver.com) using [MaxMindDB](https://github.com/oschwald/maxminddb-golang)

# Caddyfile examples

```
ipfilter / {
	database /data/GeoLite.mmdb
	allow US JP
}
```
with that in your `Caddyfile` caddy will only serve users from the `United States` or `Japan`

```
ipfilter /notglobal /secret {
	database /data/GeoLite.mmdb
	blockpage default.html
	block US JP
}
```
having that in your `Caddyfile` caddy will ignore any requests from `United States` or `Japan` to `/notglobal` or `/secret` and it will show `default.html` instead, `blockpage` is optional
