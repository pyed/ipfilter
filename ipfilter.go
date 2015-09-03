package ipfilter

import (
	"net"
	"net/http"
	"strings"

	"github.com/mholt/caddy/config/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/oschwald/maxminddb-golang"
)

type IPFilter struct {
	Next   middleware.Handler
	Config ipfconfig
}

type ipfconfig struct {
	Database     string
	Type         string // allow or block
	CountryCodes []string
}

// the following type is used to fetch only the country code from mmdb
type onlyCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func Setup(c *setup.Controller) (middleware.Middleware, error) {
	ifconfig, err := ipfilterParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return &IPFilter{
			Next:   next,
			Config: ifconfig,
		}
	}, nil
}

func (ipf IPFilter) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	db, err := maxminddb.Open(ipf.Config.Database)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	defer db.Close()

	getCountryCode := func(ip string) (string, error) {
		parsedIP := net.ParseIP(ip)

		var ipInfo onlyCountry
		if err := db.Lookup(parsedIP, &ipInfo); err != nil {
			return "", err
		}
		return ipInfo.Country.ISOCode, nil
	}

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	clientCountry, err := getCountryCode(clientIP)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	switch ipf.Config.Type {
	case "allow":
		for _, c := range ipf.Config.CountryCodes {
			if clientCountry == c {
				return ipf.Next.ServeHTTP(w, r)
			}
		}
		return http.StatusForbidden, nil

	case "block":
		for _, c := range ipf.Config.CountryCodes {
			if clientCountry == c {
				return http.StatusForbidden, nil
			}
		}
		return ipf.Next.ServeHTTP(w, r)

	}
	return ipf.Next.ServeHTTP(w, r)

}

func ipfilterParse(c *setup.Controller) (ipfconfig, error) {
	var config ipfconfig

	for c.Next() {
		if c.Val() == "ipfilter" {
			for c.NextBlock() {
				value := c.Val()
				switch value {
				case "database":
					if !c.NextArg() {
						return config, c.ArgErr()
					}
					config.Database = c.Val()

				case "allow", "block":
					if !c.NextArg() {
						return config, c.ArgErr()
					}
					config.Type = value
					config.CountryCodes = strings.Split(c.Val(), " ")
				}
			}
		}
	}
	if config.Database == "" || config.Type == "" {
		return config, c.ArgErr()
	}
	return config, nil
}
