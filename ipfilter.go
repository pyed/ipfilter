package ipfilter

import (
	"fmt"
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
	PathScope    string
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

// for speed, we will spin a goroutine that will listen on `IPChan`;
// and will do the lookup and send back the country code over `CCChan`.
var (
	IPChan = make(chan string) // send IPs over this channel
	CCChan = make(chan string) // get CountryCodes over this channel
)

func lookup(database string) {
	db, _ := maxminddb.Open(database)
	defer db.Close()

	var ipInfo onlyCountry
	var parsedIP net.IP
	for {
		parsedIP = net.ParseIP(<-IPChan)
		db.Lookup(parsedIP, &ipInfo)
		CCChan <- ipInfo.Country.ISOCode
	}
}

func Setup(c *setup.Controller) (middleware.Middleware, error) {
	ifconfig, err := ipfilterParse(c)
	if err != nil {
		return nil, err
	}

	// spawn a goroutine that will listen on 'IPChan'
	c.Startup = append(c.Startup, func() error {
		go lookup(ifconfig.Database)
		return nil
	})

	return func(next middleware.Handler) middleware.Handler {
		return &IPFilter{
			Next:   next,
			Config: ifconfig,
		}
	}, nil
}

func (ipf IPFilter) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	// send the IP to 'IPChan' and get the client's country from 'CCChan'
	IPChan <- clientIP
	clientCountry := <-CCChan

	fmt.Printf("%v\nIP: %s\nCC: %s\n", ipf.Config, clientIP, clientCountry)

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

		// get the pathscope
		if !c.NextArg() || c.Val() == "{" {
			return config, c.ArgErr()
		}
		config.PathScope = c.Val()

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
	// we have to have both
	if config.Database == "" || config.Type == "" {
		return config, c.ArgErr()
	}
	return config, nil
}
