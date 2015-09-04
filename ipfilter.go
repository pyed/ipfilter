package ipfilter

import (
	"io"
	"net"
	"net/http"
	"os"
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
	BlockPage    string // optional page to write to blocked requests
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

// for efficiency, we will spin a goroutine that will listen on `IPChan`;
// and will do the lookup and send back the country code over `CCChan`.
var (
	IPChan = make(chan string) // send IPs over this channel
	CCChan = make(chan string) // get CountryCodes over this channel
)

// 'lookup' will be spawned in a goroutine to listen to 'IPChan'
func lookup(database string) {
	db, _ := maxminddb.Open(database)
	defer db.Close()

	var ipInfo onlyCountry
	var parsedIP net.IP
	// listening loop
	for {
		// get the IP and parse it into `net.IP`
		parsedIP = net.ParseIP(<-IPChan)
		db.Lookup(parsedIP, &ipInfo)
		// send the country code through 'CCChan'
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
	// if we are not in our scope, pass-thru
	if !middleware.Path(r.URL.Path).Matches(ipf.Config.PathScope) {
		return ipf.Next.ServeHTTP(w, r)
	}

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// send the IP to 'IPChan' and get the client's country from 'CCChan'
	IPChan <- clientIP
	clientCountry := <-CCChan

	switch ipf.Config.Type {
	case "allow":
		for _, c := range ipf.Config.CountryCodes {
			if clientCountry == c {
				return ipf.Next.ServeHTTP(w, r)
			}
		}
		// if we have blockpage, write it
		if ipf.Config.BlockPage != "" {
			bp, err := os.Open(ipf.Config.BlockPage)
			if err != nil {
				return http.StatusInternalServerError, err
			}
			defer bp.Close()

			if _, err := io.Copy(w, bp); err != nil {
				return http.StatusInternalServerError, err
			}
			// we wrote the blockpage, return OK
			return http.StatusOK, nil

		}
		// if we don't have blockpage, return forbidden
		return http.StatusForbidden, nil

	case "block":
		for _, c := range ipf.Config.CountryCodes {
			if clientCountry == c {
				// if we have blockpage, write it
				if ipf.Config.BlockPage != "" {
					bp, err := os.Open(ipf.Config.BlockPage)
					if err != nil {
						return http.StatusInternalServerError, err
					}
					defer bp.Close()

					if _, err := io.Copy(w, bp); err != nil {
						return http.StatusInternalServerError, err
					}
					// we wrote the blockpage, return OK
					return http.StatusOK, nil
				}
				// if we don't have blockpage, return forbidden
				return http.StatusForbidden, nil
			}
		}
		// the client isn't blocked, pass-thru
		return ipf.Next.ServeHTTP(w, r)

	default: // we have to return anyway
		return ipf.Next.ServeHTTP(w, r)
	}

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
				// check if the database file exists
				database := c.Val()
				if _, err := os.Stat(database); os.IsNotExist(err) {
					return config, c.Err("No such file: " + database)
				}
				config.Database = database
			case "blockpage":
				if !c.NextArg() {
					return config, c.ArgErr()
				}
				// check if blockpage exists
				blockpage := c.Val()
				if _, err := os.Stat(blockpage); os.IsNotExist(err) {
					return config, c.Err("No such file: " + blockpage)
				}
				config.BlockPage = blockpage

			case "allow", "block":
				if !c.NextArg() {
					return config, c.ArgErr()
				}
				config.Type = value
				config.CountryCodes = strings.Split(c.Val(), " ")
			}
		}
	}
	// These two are mandatory
	if config.Database == "" || config.Type == "" {
		return config, c.ArgErr()
	}
	return config, nil
}
