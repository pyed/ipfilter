package ipfilter

import (
	"io"
	"net"
	"net/http"
	"os"

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
	BlockPage    string // optional page to write it to blocked requests
	Rule         string // allow or block
	CountryCodes []string
}

// the following type is used to fetch only the country code from mmdb
type onlyCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// The database will get bound to this variable
var DB *maxminddb.Reader

func Setup(c *setup.Controller) (middleware.Middleware, error) {
	ifconfig, err := ipfilterParse(c)
	if err != nil {
		return nil, err
	}

	// open the database to the global variable 'DB'
	DB, err = maxminddb.Open(ifconfig.Database)
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
	// if we are not in our scope, pass-thru
	if !middleware.Path(r.URL.Path).Matches(ipf.Config.PathScope) {
		return ipf.Next.ServeHTTP(w, r)
	}

	// extract the client's IP and parse it via the 'net' package
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	parsedIP := net.ParseIP(clientIP)

	// do the lookup
	var result onlyCountry
	if err = DB.Lookup(parsedIP, &result); err != nil {
		return http.StatusInternalServerError, err
	}

	// get only the ISOCode out of the lookup results
	clientCountry := result.Country.ISOCode

	// writeBlockPage will be called in the switch statement
	writeBlockPage := func() (int, error) {
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

	switch ipf.Config.Rule {
	case "allow":
		for _, c := range ipf.Config.CountryCodes {
			if clientCountry == c { // the client's country exists as allowed, pass-thru
				return ipf.Next.ServeHTTP(w, r)
			}
		}
		// the client's isn't allowed, stop it.
		// if we have blockpage, write it
		if ipf.Config.BlockPage != "" {
			return writeBlockPage()
		}
		// if we don't have blockpage, return forbidden
		return http.StatusForbidden, nil

	case "block":
		for _, c := range ipf.Config.CountryCodes {
			if clientCountry == c { // client's country exists as blokced, stop it.
				// if we have blockpage, write it
				if ipf.Config.BlockPage != "" {
					return writeBlockPage()
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
					return config, c.Err("No such database: " + database)
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
				config.CountryCodes = c.RemainingArgs()
				if len(config.CountryCodes) == 0 {
					return config, c.ArgErr()
				}
				config.Rule = value
			}
		}
	}
	// These two are mandatory
	if config.Database == "" || config.Rule == "" {
		return config, c.ArgErr()
	}
	return config, nil
}
