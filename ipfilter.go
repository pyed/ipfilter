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

// IPFilter is a middleware for filtering clients based on their country's ISO code;
// by looking up their IPs using 'MaxMind' database.
type IPFilter struct {
	Next   middleware.Handler
	Config IPFConfig
}

type IPFConfig struct {
	PathScopes   []string
	Database     string
	BlockPage    string
	Rule         string
	CountryCodes []string

	DBHandler *maxminddb.Reader // Database's handler when it get opened
}

// the following type is used to fetch only the country's code from 'mmdb'
type OnlyCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func Setup(c *setup.Controller) (middleware.Middleware, error) {
	ifconfig, err := ipfilterParse(c)
	if err != nil {
		return nil, err
	}

	// open the database
	ifconfig.DBHandler, err = maxminddb.Open(ifconfig.Database)
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
	// check if we are in one of our scopes
	for _, scope := range ipf.Config.PathScopes {
		if middleware.Path(r.URL.Path).Matches(scope) {
			// extract the client's IP and parse it via the 'net' package
			clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return http.StatusInternalServerError, err
			}
			parsedIP := net.ParseIP(clientIP)

			// do the lookup
			var result OnlyCountry
			if err = ipf.Config.DBHandler.Lookup(parsedIP, &result); err != nil {
				return http.StatusInternalServerError, err
			}

			// get only the ISOCode out of the lookup results
			clientCountry := result.Country.ISOCode

			// writeBlockPage will get called in the switch statement
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
				// the client's country isn't allowed, stop it.
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
				// the client's country isn't blocked, pass-thru
				return ipf.Next.ServeHTTP(w, r)
			}
		}
	}

	// no scope match, pass-thru
	return ipf.Next.ServeHTTP(w, r)
}

func ipfilterParse(c *setup.Controller) (IPFConfig, error) {
	var config IPFConfig

	for c.Next() {

		// get the PathScopes
		config.PathScopes = c.RemainingArgs()

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

	// These are mandatory
	if config.Database == "" ||
		config.Rule == "" ||
		len(config.PathScopes) == 0 {
		return config, c.ArgErr()
	}
	return config, nil
}
