package ipfilter

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/oschwald/maxminddb-golang"
)

// IPFilter is a middleware for filtering clients based on their ip or country's ISO code;
type IPFilter struct {
	Next   middleware.Handler
	Config IPFConfig
}

// IPFConfig holds the configuration for the ipfilter middleware
type IPFConfig struct {
	PathScopes   []string
	Rule         string
	BlockPage    string
	CountryCodes []string
	Ranges       []Range

	DBHandler *maxminddb.Reader // Database's handler if it gets opened
}

// to ease if-statments, and not over-use len()
var (
	hasCountryCodes bool
	hasRanges       bool
	isBlock         bool // true if the rule is 'block'
	strict          bool
)

// Range is a pair of two 'net.IP'
type Range struct {
	start net.IP
	end   net.IP
}

// InRange is a method of 'Range' takes a pointer to net.IP, returns true if in range, false otherwise
func (rng Range) InRange(ip *net.IP) bool {
	if bytes.Compare(*ip, rng.start) >= 0 && bytes.Compare(*ip, rng.end) <= 0 {
		return true
	}
	return false
}

// OnlyCountry is used to fetch only the country's code from 'mmdb'
type OnlyCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// status is used to keep track of the status of the request
type Status struct {
	countryMatch, inRange bool
}

// method of Status, returns 'true' if any of the two is true
func (s *Status) Any() bool {
	return s.countryMatch || s.inRange
}

// block will take care of blocking
func block(blockPage string, w *http.ResponseWriter) (int, error) {
	if blockPage != "" {
		bp, err := os.Open(blockPage)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		defer bp.Close()

		if _, err := io.Copy(*w, bp); err != nil {
			return http.StatusInternalServerError, err
		}
		// we wrote the blockpage, return OK
		return http.StatusOK, nil
	}

	// if we don't have blockpage, return forbidden
	return http.StatusForbidden, nil
}

// Setup parses the ipfilter configuration and returns the middleware handler
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

func getClientIP(r *http.Request) (net.IP, error) {
	var ip string

	// Use the client ip from the 'X-Forwarded-For' header, if available
	if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" && !strict {
		ip = fwdFor
	} else {
		// Otherwise, get the client ip from the request remote address
		var err error
		ip, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return nil, err
		}
	}

	// Parse the ip address string into a net.IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, errors.New("unable to parse address")
	}

	return parsedIP, nil
}

func (ipf IPFilter) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// check if we are in one of our scopes
	for _, scope := range ipf.Config.PathScopes {
		if middleware.Path(r.URL.Path).Matches(scope) {
			// extract the client's IP and parse it
			clientIP, err := getClientIP(r)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			// request status
			var rs Status

			if hasCountryCodes {
				// do the lookup
				var result OnlyCountry
				if err = ipf.Config.DBHandler.Lookup(clientIP, &result); err != nil {
					return http.StatusInternalServerError, err
				}

				// get only the ISOCode out of the lookup results
				clientCountry := result.Country.ISOCode
				for _, c := range ipf.Config.CountryCodes {
					if clientCountry == c {
						rs.countryMatch = true
						break
					}
				}
			}

			if hasRanges {
				for _, rng := range ipf.Config.Ranges {
					if rng.InRange(&clientIP) {
						rs.inRange = true
						break
					}
				}
			}

			if rs.Any() {
				if isBlock { // if the rule is block and we have a true in our status, block
					return block(ipf.Config.BlockPage, &w)
				}
				// the rule is allow, and we have a true in our status, allow
				return ipf.Next.ServeHTTP(w, r)
			}
			if isBlock { // the rule is block and we have no trues in status, allow
				return ipf.Next.ServeHTTP(w, r)
			}
			// the rule is allow, and we have no trues in status, block
			return block(ipf.Config.BlockPage, &w)
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
		if len(config.PathScopes) == 0 {
			return config, c.ArgErr()
		}

		for c.NextBlock() {
			value := c.Val()

			switch value {
			case "rule":
				if !c.NextArg() {
					return config, c.ArgErr()
				}
				config.Rule = c.Val()

				if config.Rule == "block" {
					isBlock = true
				} else if config.Rule != "allow" {
					return config, c.Err("ipfilter: Rule should be 'block' or 'allow'")
				}

			case "database":
				if !c.NextArg() {
					return config, c.ArgErr()
				}
				database := c.Val()

				// open the database
				var err error
				config.DBHandler, err = maxminddb.Open(database)
				if err != nil {
					return config, c.Err("ipfilter: Can't open database: " + database)
				}

			case "blockpage":
				if !c.NextArg() {
					return config, c.ArgErr()
				}

				// check if blockpage exists
				blockpage := c.Val()
				if _, err := os.Stat(blockpage); os.IsNotExist(err) {
					return config, c.Err("ipfilter: No such file: " + blockpage)
				}
				config.BlockPage = blockpage

			case "country":
				config.CountryCodes = c.RemainingArgs()
				if len(config.CountryCodes) == 0 {
					return config, c.ArgErr()
				}
				hasCountryCodes = true

			case "ip":
				ips := c.RemainingArgs()
				if len(ips) == 0 {
					return config, c.ArgErr()
				}

				for _, ip := range ips {
					// check if the ip isn't complete;
					// e.g. 192.168 -> Range{"192.168.0.0", "192.168.255.255"}
					dotSplit := strings.Split(ip, ".")
					if len(dotSplit) < 4 {
						startR := make([]string, len(dotSplit), 4)
						copy(startR, dotSplit)
						for len(dotSplit) < 4 {
							startR = append(startR, "0")
							dotSplit = append(dotSplit, "255")
						}
						start := net.ParseIP(strings.Join(startR, "."))
						end := net.ParseIP(strings.Join(dotSplit, "."))
						if start.To4() == nil || end.To4() == nil {
							return config, c.Err("ipfilter: Can't parse IPv4 address")
						}
						config.Ranges = append(config.Ranges, Range{start, end})
						hasRanges = true
						continue
					}

					// try to split on '-' to see if it is a range of ips e.g. 1.1.1.1-10
					splitted := strings.Split(ip, "-")
					if len(splitted) > 1 { // if more than one, then we got a range e.g. ["1.1.1.1", "10"]
						start := net.ParseIP(splitted[0])
						// make sure that we got a valid IPv4 IP
						if start.To4() == nil {
							return config, c.Err("ipfilter: Can't parse IPv4 address")
						}

						// split the start of the range on "." and switch the last field with splitted[1], e.g 1.1.1.1 -> 1.1.1.10
						fields := strings.Split(start.String(), ".")
						fields[3] = splitted[1]
						end := net.ParseIP(strings.Join(fields, "."))

						// parse the end range
						if end.To4() == nil {
							return config, c.Err("ipfilter: Can't parse IPv4 address")
						}

						// append to ranges, continue the loop
						config.Ranges = append(config.Ranges, Range{start, end})
						hasRanges = true
						continue

					}

					// the IP is not a range
					parsedIP := net.ParseIP(ip)
					if parsedIP.To4() == nil {
						return config, c.Err("ipfilter: Can't parse IPv4 address")
					}
					// append singular IPs as a range e.g Range{192.168.1.100, 192.168.1.100}
					config.Ranges = append(config.Ranges, Range{parsedIP, parsedIP})
					hasRanges = true
				}

			case "strict":
				strict = true
			}
		}
	}

	// having a databse is mandatory if you are blocking by country codes
	if hasCountryCodes && config.DBHandler == nil {
		return config, c.Err("ipfilter: Database is required to block/allow by country")
	}

	// needs atleast one of the three
	if !hasCountryCodes && !hasRanges {
		return config, c.Err("ipfilter: No IPs or Country codes has been provided")
	}
	return config, nil
}
