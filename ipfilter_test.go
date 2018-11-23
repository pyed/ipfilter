package ipfilter

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/oschwald/maxminddb-golang"
)

const (
	// 'GeoLite2.mmdb' taken from 'MaxMind.com'
	// 'https://dev.maxmind.com/geoip/geoip2/geolite2/'
	BlacklistPrefix = "./testdata/blacklist"
	WhitelistPrefix = "./testdata/whitelist"
	DataBase        = "./testdata/GeoLite2.mmdb"
	BlockPage       = "./testdata/blockpage.html"
	Allow           = "allow"
	Block           = "block"
	BlockMsg        = "You are not allowed here"
)

func TestCountryCodes(t *testing.T) {
	TestCases := []struct {
		ipfconf        IPFConfig
		reqIP          string
		scope          string
		expectedBody   string
		expectedStatus int
	}{
		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes:   []string{"/"},
					BlockPage:    BlockPage,
					IsBlock:      false,
					CountryCodes: []string{"JP", "SA"},
				},
			},
		},
			"8.8.8.8:_", // US
			"/",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes:   []string{"/private"},
					BlockPage:    BlockPage,
					IsBlock:      true,
					CountryCodes: []string{"US", "CA"},
				},
			},
		},
			"24.53.192.20:_", // CA
			"/private",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes:   []string{"/testdata"},
					IsBlock:      true,
					CountryCodes: []string{"RU", "CN"},
				},
			},
		},
			"42.48.120.7:_", // CN
			"/",
			"",
			http.StatusOK, // pass-thru, out of scope
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes:   []string{"/"},
					IsBlock:      true,
					CountryCodes: []string{"RU", "JP", "SA"},
				},
			},
		},
			"78.95.221.163:_", // SA
			"/",
			"",
			http.StatusForbidden,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes:   []string{"/onlyus"},
					IsBlock:      false,
					CountryCodes: []string{"US"},
				},
			},
		},
			"5.175.96.22:_", // RU
			"/onlyus",
			"",
			http.StatusForbidden,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes:   []string{"/"},
					IsBlock:      false,
					CountryCodes: []string{"FR", "GB", "AE", "DE"},
				},
			},
		},
			"5.4.9.3:_", // DE
			"/",
			"",
			http.StatusOK, // Allowed
		},
	}
	// open the db
	db, err := maxminddb.Open(DataBase)
	if err != nil {
		t.Fatalf("Error opening the database: %v", err)
	}
	defer db.Close()

	for _, tc := range TestCases {

		ipf := IPFilter{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return http.StatusOK, nil
			}),
			Config: tc.ipfconf,
		}

		// set the DBHandler
		ipf.Config.DBHandler = db

		req, err := http.NewRequest("GET", tc.scope, nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}

		req.RemoteAddr = tc.reqIP

		rec := httptest.NewRecorder()

		status, _ := ipf.ServeHTTP(rec, req)
		if status != tc.expectedStatus {
			t.Fatalf("Expected StatusCode: '%d', Got: '%d'\nTestCase: %v\n",
				tc.expectedStatus, status, tc)
		}

		if rec.Body.String() != tc.expectedBody {
			t.Fatalf("Expected Body: '%s', Got: '%s'\nTestCase: %v\n",
				tc.expectedBody, rec.Body.String(), tc)
		}
	}
}

func TestPrefixDir(t *testing.T) {
	TestCases := []struct {
		ipfconf        IPFConfig
		reqIP          string
		scope          string
		expectedBody   string
		expectedStatus int
	}{
		// Non blacklisted address should be okay.
		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					IsBlock:    true,
					PrefixDir:  BlacklistPrefix,
				},
			},
		},
			"243.1.3.15:_",
			"/",
			"",
			http.StatusOK,
		},

		// "Flat" blacklisted address should be forbidden. Note that IPv6
		// "::1" is always a "flat" address as it has no leading non-zero
		// components and thus can't be sharded.
		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					IsBlock:    true,
					PrefixDir:  BlacklistPrefix,
				},
			},
		},
			"[::1]:_",
			"/",
			"",
			http.StatusForbidden,
		},

		// "Sharded" blacklisted IPv6 address should be forbidden.
		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					IsBlock:    true,
					PrefixDir:  BlacklistPrefix,
				},
			},
		},
			"[1234:abcd::1]:_",
			"/",
			"",
			http.StatusForbidden,
		},

		// "Sharded" blacklisted IPv4 address should be forbidden.
		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					IsBlock:    true,
					PrefixDir:  BlacklistPrefix,
				},
			},
		},
			//"[::1]:_",
			"192.168.1.2:_",
			"/",
			"",
			http.StatusForbidden,
		},

		// "Flat" whitelisted IPv4 address should be okay even if the
		// preceding rule would have blacklisted it.
		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					IsBlock:    true,
					Nets:       parseCIDRs([]string{"127.0.0.1/32"}),
				},
				{
					PathScopes: []string{"/"},
					IsBlock:    false,
					PrefixDir:  WhitelistPrefix,
				},
			},
		},
			"127.0.0.1:_",
			"/hello",
			"",
			http.StatusOK,
		},
	}

	for _, tc := range TestCases {
		ipf := IPFilter{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return http.StatusOK, nil
			}),
			Config: tc.ipfconf,
		}
		req, err := http.NewRequest("GET", tc.scope, nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}

		req.RemoteAddr = tc.reqIP

		rec := httptest.NewRecorder()

		status, _ := ipf.ServeHTTP(rec, req)
		if status != tc.expectedStatus {
			t.Fatalf("Expected StatusCode: '%d', Got: '%d'\nTestCase: %v\n",
				tc.expectedStatus, status, tc)
		}

		if rec.Body.String() != tc.expectedBody {
			t.Fatalf("Expected Body: '%s', Got: '%s'\nTestCase: %v\n",
				tc.expectedBody, rec.Body.String(), tc)
		}
	}
}
func TestNets(t *testing.T) {
	TestCases := []struct {
		ipfconf        IPFConfig
		reqIP          string
		scope          string
		expectedBody   string
		expectedStatus int
	}{
		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					BlockPage:  BlockPage,
					IsBlock:    true,
					Nets: parseCIDRs([]string{"243.1.3.10/31", "243.1.3.12/30",
						"243.1.3.16/30", "243.1.3.20/32"}),
				},
			},
		},
			"243.1.3.15:_",
			"/",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/private"},
					BlockPage:  BlockPage,
					IsBlock:    true,
					Nets:       parseCIDRs([]string{"243.1.3.0/24", "202.33.44.0/24"}),
				},
			},
		},
			"202.33.44.224:_",
			"/private",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					BlockPage:  BlockPage,
					IsBlock:    true,
					Nets: parseCIDRs([]string{
						"243.1.3.10/31", "243.1.3.12/30", "243.1.3.16/30", "243.1.3.20/32",
					}),
				},
			},
		},
			"243.1.3.9:_",
			"/",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/eighties"},
					BlockPage:  BlockPage,
					IsBlock:    false,
					Nets: parseCIDRs([]string{
						"243.1.3.10/31", "243.1.3.12/30", "243.1.3.16/30", "243.1.3.20/32",
						"80.0.0.0/8",
					}),
				},
			},
		},
			"80.245.155.250:_",
			"/eighties",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/eighties"},
					IsBlock:    true,
					Nets: parseCIDRs([]string{
						"243.1.3.10/31", "243.1.3.12/30", "243.1.3.16/30", "243.1.3.20/32",
						"80.0.0.0/8",
					}),
				},
			},
		},
			"80.245.155.250:_",
			"/",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					IsBlock:    true,
					Nets: parseCIDRs([]string{
						"243.1.3.10/31", "243.1.3.12/30", "243.1.3.16/30", "243.1.3.20/32",
						"80.0.0.0/8", "23.1.3.1/32", "23.1.3.2/31", "23.1.3.4/30", "23.1.3.8/29",
						"23.1.3.16/30", "23.1.3.20/32", "85.0.0.0/8",
					}),
				},
			},
		},
			"23.1.3.9:_",
			"/",
			"",
			http.StatusForbidden,
		},
		// From here on out, tests are covering single IPNets
		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					BlockPage:  BlockPage,
					IsBlock:    true,
					Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
				},
			},
		},
			"8.8.4.4:_",
			"/",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/"},
					BlockPage:  BlockPage,
					IsBlock:    false,
					Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
				},
			},
		},
			"8.8.4.4:_",
			"/",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/private"},
					BlockPage:  BlockPage,
					IsBlock:    false,
					Nets: parseCIDRs([]string{
						"52.9.1.2/32", "52.9.1.3/32", "52.9.1.4/32",
					}),
				},
			},
		},
			"52.9.1.3:_",
			"/private",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/private"},
					BlockPage:  BlockPage,
					IsBlock:    false,
					Nets:       parseCIDRs([]string{"99.1.8.8/32"}),
				},
			},
		},
			"90.90.90.90:_",
			"/",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			Paths: []IPPath{
				{
					PathScopes: []string{"/private"},
					IsBlock:    true,
					Nets: parseCIDRs([]string{
						"52.9.1.2/32",
						"52.9.1.3/32",
						"52.9.1.4/32",
					}),
				},
			},
		},
			"52.9.1.3:_",
			"/private",
			"",
			http.StatusForbidden,
		},
	}

	for _, tc := range TestCases {
		ipf := IPFilter{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return http.StatusOK, nil
			}),
			Config: tc.ipfconf,
		}
		req, err := http.NewRequest("GET", tc.scope, nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}

		req.RemoteAddr = tc.reqIP

		rec := httptest.NewRecorder()

		status, _ := ipf.ServeHTTP(rec, req)
		if status != tc.expectedStatus {
			t.Fatalf("Expected StatusCode: '%d', Got: '%d'\nTestCase: %v\n",
				tc.expectedStatus, status, tc)
		}

		if rec.Body.String() != tc.expectedBody {
			t.Fatalf("Expected Body: '%s', Got: '%s'\nTestCase: %v\n",
				tc.expectedBody, rec.Body.String(), tc)
		}
	}
}

func TestFwdForIPs(t *testing.T) {
	// These test cases provide test coverage for proxied requests support (Refer to https://github.com/pyed/ipfilter/pull/4)
	TestCases := []struct {
		ipfconf        IPFConfig
		reqIP          string
		fwdFor         string
		scope          string
		expectedStatus int
	}{
		// Middleware should block request when filtering rule is set to 'Block', a *blocked* IP is passed in the 'X-Forwarded-For' header and the request is coming from *permitted* remote address
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    true,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
					},
				},
			},
			"8.8.4.4:_",
			"8.8.8.8",
			"/",
			http.StatusForbidden,
		},
		// Middleware should allow request when filtering rule is set to 'Block', no IP is passed in the 'X-Forwarded-For' header and the request is coming from *permitted* remote address
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    true,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
					},
				},
			},
			"8.8.4.4:_",
			"",
			"/",
			http.StatusOK,
		},
		// Middleware should allow request when filtering rule is set to 'Block', a *permitted* IP is passed in the 'X-Forwarded-For' header and the request is coming from *blocked* remote address
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    true,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
					},
				},
			},
			"8.8.8.8:_",
			"8.8.4.4",
			"/",
			http.StatusOK,
		},
		// Middleware should allow request when filtering rule is set to 'Allow', a *permitted* IP is passed in the 'X-Forwarded-For' header and the request is coming from *blocked* remote address
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    false,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
					},
				},
			},
			"8.8.4.4:_",
			"8.8.8.8",
			"/",
			http.StatusOK,
		},
		// Middleware should block request when filtering rule is set to 'Allow', no IP is passed in the 'X-Forwarded-For' header and the request is coming from *blocked* remote address
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    false,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
					},
				},
			},
			"8.8.4.4:_",
			"",
			"/",
			http.StatusForbidden,
		},
		// Middleware should block request when filtering rule is set to 'Allow', a *blocked* IP is passed in the 'X-Forwarded-For' header and the request is coming from *permitted* remote address
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    false,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
					},
				},
			},
			"8.8.8.8:_",
			"8.8.4.4",
			"/",
			http.StatusForbidden,
		},
	}

	for _, tc := range TestCases {
		ipf := IPFilter{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return http.StatusOK, nil
			}),
			Config: tc.ipfconf,
		}

		req, err := http.NewRequest("GET", tc.scope, nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}

		req.RemoteAddr = tc.reqIP
		if tc.fwdFor != "" {
			req.Header.Set("X-Forwarded-For", tc.fwdFor)
		}

		rec := httptest.NewRecorder()

		status, _ := ipf.ServeHTTP(rec, req)
		if status != tc.expectedStatus {
			t.Fatalf("Expected StatusCode: '%d', Got: '%d'\nTestCase: %v\n",
				tc.expectedStatus, status, tc)
		}
	}
}

func TestStrict(t *testing.T) {
	TestCases := []struct {
		ipfconf        IPFConfig
		reqIP          string
		fwdFor         string
		scope          string
		expectedStatus int
	}{
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    true,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
						Strict:     true,
					},
				},
			},
			"8.8.4.4:_",
			"8.8.8.8",
			"/",
			http.StatusOK,
		},
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    true,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
						Strict:     true,
					},
				},
			},
			"8.8.8.8:_",
			"8.8.8.8",
			"/",
			http.StatusForbidden,
		},
		{
			IPFConfig{
				Paths: []IPPath{
					{
						PathScopes: []string{"/"},
						IsBlock:    true,
						Nets:       parseCIDRs([]string{"8.8.8.8/32"}),
						Strict:     false,
					},
				},
			},
			"8.8.4.4:_",
			"8.8.8.8",
			"/",
			http.StatusForbidden,
		},
	}

	for _, tc := range TestCases {
		ipf := IPFilter{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return http.StatusOK, nil
			}),
			Config: tc.ipfconf,
		}

		req, err := http.NewRequest("GET", tc.scope, nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}

		req.RemoteAddr = tc.reqIP
		if tc.fwdFor != "" {
			req.Header.Set("X-Forwarded-For", tc.fwdFor)
		}

		rec := httptest.NewRecorder()

		status, _ := ipf.ServeHTTP(rec, req)
		if status != tc.expectedStatus {
			t.Fatalf("Expected StatusCode: '%d', Got: '%d'\nTestCase: %v\n",
				tc.expectedStatus, status, tc)
		}
	}
}

func TestIpfilterParseSingle(t *testing.T) {
	tests := []struct {
		inputIpfilterConfig string
		shouldErr           bool
		expectedPath        IPPath
		DBHandler           *maxminddb.Reader
	}{
		{`/ {
			rule allow
			ip 10.0.0.1
			}`, false, IPPath{
			PathScopes: []string{"/"},
			IsBlock:    false,
			Nets:       parseCIDRs([]string{"10.0.0.1/32"}),
		}, nil,
		},
		{fmt.Sprintf(`/blog /local {
			rule block
			ip 10.0.0.1-150 20.0.0.1-255 30.0.0.2
			blockpage %s
			}`, BlockPage), false, IPPath{
			PathScopes: []string{"/local", "/blog"},
			IsBlock:    true,
			BlockPage:  BlockPage,
			Nets: parseCIDRs([]string{
				"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/29",
				"10.0.0.16/28", "10.0.0.32/27", "10.0.0.64/26", "10.0.0.128/28",
				"10.0.0.144/30", "10.0.0.148/31", "10.0.0.150/32", "20.0.0.1/32",
				"20.0.0.2/31", "20.0.0.4/30", "20.0.0.8/29", "20.0.0.16/28",
				"20.0.0.32/27", "20.0.0.64/26", "20.0.0.128/25", "30.0.0.2/32"}),
		}, nil,
		},
		{`/ {
			rule allow
			ip 192.168 10.0.0.20-25 8.8.4.4 182 0
			}`, false, IPPath{
			PathScopes: []string{"/"},
			IsBlock:    false,
			Nets: parseCIDRs([]string{
				"192.168.0.0/16", "10.0.0.20/30", "10.0.0.24/31",
				"8.8.4.4/32", "182.0.0.0/8", "0.0.0.0/8",
			}),
		}, nil,
		},
		{fmt.Sprintf(`/private /blog /local {
			rule block
			ip 11.10.12 192.168.8.4-50 20.20.20.20 255 8.8.8.8
			country US JP RU FR
			database %s
			blockpage %s
			}`, DataBase, BlockPage), false, IPPath{
			PathScopes:   []string{"/private", "/local", "/blog"},
			IsBlock:      true,
			BlockPage:    BlockPage,
			CountryCodes: []string{"US", "JP", "RU", "FR"},
			Nets: parseCIDRs([]string{
				"11.10.12.0/24", "192.168.8.4/30", "192.168.8.8/29", "192.168.8.16/28",
				"192.168.8.32/28", "192.168.8.48/31", "192.168.8.50/32", "20.20.20.20/32",
				"255.0.0.0/8", "8.8.8.8/32",
			}),
		}, &maxminddb.Reader{},
		},
		{fmt.Sprintf(`/private /blog /local /contact {
			rule block
			ip 11.10.12 192.168.8.4-50 20.20.20.20 255 8.8.8.8
			country US JP RU FR
			database %s
			blockpage %s
			}`, DataBase, BlockPage), false, IPPath{
			PathScopes:   []string{"/private", "/contact", "/local", "/blog"},
			IsBlock:      true,
			BlockPage:    BlockPage,
			CountryCodes: []string{"US", "JP", "RU", "FR"},
			Nets: parseCIDRs([]string{
				"11.10.12.0/24", "192.168.8.4/30", "192.168.8.8/29", "192.168.8.16/28",
				"192.168.8.32/28", "192.168.8.48/31", "192.168.8.50/32", "20.20.20.20/32",
				"255.0.0.0/8", "8.8.8.8/32",
			}),
		}, &maxminddb.Reader{},
		},
		{`/ {
			rule allow
			ip 11.
			}`, true, IPPath{
			PathScopes: []string{"/"},
			IsBlock:    false,
		}, nil,
		},
		{`/ {
			rule allow
			ip 192.168.1.10-
			}`, true, IPPath{
			PathScopes: []string{"/"},
			IsBlock:    false,
		}, nil,
		},
		{`/ {
			rule allow
			ip 192.168.1.10- 20.20.20.20
			}`, true, IPPath{
			PathScopes: []string{"/"},
			IsBlock:    false,
		}, nil,
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("http", test.inputIpfilterConfig)

		actualConfig := IPFConfig{[]IPPath{test.expectedPath}, nil}

		actualPath, err := ipfilterParseSingle(&actualConfig, c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got: '%v'", i, err)
		}

		// PathScopes
		if !reflect.DeepEqual(actualPath.PathScopes, test.expectedPath.PathScopes) {
			t.Errorf("Test %d expected 'PathScopes': %v got: %v",
				i, test.expectedPath.PathScopes, actualPath.PathScopes)
		}

		// Rule
		if actualPath.IsBlock != test.expectedPath.IsBlock {
			t.Errorf("Test %d expected 'IsBlock': %t, got: %t",
				i, test.expectedPath.IsBlock, actualPath.IsBlock)
		}

		// BlockPage
		if actualPath.BlockPage != test.expectedPath.BlockPage {
			t.Errorf("Test %d expected 'BlockPage': %s got: %s",
				i, test.expectedPath.BlockPage, actualPath.BlockPage)
		}

		// CountryCodes
		if !reflect.DeepEqual(actualPath.CountryCodes, test.expectedPath.CountryCodes) {
			t.Errorf("Test %d expected 'CountryCodes': %v got: %v",
				i, test.expectedPath.CountryCodes, actualPath.CountryCodes)
		}

		// Nets
		if len(actualPath.Nets) != len(test.expectedPath.Nets) {
			t.Errorf("Test %d expected 'Nets': %s\ngot: %s",
				i, test.expectedPath.Nets, actualPath.Nets)
		}
		for n := range actualPath.Nets {
			if actualPath.Nets[n].String() != test.expectedPath.Nets[n].String() {
				t.Errorf("Test %d expected : %s\ngot: %s",
					i, test.expectedPath.Nets[n], actualPath.Nets[n])
			}
		}

		// DBHandler
		if actualConfig.DBHandler == nil && test.DBHandler != nil {
			t.Errorf("Test %d expected 'DBHandler' to NOT be a nil, got a non-nil", i)
		}
		if actualConfig.DBHandler != nil && test.DBHandler == nil {
			t.Errorf("Test %d expected 'DBHandler' to be nil, it is not", i)
		}

	}
}

func TestMultipleIpFilters(t *testing.T) {
	TestCases := []struct {
		inputIpfilterConfig string
		shouldErr           bool
		reqIP               string
		reqPath             string
		expectedStatus      int
	}{
		{
			`ipfilter / {
				rule block
				ip 192.168.1.10
			}
			ipfilter /allowed {
				rule allow
				ip 192.168.1.10
			}`, false, "192.168.1.10:_", "/", http.StatusForbidden,
		},
		{
			`ipfilter / {
				rule block
				ip 192.168.1.10
			}
			ipfilter /allowed {
				rule allow
				ip 192.168.1.10
			}`, false, "192.168.1.10:_", "/allowed", http.StatusOK,
		},
		{
			`ipfilter / {
				rule block
				ip 192.168.1.10
			}
			ipfilter /allowed {
				rule allow
				ip 192.168.1.10
			}`, false, "212.168.23.13:_", "/", http.StatusOK,
		},
		{
			`ipfilter / {
				rule block
				ip 192.168.1.10
			}
			ipfilter /allowed {
				rule allow
				ip 192.168.1.10
			}`, false, "212.168.23.13:_", "/allowed", http.StatusForbidden,
		},
		{
			fmt.Sprintf(`ipfilter / {
				rule allow
				ip 192.168.1.10
			}
			ipfilter /allowed {
				rule allow
				country US
				database %s
			}`, DataBase), false, "8.8.8.8:_", "/allowed", http.StatusOK,
		},
		{
			fmt.Sprintf(`ipfilter /local {
				rule allow
				ip 192.168.1
			}
			ipfilter /private {
				rule allow
				ip 192.168.1.10-15
			}
			ipfilter /notglobal /secret {
				rule block
				country RU
				database %s
			}
			ipfilter / {
				rule allow
				ip 212.222.222.1
			}`, DataBase), false, "192.168.1.9:_", "/private", http.StatusForbidden,
		},
		{
			fmt.Sprintf(`ipfilter /local {
				rule allow
				ip 192.168.1
			}
			ipfilter /private {
				rule allow
				ip 192.168.1.10-15
			}
			ipfilter /notglobal /secret {
				rule block
				country RU
				database %s
			}
			ipfilter / {
				rule allow
				ip 212.222.222.1
			}`, DataBase), false, "212.222.222.1:_", "/list", http.StatusOK,
		},
		{
			fmt.Sprintf(`ipfilter /local {
				rule allow
				ip 192.168.1
			}
			ipfilter /private {
				rule allow
				ip 192.168.1.10-15
			}
			ipfilter /notglobal /secret {
				rule block
				country RU
				database %s
			}
			ipfilter / {
				rule allow
				ip 212.222.222.1
			}`, DataBase), false, "5.175.96.22:_", "/secret", http.StatusForbidden,
		},
		{
			fmt.Sprintf(`ipfilter /local {
				rule allow
				ip 192.168.1
			}
			ipfilter /private {
				rule allow
				ip 192.168.1.10-15
			}
			ipfilter /notglobal /secret {
				rule block
				country RU
				database %s
			}
			ipfilter / {
				rule allow
				ip 212.222.222.1
			}`, DataBase), false, "192.168.1.14:_", "/local", http.StatusOK,
		},
		{
			fmt.Sprintf(`ipfilter /local {
				rule allow
				ip 192.168.1
			}
			ipfilter /private {
				rule allow
				ip 192.168.1.10-15
			}
			ipfilter /notglobal /secret {
				rule block
				country RU
				database %s
			}
			ipfilter / {
				rule allow
				ip 212.222.222.1
			}`, DataBase), false, "192.168.1.16:_", "/private", http.StatusForbidden,
		},
	}

	for i, tc := range TestCases {
		// Parse the text config
		c := caddy.NewTestController("http", tc.inputIpfilterConfig)
		config, err := ipfilterParse(c)

		if err != nil && !tc.shouldErr {
			t.Errorf("Test %d failed, error generated while it should not: %v", i, err)
		} else if err == nil && tc.shouldErr {
			t.Errorf("Test %d failed, no error generated while it should", i)
		} else if err != nil {
			continue
		}

		ipf := IPFilter{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return http.StatusOK, nil
			}),
			Config: config,
		}

		req, err := http.NewRequest("GET", tc.reqPath, nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}

		req.RemoteAddr = tc.reqIP

		rec := httptest.NewRecorder()

		status, err := ipf.ServeHTTP(rec, req)
		if err != nil {
			t.Fatalf("Test %d failed. Error generated:\n%v", i, err)
		}
		if status != tc.expectedStatus {
			t.Fatalf("Test %d failed. Expected StatusCode: '%d', Got: '%d'\nTestCase: %v\n",
				i, tc.expectedStatus, status, tc)
		}
	}
}

func TestIPv6(t *testing.T) {
	TestCases := []struct {
		inputIpfilterConfig string
		shouldErr           bool
		reqIP               string
		reqPath             string
		expectedStatus      int
	}{
		{
			`ipfilter / {
				rule allow
				ip 2001:db8:1234::/48
			}`, false, "[2001:db8:1234:0000:0000:0000:0000:0000]:_", "/", http.StatusOK,
		},
		{
			`ipfilter / {
				rule allow
				ip 2001:db8:1234::/48
			}`, false, "[2001:db8:1234:ffff:ffff:ffff:ffff:ffff]:_", "/", http.StatusOK,
		},
		{
			`ipfilter / {
				rule allow
				ip 2001:db8:1234::/48
			}`, false, "[2001:db8:1244:0000:0000:0000:0000:0000]:_", "/", http.StatusForbidden,
		},
		{
			`ipfilter / {
				rule allow
				ip 8.8.8.8 2001:db8:85a3:8d3:1319:8a2e:370:7348 8.8.4.4
			}`, false, "[2001:db8:85a3:8d3:1319:8a2e:370:7338]:_", "/", http.StatusForbidden,
		},
		{
			`ipfilter / {
				rule allow
				ip 8.8.8.8 2001:db8:85a3:8d3:1319:8a2e:370:7348 8.8.4.4
			}`, false, "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:_", "/", http.StatusOK,
		},
		{
			`ipfilter / {
				rule allow
				ip 2001:db8:85a3::8a2e:370:7334 10.0.0 192.168.1.5-40
			}`, false, "192.168.1.33:_", "/", http.StatusOK,
		},
		{
			`ipfilter / {
				rule allow
				ip 2001:db8:85a3::8a2e:370:7334/64 10.0.0
			}`, false, "10.0.0.5:_", "/", http.StatusOK,
		},
	}

	for i, tc := range TestCases {
		// Parse the text config
		c := caddy.NewTestController("http", tc.inputIpfilterConfig)
		config, err := ipfilterParse(c)

		if err != nil && !tc.shouldErr {
			t.Errorf("Test %d failed, error generated while it should not: %v", i, err)
		} else if err == nil && tc.shouldErr {
			t.Errorf("Test %d failed, no error generated while it should", i)
		} else if err != nil {
			continue
		}

		ipf := IPFilter{
			Next: httpserver.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return http.StatusOK, nil
			}),
			Config: config,
		}

		req, err := http.NewRequest("GET", tc.reqPath, nil)
		if err != nil {
			t.Fatalf("Could not create HTTP request: %v", err)
		}

		req.RemoteAddr = tc.reqIP

		rec := httptest.NewRecorder()

		status, err := ipf.ServeHTTP(rec, req)
		if err != nil {
			t.Fatalf("Test %d failed. Error generated:\n%v", i, err)
		}
		if status != tc.expectedStatus {
			t.Fatalf("Test %d failed. Expected StatusCode: '%d', Got: '%d'\nTestCase: %v\n",
				i, tc.expectedStatus, status, tc)
		}
	}

}

// parseCIDRs takes a slice of IPs as strings and returns them parsed via net.ParseCIDR as []*net.IPNet
func parseCIDRs(ips []string) []*net.IPNet {
	ipnets := make([]*net.IPNet, len(ips))
	for i, ip := range ips {
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			log.Fatalf("ParseCIDR can't parse: %s\nError: %s", ip, err)
		}

		ipnets[i] = ipnet
	}

	return ipnets
}
