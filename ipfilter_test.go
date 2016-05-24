package ipfilter

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/mholt/caddy/caddy/setup"
	"github.com/mholt/caddy/middleware"
	"github.com/oschwald/maxminddb-golang"
)

const (
	// 'GeoLite2.mmdb' taken from 'MaxMind.com'
	// 'https://dev.maxmind.com/geoip/geoip2/geolite2/'
	DataBase  = "./testdata/GeoLite2.mmdb"
	BlockPage = "./testdata/blockpage.html"
	Allow     = "allow"
	Block     = "block"
	BlockMsg  = "You are not allowed here"
)

func TestCountryCodes(t *testing.T) {
	hasCountryCodes = true

	TestCases := []struct {
		ipfconf        IPFConfig
		reqIP          string
		scope          string
		expectedBody   string
		expectedStatus int
	}{
		{IPFConfig{
			PathScopes:   []string{"/"},
			BlockPage:    BlockPage,
			Rule:         Allow,
			CountryCodes: []string{"JP", "SA"},
		},
			"8.8.8.8:_", // US
			"/",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes:   []string{"/private"},
			BlockPage:    BlockPage,
			Rule:         Block,
			CountryCodes: []string{"US", "CA"},
		},
			"24.53.192.20:_", // CA
			"/private",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes:   []string{"/testdata"},
			Rule:         Block,
			CountryCodes: []string{"RU", "CN"},
		},
			"42.48.120.7:_", // CN
			"/",
			"",
			http.StatusOK, // pass-thru, out of scope
		},

		{IPFConfig{
			PathScopes:   []string{"/"},
			Rule:         Block,
			CountryCodes: []string{"RU", "JP", "SA"},
		},
			"78.95.221.163:_", // SA
			"/",
			"",
			http.StatusForbidden,
		},

		{IPFConfig{
			PathScopes:   []string{"/onlyus"},
			Rule:         Allow,
			CountryCodes: []string{"US"},
		},
			"5.175.96.22:_", // RU
			"/onlyus",
			"",
			http.StatusForbidden,
		},

		{IPFConfig{
			PathScopes:   []string{"/"},
			Rule:         Allow,
			CountryCodes: []string{"FR", "GB", "AE", "DE"},
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
		if tc.ipfconf.Rule == Block {
			isBlock = true
		} else {
			isBlock = false
		}

		ipf := IPFilter{
			Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
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
	// get ready for the next test
	hasCountryCodes = false
}

func TestRanges(t *testing.T) {
	hasRanges = true

	TestCases := []struct {
		ipfconf        IPFConfig
		reqIP          string
		scope          string
		expectedBody   string
		expectedStatus int
	}{
		{IPFConfig{
			PathScopes: []string{"/"},
			BlockPage:  BlockPage,
			Rule:       Block,
			Ranges: []Range{
				{
					net.ParseIP("243.1.3.10"),
					net.ParseIP("243.1.3.20"),
				},
			},
		},
			"243.1.3.15:_",
			"/",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/private"},
			BlockPage:  BlockPage,
			Rule:       Block,
			Ranges: []Range{
				{
					net.ParseIP("243.1.3.10"),
					net.ParseIP("243.1.3.20"),
				},
				{
					net.ParseIP("202.33.44.1"),
					net.ParseIP("202.33.44.255"),
				},
			},
		},
			"202.33.44.224:_",
			"/private",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/"},
			BlockPage:  BlockPage,
			Rule:       Block,
			Ranges: []Range{
				{
					net.ParseIP("243.1.3.10"),
					net.ParseIP("243.1.3.20"),
				},
			},
		},
			"243.1.3.9:_",
			"/",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/eighties"},
			BlockPage:  BlockPage,
			Rule:       Allow,
			Ranges: []Range{
				{
					net.ParseIP("243.1.3.10"),
					net.ParseIP("243.1.3.20"),
				},
				{
					net.ParseIP("80.0.0.0"),
					net.ParseIP("80.255.255.255"),
				},
			},
		},
			"80.245.155.250:_",
			"/eighties",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/eighties"},
			Rule:       Block,
			Ranges: []Range{
				{
					net.ParseIP("243.1.3.10"),
					net.ParseIP("243.1.3.20"),
				},
				{
					net.ParseIP("80.0.0.0"),
					net.ParseIP("80.255.255.255"),
				},
			},
		},
			"80.245.155.250:_",
			"/",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/"},
			Rule:       Block,
			Ranges: []Range{
				{
					net.ParseIP("243.1.3.10"),
					net.ParseIP("243.1.3.20"),
				},
				{
					net.ParseIP("80.0.0.0"),
					net.ParseIP("80.255.255.255"),
				},
				{
					net.ParseIP("23.1.3.1"),
					net.ParseIP("23.1.3.20"),
				},
				{
					net.ParseIP("85.0.0.0"),
					net.ParseIP("85.255.255.255"),
				},
			},
		},
			"23.1.3.9:_",
			"/",
			"",
			http.StatusForbidden,
		},
		// From here on out, tests are covering single IP ranges
		{IPFConfig{
			PathScopes: []string{"/"},
			BlockPage:  BlockPage,
			Rule:       Block,
			Ranges: []Range{
				{
					net.ParseIP("8.8.8.8"),
					net.ParseIP("8.8.8.8"),
				},
			},
		},
			"8.8.4.4:_",
			"/",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/"},
			BlockPage:  BlockPage,
			Rule:       Allow,
			Ranges: []Range{
				{
					net.ParseIP("8.8.8.8"),
					net.ParseIP("8.8.8.8"),
				},
			},
		},
			"8.8.4.4:_",
			"/",
			BlockMsg,
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/private"},
			BlockPage:  BlockPage,
			Rule:       Allow,
			Ranges: []Range{
				{
					net.ParseIP("52.9.1.2"),
					net.ParseIP("52.9.1.2"),
				},
				{
					net.ParseIP("52.9.1.3"),
					net.ParseIP("52.9.1.3"),
				},
				{
					net.ParseIP("52.9.1.4"),
					net.ParseIP("52.9.1.4"),
				},
			},
		},
			"52.9.1.3:_",
			"/private",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/private"},
			BlockPage:  BlockPage,
			Rule:       Allow,
			Ranges: []Range{
				{
					net.ParseIP("99.1.8.8"),
					net.ParseIP("99.1.8.8"),
				},
			},
		},
			"90.90.90.90:_",
			"/",
			"",
			http.StatusOK,
		},

		{IPFConfig{
			PathScopes: []string{"/private"},
			Rule:       Block,
			Ranges: []Range{
				{
					net.ParseIP("52.9.1.2"),
					net.ParseIP("52.9.1.2"),
				},
				{
					net.ParseIP("52.9.1.3"),
					net.ParseIP("52.9.1.3"),
				},
				{
					net.ParseIP("52.9.1.4"),
					net.ParseIP("52.9.1.4"),
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
		if tc.ipfconf.Rule == Block {
			isBlock = true
		} else {
			isBlock = false
		}

		ipf := IPFilter{
			Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
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
				PathScopes: []string{"/"},
				Rule:       Block,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.4.4:12345",
			"8.8.8.8",
			"/",
			http.StatusForbidden,
		},
		// Middleware should allow request when filtering rule is set to 'Block', no IP is passed in the 'X-Forwarded-For' header and the request is coming from *permitted* remote address
		{
			IPFConfig{
				PathScopes: []string{"/"},
				Rule:       Block,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.4.4:12345",
			"",
			"/",
			http.StatusOK,
		},
		// Middleware should allow request when filtering rule is set to 'Block', a *permitted* IP is passed in the 'X-Forwarded-For' header and the request is coming from *blocked* remote address
		{
			IPFConfig{
				PathScopes: []string{"/"},
				Rule:       Block,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.8.8:12345",
			"8.8.4.4",
			"/",
			http.StatusOK,
		},
		// Middleware should allow request when filtering rule is set to 'Allow', a *permitted* IP is passed in the 'X-Forwarded-For' header and the request is coming from *blocked* remote address
		{
			IPFConfig{
				PathScopes: []string{"/"},
				Rule:       Allow,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.4.4:12345",
			"8.8.8.8",
			"/",
			http.StatusOK,
		},
		// Middleware should block request when filtering rule is set to 'Allow', no IP is passed in the 'X-Forwarded-For' header and the request is coming from *blocked* remote address
		{
			IPFConfig{
				PathScopes: []string{"/"},
				Rule:       Allow,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.4.4:12345",
			"",
			"/",
			http.StatusForbidden,
		},
		// Middleware should block request when filtering rule is set to 'Allow', a *blocked* IP is passed in the 'X-Forwarded-For' header and the request is coming from *permitted* remote address
		{
			IPFConfig{
				PathScopes: []string{"/"},
				Rule:       Allow,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.8.8:12345",
			"8.8.4.4",
			"/",
			http.StatusForbidden,
		},
	}

	for _, tc := range TestCases {
		if tc.ipfconf.Rule == Block {
			isBlock = true
		} else {
			isBlock = false
		}

		ipf := IPFilter{
			Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
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
		strict         bool
	}{
		{
			IPFConfig{
				PathScopes: []string{"/"},
				Rule:       Block,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.4.4:12345",
			"8.8.8.8",
			"/",
			http.StatusOK,
			true,
		},
		{
			IPFConfig{
				PathScopes: []string{"/"},
				Rule:       Block,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.8.8:12345",
			"8.8.8.8",
			"/",
			http.StatusForbidden,
			true,
		},
		{
			IPFConfig{
				PathScopes: []string{"/"},
				Rule:       Block,
				Ranges: []Range{
					{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.8.8"),
					},
				},
			},
			"8.8.4.4:12345",
			"8.8.8.8",
			"/",
			http.StatusForbidden,
			false,
		},
	}

	for _, tc := range TestCases {
		if tc.ipfconf.Rule == Block {
			isBlock = true
		} else {
			isBlock = false
		}

		// set the strict flag
		strict = tc.strict

		ipf := IPFilter{
			Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
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

func TestIpfilterParse(t *testing.T) {
	tests := []struct {
		inputIpfilterConfig string
		shouldErr           bool
		expectedConfig      IPFConfig
	}{
		{`ipfilter / {
			rule allow
			ip 10.0.0.1
			}`, false, IPFConfig{
			PathScopes: []string{"/"},
			Rule:       Allow,
			Ranges: []Range{
				{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.1")},
			},
		}},
		{fmt.Sprintf(`ipfilter /blog /local {
			rule block
			ip 10.0.0.1-150 20.0.0.1-255 30.0.0.2
			blockpage %s
			}`, BlockPage), false, IPFConfig{
			PathScopes: []string{"/blog", "/local"},
			Rule:       Block,
			BlockPage:  BlockPage,
			Ranges: []Range{
				{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.150")},
				{net.ParseIP("20.0.0.1"), net.ParseIP("20.0.0.255")},
				{net.ParseIP("30.0.0.2"), net.ParseIP("30.0.0.2")},
			},
		}},
		{`ipfilter / {
			rule allow
			ip 192.168 10.0.0.20-25 8.8.4.4 182 0
			}`, false, IPFConfig{
			PathScopes: []string{"/"},
			Rule:       Allow,
			Ranges: []Range{
				{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
				{net.ParseIP("10.0.0.20"), net.ParseIP("10.0.0.25")},
				{net.ParseIP("8.8.4.4"), net.ParseIP("8.8.4.4")},
				{net.ParseIP("182.0.0.0"), net.ParseIP("182.255.255.255")},
				{net.ParseIP("0.0.0.0"), net.ParseIP("0.255.255.255")},
			},
		}},
		{fmt.Sprintf(`ipfilter /private /blog /local {
			rule block
			ip 11.10.12 192.168.8.4-50 20.20.20.20 255 8.8.8.8
			country US JP RU FR
			database %s
			blockpage %s
			}`, DataBase, BlockPage), false, IPFConfig{
			PathScopes:   []string{"/private", "/blog", "/local"},
			Rule:         Block,
			BlockPage:    BlockPage,
			CountryCodes: []string{"US", "JP", "RU", "FR"},
			Ranges: []Range{
				{net.ParseIP("11.10.12.0"), net.ParseIP("11.10.12.255")},
				{net.ParseIP("192.168.8.4"), net.ParseIP("192.168.8.50")},
				{net.ParseIP("20.20.20.20"), net.ParseIP("20.20.20.20")},
				{net.ParseIP("255.0.0.0"), net.ParseIP("255.255.255.255")},
				{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.8.8")},
			},
			DBHandler: &maxminddb.Reader{},
		}},
		{`ipfilter / {
			rule allow
			ip 11.
			}`, true, IPFConfig{
			PathScopes: []string{"/"},
			Rule:       Allow,
		},
		},
		{`ipfilter / {
			rule allow
			ip 192.168.1.10-
			}`, true, IPFConfig{
			PathScopes: []string{"/"},
			Rule:       Allow,
		},
		},
		{`ipfilter / {
			rule allow
			ip 192.168.1.10- 20.20.20.20
			}`, true, IPFConfig{
			PathScopes: []string{"/"},
			Rule:       Allow,
		},
		},
	}

	for i, test := range tests {
		c := setup.NewTestController(test.inputIpfilterConfig)
		actualConfig, err := ipfilterParse(c)

		if err == nil && test.shouldErr {
			t.Errorf("Test %d didn't error, but it should have", i)
		} else if err != nil && !test.shouldErr {
			t.Errorf("Test %d errored, but it shouldn't have; got: '%v'", i, err)
		}

		// PathScopes
		if !reflect.DeepEqual(actualConfig.PathScopes, test.expectedConfig.PathScopes) {
			t.Errorf("Test %d expected 'PathScopes': %v got: %v",
				i, test.expectedConfig.PathScopes, actualConfig.PathScopes)
		}

		// Rule
		if actualConfig.Rule != test.expectedConfig.Rule {
			t.Errorf("Test %d expected 'Rule': %s, got: %s",
				i, test.expectedConfig.Rule, actualConfig.Rule)
		}

		// BlockPage
		if actualConfig.BlockPage != test.expectedConfig.BlockPage {
			t.Errorf("Test %d expected 'BlockPage': %s got: %s",
				i, test.expectedConfig.BlockPage, actualConfig.BlockPage)
		}

		// CountryCodes
		if !reflect.DeepEqual(actualConfig.CountryCodes, test.expectedConfig.CountryCodes) {
			t.Errorf("Test %d expected 'CountryCodes': %v got: %v",
				i, test.expectedConfig.CountryCodes, actualConfig.CountryCodes)
		}

		// Ranges
		if !reflect.DeepEqual(actualConfig.Ranges, test.expectedConfig.Ranges) {
			t.Errorf("Test %d expected 'Ranges': %s\ngot: %s",
				i, prettyPrintRanges(test.expectedConfig.Ranges), prettyPrintRanges(actualConfig.Ranges))
		}

		// DBHandler
		if actualConfig.DBHandler == nil && test.expectedConfig.DBHandler != nil {
			t.Errorf("Test %d expected 'DBHandler' to NOT be a nil, got a non-nil", i)
		}
		if actualConfig.DBHandler != nil && test.expectedConfig.DBHandler == nil {
			t.Errorf("Test %d expected 'DBHandler' to be nil, it is not", i)
		}

	}
}

// helps printRanges for the Ranges tests
func prettyPrintRanges(ranges []Range) string {
	buf := new(bytes.Buffer)
	for _, r := range ranges {
		buf.WriteString(fmt.Sprintf("[%s - %s] ", r.start.String(), r.end.String()))
	}
	return buf.String()
}
