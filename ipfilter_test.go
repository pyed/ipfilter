package ipfilter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mholt/caddy/middleware"
	"github.com/oschwald/maxminddb-golang"
)

const (
	// 'GeoLite2.mmdb' taken from 'MaxMind.com'
	// 'https://dev.maxmind.com/geoip/geoip2/geolite2/'
	DataBase = "./testdata/GeoLite2.mmdb"
	Page     = "./testdata/blockpage.html"
	Allow    = "allow"
	Block    = "block"
	BlockMsg = "You are not allowed here"
)

var TestCases = []struct {
	ipfconf        IPFConfig
	reqIP          string
	expectedBody   string
	expectedStatus int
}{
	{IPFConfig{
		PathScopes:   []string{"/"},
		BlockPage:    Page,
		Rule:         Allow,
		CountryCodes: []string{"JP", "SA"},
	},
		"8.8.8.8:_", // US
		BlockMsg,
		http.StatusOK,
	},

	{IPFConfig{
		PathScopes:   []string{"/"},
		BlockPage:    Page,
		Rule:         Block,
		CountryCodes: []string{"US", "CA"},
	},
		"24.53.192.20:_", // CA
		BlockMsg,
		http.StatusOK,
	},

	{IPFConfig{
		PathScopes:   []string{"/testdata"},
		Rule:         Block,
		CountryCodes: []string{"RU", "CN"},
	},
		"42.48.120.7:_", // CN
		"",
		http.StatusOK, // pass-thru, out of scope
	},

	{IPFConfig{
		PathScopes:   []string{"/testdata", "/"},
		BlockPage:    Page,
		Rule:         Allow,
		CountryCodes: []string{}, // no one allowed
	},
		"8.8.4.4:_", // US
		BlockMsg,
		http.StatusOK,
	},

	{IPFConfig{
		PathScopes:   []string{"/"},
		Rule:         Block,
		CountryCodes: []string{"RU", "JP", "SA"},
	},
		"78.95.221.163:_", // SA
		"",
		http.StatusForbidden,
	},

	{IPFConfig{
		PathScopes:   []string{"/"},
		Rule:         Allow,
		CountryCodes: []string{"US"},
	},
		"5.175.96.22:_", // RU
		"",
		http.StatusForbidden,
	},

	{IPFConfig{
		PathScopes:   []string{"/"},
		Rule:         Allow,
		CountryCodes: []string{"FR", "GB", "AE", "DE"},
	},
		"5.4.9.3:_", // DE
		"",
		http.StatusOK, // Allowed
	},
}

func TestIPFilter(t *testing.T) {
	// open the db
	db, err := maxminddb.Open(DataBase)
	if err != nil {
		t.Fatalf("Error opening the database: %v", err)
	}

	for _, tc := range TestCases {
		ipf := IPFilter{
			Next: middleware.HandlerFunc(func(w http.ResponseWriter, r *http.Request) (int, error) {
				return http.StatusOK, nil
			}),
			Config: tc.ipfconf,
		}

		// set the DBHandler
		ipf.Config.DBHandler = db

		req, err := http.NewRequest("GET", "/", nil)
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
