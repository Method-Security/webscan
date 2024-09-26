package runner

import (
	"net/url"
)

type subdomainResult struct {
	Subdomain     string   `json:"subdomain"`
	Status        string   `json:"status"`
	Engine        string   `json:"engine"`
	Documentation string   `json:"documentation"`
	Discussion    string   `json:"discussion"`
	CICDPass      bool     `json:"cicd_pass"`
	CName         []string `json:"cname"`
	Fingerprint   string   `json:"fingerprint"`
	HTTPStatus    *int     `json:"http_status"`
	NXDomain      bool     `json:"nxdomain"`
	Service       string   `json:"service"`
	Vulnerable    bool     `json:"vulnerable"`
}

func isValidURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	return err == nil
}
