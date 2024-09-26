package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Fingerprint struct {
	CICDPass      bool     `json:"cicd_pass"`
	CName         []string `json:"cname"`
	Discussion    string   `json:"discussion"`
	Documentation string   `json:"documentation"`
	Fingerprint   string   `json:"fingerprint"`
	HTTPStatus    *int     `json:"http_status"`
	NXDomain      bool     `json:"nxdomain"`
	Service       string   `json:"service"`
	Status        string   `json:"status"`
	Vulnerable    bool     `json:"vulnerable"`
}

func Fingerprints() ([]Fingerprint, error) {
	var fingerprints []Fingerprint

	absPath, err := filepath.Abs("internal/sdt/runner/fingerprints.json")
	if err != nil {
		fmt.Println("Error getting absolute path:", err)
		return nil, fmt.Errorf("Fingerprints: %v", err)
	}

	file, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("Fingerprints: %v", err)
	}

	err = json.Unmarshal(file, &fingerprints)
	if err != nil {
		return nil, fmt.Errorf("Fingerprints: %v", err)
	}
	return fingerprints, nil
}
