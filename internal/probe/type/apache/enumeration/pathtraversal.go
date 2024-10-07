package probe

import (
	"net/http"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
	helpers "github.com/Method-Security/webscan/internal/probe/type/general/enumeration"
)

type PathTraversalLibrary struct{}

var commonExposedPaths = []string{
	"/.cgi",
	"/.env",
	"/.git",
	"/.htaccess",
	"/cgi-bin/",
	"/cgi-bin/admin.cgi",
	"/cgi-bin/test.cgi",
	"/etc/apache2/apache2.conf",
	"/etc/httpd/conf/httpd.conf",
	"/logs/access.log",
	"/logs/error.log",
	"/perl/admin.cgi",
	"/perl/test.cgi",
	"/scripts/admin.cgi",
	"/scripts/test.cgi",
	"/server-status",
	"/test.cgi",
}

func (PathTraversalLib *PathTraversalLibrary) ModuleRun(target string, config *webscan.ProbeTypeConfig) (*webscan.Attempt, []string) {
	//Initialize structs
	attempt := webscan.Attempt{Name: webscan.ModuleNamePathTraversal, Timestamp: time.Now()}
	findingGlobal := false

	// Enumerate paths
	paths, errors := helpers.PathTraversal(target, config.Timeout, commonExposedPaths)
	for _, path := range paths {
		finding := path.Response != nil && PathTraversalLib.AnalyzeResponse(webscan.NewResponseUnionFromGeneralResponse(path.Response))
		path.Finding = &finding
		findingGlobal = findingGlobal || finding
	}

	// Marshal structs
	PathTraversalAttemptInfo := webscan.MultiplePathsAttemptInfo{Paths: paths}
	attempt.AttemptInfo = webscan.NewAttemptInfoUnionFromMultiplePathsAttempt(&PathTraversalAttemptInfo)
	attempt.Finding = findingGlobal
	return &attempt, errors
}

func (PathTraversalLib *PathTraversalLibrary) AnalyzeResponse(response *webscan.ResponseUnion) bool {
	return response.GeneralResponse.StatusCode == http.StatusOK
}
