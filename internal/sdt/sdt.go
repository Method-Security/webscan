package sdt

import (
	webscan "github.com/Method-Security/webscan/generated/go"
	"github.com/Method-Security/webscan/internal/sdt/runner"
)

func AnalyzeSDT(config *runner.Config) (*webscan.SubdomainTakeoverReport, error) {
	return runner.Process(config)
}
