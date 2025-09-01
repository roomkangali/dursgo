package scanner

import (
	"github.com/roomkangali/dursgo/internal/crawler"
	"github.com/roomkangali/dursgo/internal/httpclient"
	"github.com/roomkangali/dursgo/internal/logger"
)

type Scanner interface {
	Name() string
	Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts ScannerOptions) ([]VulnerabilityResult, error)
}