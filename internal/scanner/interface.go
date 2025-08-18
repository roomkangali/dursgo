package scanner

import (
	"Dursgo/internal/crawler"
	"Dursgo/internal/httpclient"
	"Dursgo/internal/logger"
)

type Scanner interface {
	Name() string
	Scan(req crawler.ParameterizedRequest, client *httpclient.Client, log *logger.Logger, opts ScannerOptions) ([]VulnerabilityResult, error)
}