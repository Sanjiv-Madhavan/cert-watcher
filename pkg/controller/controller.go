package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Sanjiv-Madhavan/cert-watcher/pkg/metrics"
	"github.com/Sanjiv-Madhavan/cert-watcher/pkg/models"
	"github.com/genkiroid/cert"
	"github.com/sirupsen/logrus"
)

type Controller struct {
	log      *logrus.Entry
	metrics  *metrics.Metrics
	certs    []models.Certificate
	interval time.Duration
}

func New(interval time.Duration, servingAddress string, log *logrus.Entry, certs []models.Certificate) *Controller {
	metrics := metrics.New(log)

	if err := metrics.Run(servingAddress); err != nil {
		log.Errorf("failed to start metrics server: %s", err)
		return nil
	}
	return &Controller{
		certs:    certs,
		metrics:  metrics,
		interval: interval,
		log:      log,
	}
}

// Certs exposes certificate info to external services
func (c *Controller) Certs() []models.Certificate {
	return c.certs
}

func (c *Controller) Run(ctx context.Context) error {
	// Start the Probe
	c.probeAll(ctx)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		//select as usual
		select {
		case <-ctx.Done():
			c.log.Info("Stopping controller..")
			return nil
		case <-ticker.C:
			//give priority to a possible concurrent Done() event non-blocking way
			select {
			case <-ctx.Done():
				c.log.Info("stopping controller gracefully... ")
				return nil
			default:
			}
			c.probeAll(ctx)
		}
	}
}

func (c *Controller) probeAll(ctx context.Context) {
	c.log.Debug("Probing all certificate endpoints")

	for id, certificate := range c.certs {
		c.log.Debugf("Probing: %s", certificate.DNS)

		certificate.Info = cert.NewCert(certificate.DNS)

		if strings.HasPrefix(certificate.Info.Error, "dial tcp") {
			c.log.Warnf("Problem checking %s : %s", certificate.DNS, certificate.Info.Error)
			continue
		}

		c.certs[id] = certificate

		isValid := certificate.Info.Error == ""

		if !isValid {
			c.log.Debugf(" - Found error for %s : %s", certificate.DNS, certificate.Info.Error)
		}
		c.metrics.AddCertificateInfo(certificate, isValid)
	}
}

// Shutdown closes the metrics server gracefully
func (c *Controller) Shutdown() error {
	// If metrics server is not started than exit early
	if c.metrics == nil {
		return nil
	}

	c.log.Info("shutting down metrics server...")

	if err := c.metrics.Shutdown(); err != nil {
		return fmt.Errorf("metrics server shutdown failed: %s", err)
	}

	c.log.Info("metrics server gracefully stopped")

	return nil
}
