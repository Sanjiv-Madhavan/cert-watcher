package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Sanjiv-Madhavan/cert-watcher/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type Metrics struct {
	*http.Server

	registry       *prometheus.Registry
	certExpiration *prometheus.GaugeVec
	certValidity   *prometheus.GaugeVec
	log            *logrus.Entry

	containerCache map[string]models.Certificate
	mutex          sync.Mutex
}

func New(log *logrus.Entry) *Metrics {
	certValidity := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "cert_checker",
			Name:      "is_valid",
			Help:      "Detailing if the certificate served by the server at the dns is valid",
		},
		[]string{
			"dns", "issuer", "not_before", "not_after", "cert_error",
		},
	)

	certExpiration := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "cert_checker",
			Name:      "expire_time",
			Help:      "Detailing when a certificate is set to expire",
		},
		[]string{
			"dns", "issuer", "not_before", "not_after",
		},
	)

	registry := prometheus.NewRegistry()
	registry.MustRegister(certValidity)
	registry.MustRegister(certExpiration)

	return &Metrics{
		log:            log,
		registry:       registry,
		certExpiration: certExpiration,
		certValidity:   certValidity,
		containerCache: make(map[string]models.Certificate),
	}
}

// Run will run the metrics server
func (m *Metrics) Run(servingAddress string) error {
	router := http.NewServeMux()
	router.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))

	ln, err := net.Listen("tcp", servingAddress)
	if err != nil {
		return err
	}

	m.Server = &http.Server{
		Addr:           ln.Addr().String(),
		ReadTimeout:    8 * time.Second,
		WriteTimeout:   8 * time.Second,
		MaxHeaderBytes: 1 << 15, // 1 MiB
		Handler:        router,
	}

	go func() {
		m.log.Infof("serving metrics on %s/metrics", servingAddress)

		if err := m.Serve(ln); err != nil && !strings.Contains(err.Error(), "Server closed") {
			m.log.Errorf("failed to serve prometheus metrics: %s", err)
			return
		}
	}()

	return nil
}

func (m *Metrics) AddCertificateInfo(certificate models.Certificate, isValid bool) {
	// Remove stale details
	m.RemoveCertificateInfo(certificate.DNS)

	// Assign mutex - assign into cache - check validity, if exists, increment guage vector -
	// if valid - set expiry
	m.containerCache[certificate.DNS] = certificate

	isValidCounter := 0.0 // Float since its better for a metric
	if isValid {
		isValidCounter = 1.0
	}

	m.certValidity.With(
		m.buildValidityLabels(certificate),
	).Set(isValidCounter)

	if !isValid {
		return
	}

	layout := "2006-01-02 15:04:05 -0700 MST"

	// Parse the time string into a time.Time value
	parsedTime, err := time.Parse(layout, certificate.Info.NotAfter)
	if err != nil {
		fmt.Println(err)
		return
	}

	m.certExpiration.With(
		m.buildExpirationLabels(certificate),
	).Set(float64(parsedTime.Unix()))
}

func (m *Metrics) RemoveCertificateInfo(dns string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	item, ok := m.containerCache[dns]
	if !ok {
		m.log.Debugf("Did not find %s in cache", dns)
		return
	}

	m.certValidity.Delete(m.buildValidityLabels(item))
	m.certExpiration.Delete(m.buildExpirationLabels(item))

	delete(m.containerCache, dns)
}

func (m *Metrics) buildExpirationLabels(certificate models.Certificate) prometheus.Labels {
	return prometheus.Labels{
		"dns":        certificate.DNS,
		"issuer":     certificate.Info.Issuer,
		"not_before": certificate.Info.NotBefore,
		"not_after":  certificate.Info.NotAfter,
	}
}

func (m *Metrics) buildValidityLabels(certificate models.Certificate) prometheus.Labels {
	return prometheus.Labels{
		"dns":        certificate.DNS,
		"issuer":     certificate.Info.Issuer,
		"not_before": certificate.Info.NotBefore,
		"not_after":  certificate.Info.NotAfter,
		"cert_error": certificate.Info.Error,
	}
}

func (m *Metrics) Shutdown() error {
	// If metrics server is not started than exit early
	if m.Server == nil {
		return nil
	}

	m.log.Info("shutting down prometheus metrics server...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	if err := m.Server.Shutdown(ctx); err != nil {
		return fmt.Errorf("prometheus metrics server shutdown failed: %s", err)
	}

	m.log.Info("prometheus metrics server gracefully stopped")

	return nil
}
