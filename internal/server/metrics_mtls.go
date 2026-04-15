package server

import (
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	mtlsCAExpiresInSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Subsystem: "mtls",
		Name:      "ca_expires_in_seconds",
		Help:      "Seconds until the mTLS CA certificate expires.",
	})

	mtlsCertExpiresInSeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "identree",
		Subsystem: "mtls",
		Name:      "cert_expires_in_seconds",
		Help:      "Seconds until the mTLS client certificate expires, per host.",
	}, []string{"hostname"})
)

// startMTLSMetrics starts a background goroutine that updates mTLS certificate
// expiry Prometheus gauges every hour. The goroutine stops when stopCh is closed.
func (s *Server) startMTLSMetrics(stopCh <-chan struct{}) {
	// Initial update.
	s.updateMTLSMetrics()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("mTLS metrics goroutine panic", "panic", r)
			}
		}()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.updateMTLSMetrics()
			case <-stopCh:
				return
			}
		}
	}()
}

// updateMTLSMetrics refreshes the CA and per-host cert expiry gauges.
func (s *Server) updateMTLSMetrics() {
	now := time.Now()

	// CA expiry gauge.
	if s.mtlsCACert != nil {
		remaining := s.mtlsCACert.NotAfter.Sub(now).Seconds()
		mtlsCAExpiresInSeconds.Set(remaining)
	}

	// Per-host cert expiry gauges.
	expiries := s.hostRegistry.HostCertExpiries()
	for hostname, expiresAt := range expiries {
		remaining := expiresAt.Sub(now).Seconds()
		mtlsCertExpiresInSeconds.WithLabelValues(hostname).Set(remaining)
	}
}

// mtlsCertsExpiringSoon returns the count of hosts whose mTLS certificates
// expire within the given threshold duration.
func (s *Server) mtlsCertsExpiringSoon(threshold time.Duration) int {
	deadline := time.Now().Add(threshold)
	expiries := s.hostRegistry.HostCertExpiries()
	count := 0
	for _, expiresAt := range expiries {
		if expiresAt.Before(deadline) {
			count++
		}
	}
	return count
}
