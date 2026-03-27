package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	challengesCreated = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "challenges_created_total",
		Help:      "Total number of sudo challenges created.",
	})

	challengesApproved = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "challenges_approved_total",
		Help:      "Total number of sudo challenges approved via OIDC authentication.",
	})

	challengesAutoApproved = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "challenges_auto_approved_total",
		Help:      "Total number of sudo challenges auto-approved via grace period.",
	})

	challengesDenied = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "challenges_denied_total",
		Help:      "Total number of sudo challenges denied.",
	}, []string{"reason"})

	challengesExpired = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "challenges_expired_total",
		Help:      "Total number of sudo challenges that expired without resolution.",
	})

	challengeDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "identree",
		Name:      "challenge_duration_seconds",
		Help:      "Time from challenge creation to resolution.",
		Buckets:   []float64{5, 10, 15, 30, 45, 60, 90, 120},
	})

	rateLimitRejections = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "rate_limit_rejections_total",
		Help:      "Total challenge creation requests rejected by rate limiting.",
	})

	authFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "auth_failures_total",
		Help:      "Total requests rejected due to invalid shared secret.",
	})

	activeChallenges = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Name:      "active_challenges",
		Help:      "Number of currently active (pending) challenges.",
	})

	breakglassEscrowTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "breakglass_escrow_total",
		Help:      "Total break-glass password escrow operations.",
	}, []string{"status"})

	notificationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "notifications_total",
		Help:      "Total push notification attempts.",
	}, []string{"status"}) // sent, failed, skipped

	graceSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Name:      "grace_sessions_active",
		Help:      "Current number of active grace period sessions.",
	})

	oidcExchangeDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "identree",
		Name:      "oidc_exchange_duration_seconds",
		Help:      "Time spent on OIDC token exchange.",
		Buckets:   []float64{0.1, 0.25, 0.5, 1, 2, 5, 15},
	})

	registeredHosts = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Name:      "registered_hosts",
		Help:      "Number of hosts registered in the host registry.",
	})

	ldapRefreshTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "ldap_refresh_total",
		Help:      "Total LDAP directory refresh operations.",
	}, []string{"trigger"}) // poll, webhook

	ldapQueryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identree",
		Name:      "ldap_queries_total",
		Help:      "Total LDAP search queries served.",
	}, []string{"base"}) // people, groups, sudoers, root
)

func init() {
	notificationsTotal.WithLabelValues("sent")
	notificationsTotal.WithLabelValues("failed")
	notificationsTotal.WithLabelValues("skipped")
	breakglassEscrowTotal.WithLabelValues("success")
	breakglassEscrowTotal.WithLabelValues("failure")
	challengesDenied.WithLabelValues("oidc_error")
	challengesDenied.WithLabelValues("nonce_mismatch")
	challengesDenied.WithLabelValues("identity_mismatch")
	challengesDenied.WithLabelValues("user_rejected")
	ldapRefreshTotal.WithLabelValues("poll")
	ldapRefreshTotal.WithLabelValues("webhook")
}
