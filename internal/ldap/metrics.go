package ldap

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
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
	ldapRefreshTotal.WithLabelValues("poll")
	ldapRefreshTotal.WithLabelValues("webhook")
	ldapQueryTotal.WithLabelValues("people")
	ldapQueryTotal.WithLabelValues("groups")
	ldapQueryTotal.WithLabelValues("sudoers")
	ldapQueryTotal.WithLabelValues("root")
}
