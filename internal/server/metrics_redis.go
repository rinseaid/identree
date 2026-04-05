package server

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
)

var (
	redisPoolTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Subsystem: "redis",
		Name:      "pool_total_connections",
		Help:      "Total number of connections in the Redis pool.",
	})

	redisPoolIdle = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Subsystem: "redis",
		Name:      "pool_idle_connections",
		Help:      "Number of idle connections in the Redis pool.",
	})

	redisPoolActive = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "identree",
		Subsystem: "redis",
		Name:      "pool_active_connections",
		Help:      "Number of active (in-use) connections in the Redis pool.",
	})

	redisCommandDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "identree",
		Subsystem: "redis",
		Name:      "command_duration_seconds",
		Help:      "Latency of Redis commands.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	})
)

// startRedisMetrics starts a goroutine that periodically updates Redis pool
// metrics and adds a command-timing hook to the Redis client. The goroutine
// stops when stopCh is closed.
func startRedisMetrics(client redis.UniversalClient, stopCh <-chan struct{}) {
	// Add timing hook.
	if hookable, ok := client.(interface{ AddHook(redis.Hook) }); ok {
		hookable.AddHook(&redisTimingHook{})
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("redis metrics goroutine panic", "panic", r)
			}
		}()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				updateRedisPoolMetrics(client)
			case <-stopCh:
				return
			}
		}
	}()
}

func updateRedisPoolMetrics(client redis.UniversalClient) {
	// PoolStats is available on *redis.Client and *redis.ClusterClient.
	type poolStatter interface {
		PoolStats() *redis.PoolStats
	}
	if ps, ok := client.(poolStatter); ok {
		stats := ps.PoolStats()
		redisPoolTotal.Set(float64(stats.TotalConns))
		redisPoolIdle.Set(float64(stats.IdleConns))
		redisPoolActive.Set(float64(stats.TotalConns - stats.IdleConns))
	}
}

// redisTimingHook implements redis.Hook to record command latency.
type redisTimingHook struct{}

func (h *redisTimingHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *redisTimingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		start := time.Now()
		err := next(ctx, cmd)
		redisCommandDuration.Observe(time.Since(start).Seconds())
		return err
	}
}

func (h *redisTimingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		start := time.Now()
		err := next(ctx, cmds)
		redisCommandDuration.Observe(time.Since(start).Seconds())
		return err
	}
}
