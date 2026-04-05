package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/rinseaid/identree/internal/config"
)

// newRedisClient creates a redis.UniversalClient from the server config.
// Supports standalone, Sentinel, and Cluster topologies.
func newRedisClient(cfg *config.ServerConfig) (redis.UniversalClient, error) {
	var tlsCfg *tls.Config
	if cfg.RedisTLS {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.RedisTLSCACert != "" {
			caCert, err := os.ReadFile(cfg.RedisTLSCACert)
			if err != nil {
				return nil, fmt.Errorf("reading Redis TLS CA cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse Redis TLS CA cert from %s", cfg.RedisTLSCACert)
			}
			tlsCfg.RootCAs = pool
		}
	}

	// Cluster mode.
	if len(cfg.RedisClusterAddrs) > 0 {
		client := redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:        cfg.RedisClusterAddrs,
			Password:     cfg.RedisPassword,
			PoolSize:     cfg.RedisPoolSize,
			DialTimeout:  cfg.RedisDialTimeout,
			ReadTimeout:  cfg.RedisReadTimeout,
			WriteTimeout: cfg.RedisWriteTimeout,
			TLSConfig:    tlsCfg,
		})
		if err := client.Ping(context.Background()).Err(); err != nil {
			client.Close()
			return nil, fmt.Errorf("redis cluster ping: %w", err)
		}
		return client, nil
	}

	// Sentinel mode.
	if cfg.RedisSentinelMaster != "" {
		client := redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    cfg.RedisSentinelMaster,
			SentinelAddrs: cfg.RedisSentinelAddrs,
			Password:      cfg.RedisPassword,
			DB:            cfg.RedisDB,
			PoolSize:      cfg.RedisPoolSize,
			DialTimeout:   cfg.RedisDialTimeout,
			ReadTimeout:   cfg.RedisReadTimeout,
			WriteTimeout:  cfg.RedisWriteTimeout,
			TLSConfig:     tlsCfg,
		})
		if err := client.Ping(context.Background()).Err(); err != nil {
			client.Close()
			return nil, fmt.Errorf("redis sentinel ping: %w", err)
		}
		return client, nil
	}

	// Standalone mode from URL.
	opts := &redis.Options{
		PoolSize:     cfg.RedisPoolSize,
		DialTimeout:  cfg.RedisDialTimeout,
		ReadTimeout:  cfg.RedisReadTimeout,
		WriteTimeout: cfg.RedisWriteTimeout,
		TLSConfig:    tlsCfg,
	}

	if cfg.RedisURL != "" {
		u, err := url.Parse(cfg.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("parsing IDENTREE_REDIS_URL: %w", err)
		}
		opts.Addr = u.Host
		if u.User != nil {
			opts.Username = u.User.Username()
			if pw, ok := u.User.Password(); ok {
				opts.Password = pw
			}
		}
		// Override password from config if set explicitly.
		if cfg.RedisPassword != "" {
			opts.Password = cfg.RedisPassword
		}
		if u.Path != "" && u.Path != "/" {
			db, err := strconv.Atoi(u.Path[1:])
			if err == nil {
				opts.DB = db
			}
		}
		// Use TLS for rediss:// scheme.
		if u.Scheme == "rediss" && opts.TLSConfig == nil {
			opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
	}

	// Allow explicit DB override.
	if cfg.RedisDB != 0 {
		opts.DB = cfg.RedisDB
	}

	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return client, nil
}
