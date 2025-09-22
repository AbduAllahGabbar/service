package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	ZitadelBaseURL string
	ZitadelToken   string

	RedisAddr     string
	RedisPassword string
	RedisDB       int

	CacheTTL time.Duration
	Port     string

	RequestTimeout time.Duration
	RetryMax       int
	CBInterval     time.Duration
	CBTimeout      time.Duration
	CBMaxRequests  uint32

	ProjectID      string
	ProjectGrantID string
}

func LoadConfig() *Config {
	ttl, err := time.ParseDuration(getEnv("CACHE_TTL", "300s"))
	if err != nil {
		ttl = 5 * time.Minute
	}
	reqTimeout, err := time.ParseDuration(getEnv("REQUEST_TIMEOUT", "8s"))
	if err != nil {
		reqTimeout = 8 * time.Second
	}
	cbInt, err := time.ParseDuration(getEnv("CB_INTERVAL", "60s"))
	if err != nil {
		cbInt = 60 * time.Second
	}
	cbTimeout, err := time.ParseDuration(getEnv("CB_TIMEOUT", "30s"))
	if err != nil {
		cbTimeout = 30 * time.Second
	}

	retryMax := 3
	if v := os.Getenv("RETRY_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			retryMax = n
		}
	}

	redisDB := 0
	if v := os.Getenv("REDIS_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			redisDB = n
		}
	}

	return &Config{
		ZitadelBaseURL: getEnv("ZITADEL_DOMAIN", "http://localhost:8080"),
		ZitadelToken:   os.Getenv("SERVICE_ACCOUNT_TOKEN"),
		RedisAddr:      getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:  os.Getenv("REDIS_PASSWORD"),
		RedisDB:        redisDB,
		CacheTTL:       ttl,
		Port:           getEnv("PORT", "3000"),
		RequestTimeout: reqTimeout,
		RetryMax:       retryMax,
		CBInterval:     cbInt,
		CBTimeout:      cbTimeout,
		CBMaxRequests:  5,
		ProjectID:      os.Getenv("PROJECT_ID"),
		ProjectGrantID: os.Getenv("PROJECT_GRANT_ID"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
