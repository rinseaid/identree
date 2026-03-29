COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo dev)
VERSION ?= dev

export COMMIT
export VERSION

.PHONY: up down build logs ps

up:
	docker compose -f test/docker-compose.yml up --build -d

down:
	docker compose -f test/docker-compose.yml down

build:
	docker compose -f test/docker-compose.yml build

logs:
	docker compose -f test/docker-compose.yml logs -f identree

ps:
	docker compose -f test/docker-compose.yml ps
