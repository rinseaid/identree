# Contributing to identree

## Building

```bash
go build ./...
```

## Testing

```bash
go test ./...
```

## Running locally

```bash
make up
```

This starts the full Docker Compose stack including identree, a test identity provider, and a test SSH host.

## Development session setup

See [CLAUDE.md](CLAUDE.md) for instructions on logging into the test Pocket ID instance and other development workflow details.

## Pull request process

1. Branch from `dev`.
2. Ensure `go test ./...` passes locally.
3. CI must pass before merge.
4. Keep commits focused -- one logical change per commit.
