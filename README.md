# GoBalance

GoBalance is a rewrite of [onionbalance](https://onionbalance.readthedocs.io) written in Golang.

To generate a config.toml file `./gobalance -g`

### Pros

- No need to install python on the server
- Can be used as a library in a go app

# Compiling

- `go mod vendor`
- `go build -o gobalance main.go`

