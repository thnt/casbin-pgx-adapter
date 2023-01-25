# PGX Adapter

[![Go](https://github.com/thnt/casbin-pgx-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/thnt/casbin-pgx-adapter/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/thnt/casbin-pgx-adapter/badge.svg?branch=master)](https://coveralls.io/github/thnt/casbin-pgx-adapter?branch=master)

Pgx adapter for casbin based on offical [go-pg](https://github.com/casbin/casbin-pg-adapter) adapter.

Differences:

- Use pgx instead of go-pg
- Use xxh3 instead of meow hash to generate policy ID
