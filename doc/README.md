# Flogo custom activities
t.b.d.
## Linting
Disable the `trunk` extension when installed.
Use `go-statischeck` (included in the VS Code `Go` extension).
To disable lint errors use the following format: 

`//lint:ignore error-id description`, 

e.g.


`//lint:ignore U1000 it is used, just not in this file`

or 

[install](https://golangci-lint.run/usage/install/) and use `golangci-lint` which uses several linters including `go-staticcheck`.
To disable lint errors with `golangci-lint` use the following format:

e.g.

`//nolint:errcheck,staticcheck`

## Local testing

### identification/jwt
1. Go to specific activity directory and execute:
   ```
   go build
   go test
   ```
   Testing with logging:
   ```
   go test -v
   ```
   For test coverage report:
   ```
   go test -coverprofile=coverage.out
   go tool cover -html=coverage.out -o /workspace/coverage.html
   ```

### References
[TCI Documentation - Using Extensions][1]
[TCI Flogo - building extensions][2]

[1]: https://integration.cloud.tibco.com/docs/index.html#Subsystems/flogo/flogo-all/uploading-extensions2.html?TocPath=TIBCO%2520Flogo%25C2%25AE%2520Apps%257CApp%2520Development%257CUsing%2520Extensions%257C_____0
[2]: https://tibcosoftware.github.io/tci-flogo/building-extensions/
