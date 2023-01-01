# Test

## Dependencies

Run `go mod tidy -e` to keep things up to date.

To test the dependencies:

```sh
go list -u -m all # view available minor and patch upgrades for all direct and indirect dependencies
go get -u ./... # upgrades to the latest or minor patch release
go get -t -u ./... # upgrade test dependencies
go test all # run the following command to test that packages are working correctly after an upgrade
```

## Security

```sh
go install github.com/securego/gosec/v2/cmd/gosec@latest
# machine readable
# gosec -conf test/.gosec.config.json -track-suppressions -fmt=json -out=test/results.json -stdout ./...
gosec -conf test/.gosec.config.json -track-suppressions ./...
```

