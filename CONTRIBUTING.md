# Contributing

Thanks for helping. Bug reports, fixes and new filters for the existing tools are all
welcome.

## Before you start

For anything bigger than a small fix, open an issue first so we can agree on the
approach. New tools in particular need a matching backend endpoint, so we'll want to
talk it through.

Security problems go through [SECURITY.md](SECURITY.md), not a public issue.

## Making a change

1. Fork the repository and create a branch.
2. Make the change with tests. Every tool and filter has unit tests against a fake
   backend under `internal/tools`; follow the same pattern.
3. Run the checks CI runs:

   ```bash
   go vet ./...
   go test -race ./...
   ```

4. Open a pull request that says what changed and why.

The server must stay read-only. A pull request that adds a tool able to change data in
an ARMO account won't be merged.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
