.PHONY: e2e e2e-keep

# Hermetic end-to-end suite (privileged Docker; see e2e/compose.yaml).
e2e:
	go test -tags e2e -count=1 -v -timeout 30m ./e2e/

# Same, but leave the environment running for debugging.
e2e-keep:
	E2E_KEEP=1 go test -tags e2e -count=1 -v -timeout 30m ./e2e/
