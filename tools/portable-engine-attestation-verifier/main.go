// portable-engine-attestation-verifier verifies one retained GitHub-private
// Sigstore bundle entirely offline. It is intentionally narrower than a
// general Sigstore or GitHub attestation client.
//
// @ref LLP 0035#transport-and-distribution-provenance — authenticate detached
// publisher provenance before any archive parsing or extraction.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

const usageText = `usage: portable-engine-attestation-verifier \
  --bundle PATH --artifact PATH --expectations PATH

The helper performs no network requests. It accepts exactly one retained
Sigstore v0.3 JSON bundle, the artifact bytes that bundle must name, and a
closed expectations document containing every admitted GitHub claim.
Canonical verification JSON is written to stdout only on success.`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "portable-engine-attestation-verifier: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("portable-engine-attestation-verifier", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var bundlePath string
	var artifactPath string
	var expectationsPath string
	flags.StringVar(&bundlePath, "bundle", "", "path to one retained Sigstore v0.3 bundle")
	flags.StringVar(&artifactPath, "artifact", "", "path to the exact artifact bytes")
	flags.StringVar(&expectationsPath, "expectations", "", "path to the closed expected-claims document")
	flags.Usage = func() { fmt.Fprintln(flags.Output(), usageText) }
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if bundlePath == "" || artifactPath == "" || expectationsPath == "" {
		flags.Usage()
		return fmt.Errorf("--bundle, --artifact, and --expectations are all required")
	}

	result, err := verifyFiles(bundlePath, artifactPath, expectationsPath)
	if err != nil {
		return err
	}
	if _, err := stdout.Write(append(result, '\n')); err != nil {
		return fmt.Errorf("write canonical result: %w", err)
	}
	return nil
}
