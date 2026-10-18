package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/managercontract"
)

// Exit codes of `leash manager`.
const (
	ManagerExitSuccess    = 0
	ManagerExitUnresolved = 1
	ManagerExitUsage      = 2
	ManagerExitInternal   = 4
)

// ManagerInspectSchemaVersion versions the `leash manager inspect --json`
// document independently of the CLI build contract.
const ManagerInspectSchemaVersion = 1

// managerInspectTimeout bounds the whole inspect (including a pull).
var managerInspectTimeout = 10 * time.Minute

// ManagerContractRange is the manager-contract range an image advertises.
type ManagerContractRange struct {
	Version       int `json:"version"`
	MinCompatible int `json:"minCompatible"`
}

// ManagerInspectDocument is emitted by `leash manager inspect --json`. Field
// names are additive-only, like the version document.
type ManagerInspectDocument struct {
	SchemaVersion int    `json:"schemaVersion"`
	Ref           string `json:"ref"`
	Source        string `json:"source"`
	Runtime       string `json:"runtime"`
	ImageID       string `json:"imageId"`
	// Digest is the registry manifest digest (sha256:...) of Ref when the
	// engine knows one; empty for an image that was built or loaded locally.
	Digest      string   `json:"digest"`
	RepoDigests []string `json:"repoDigests"`
	Version     string   `json:"version"`
	Revision    string   `json:"revision"`
	// ManagerContract is nil when the image's manager-contract labels are
	// missing or malformed (the CLI refuses such an image; see Reason).
	ManagerContract *ManagerContractRange `json:"managerContract"`
	// ContractVersion, MinCompatibleContract and Capabilities describe the
	// leash binary inside the image in `leash version --json` vocabulary. The
	// integers are null and the array empty for an image that predates those
	// labels; CapabilitiesLabeled tells "advertises none" from "unlabeled".
	ContractVersion       *int     `json:"contractVersion"`
	MinCompatibleContract *int     `json:"minCompatibleContract"`
	Capabilities          []string `json:"capabilities"`
	CapabilitiesLabeled   bool     `json:"capabilitiesLabeled"`
	// PolicyLimits is the image leash's `policyLimits`; null when unlabeled.
	PolicyLimits *managercontract.PolicyLimits `json:"policyLimits"`
	// CompatibleWithThisCLI is the verdict a run of this CLI would reach
	// before provisioning; Reason explains it either way.
	CompatibleWithThisCLI bool   `json:"compatibleWithThisCli"`
	Reason                string `json:"reason"`
}

type managerInspectDeps struct {
	callerDir   func() (string, error)
	newRuntime  func(name string) (Runtime, error)
	lookPath    func(string) (string, error)
	getenv      func(string) string
	diagnostics io.Writer
}

func defaultManagerInspectDeps(stderr io.Writer) managerInspectDeps {
	return managerInspectDeps{
		callerDir:   os.Getwd,
		newRuntime:  newRuntime,
		lookPath:    exec.LookPath,
		getenv:      os.Getenv,
		diagnostics: stderr,
	}
}

// ManagerMain runs `leash manager <subcommand>`. stdout carries only the JSON
// document; every diagnostic, including engine pull progress, goes to stderr.
func ManagerMain(args []string, stdout, stderr io.Writer) int {
	return managerMain(args, stdout, stderr, defaultManagerInspectDeps(stderr))
}

func managerMain(args []string, stdout, stderr io.Writer, deps managerInspectDeps) int {
	if len(args) == 0 || args[0] != "inspect" {
		fmt.Fprintln(stderr, "usage: leash manager inspect [--image <ref>] [--runtime docker|podman] [--pull missing|never] --json")
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
			return ManagerExitSuccess
		}
		return ManagerExitUsage
	}
	fs := flag.NewFlagSet("leash manager inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	image := fs.String("image", "", "manager image to inspect (default: the image a run would use: --leash-image, LEASH_IMAGE, dev image file, embedded default)")
	leashImage := fs.String("leash-image", "", "alias of --image, matching the run flag")
	runtimeName := fs.String("runtime", "", "container engine: docker or podman (default: LEASH_RUNTIME, else the first engine on PATH)")
	pull := fs.String("pull", "missing", "pull the image when it is not local: missing or never")
	asJSON := fs.Bool("json", false, "emit the inspection as JSON (required)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: leash manager inspect [--image <ref>] [--runtime docker|podman] [--pull missing|never] --json")
		fmt.Fprintln(stderr, "\nReports the manager image a container run would use and whether this CLI accepts it.")
		fmt.Fprintln(stderr, "\nflags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ManagerExitSuccess
		}
		return ManagerExitUsage
	}
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, "leash manager inspect: "+format+"\n", a...)
		return code
	}
	if fs.NArg() != 0 {
		return fail(ManagerExitUsage, "unexpected argument %q", fs.Arg(0))
	}
	if !*asJSON {
		return fail(ManagerExitUsage, "--json is required")
	}
	if *pull != "missing" && *pull != "never" {
		return fail(ManagerExitUsage, "--pull must be missing or never, got %q", *pull)
	}
	if *image != "" && *leashImage != "" && strings.TrimSpace(*image) != strings.TrimSpace(*leashImage) {
		return fail(ManagerExitUsage, "conflicting --image and --leash-image values")
	}
	if *image == "" {
		*image = *leashImage
	}

	engine, err := selectManagerEngine(*runtimeName, deps)
	if err != nil {
		return fail(ManagerExitUsage, "%v", err)
	}
	if _, err := deps.lookPath(engine); err != nil {
		return fail(ManagerExitUnresolved, "container engine %q not found on PATH: %v", engine, err)
	}
	rt, err := deps.newRuntime(engine)
	if err != nil {
		return fail(ManagerExitUsage, "%v", err)
	}

	dir, err := deps.callerDir()
	if err != nil {
		return fail(ManagerExitUnresolved, "determine working directory: %v", err)
	}
	ref, source, _, err := resolveManagerImage(dir, *image)
	if err != nil {
		return fail(ManagerExitUnresolved, "%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), managerInspectTimeout)
	defer cancel()
	r := &runner{runtime: rt, diagnostics: deps.diagnostics}
	if *pull == "never" {
		present, err := r.inspectImage(ctx, ref)
		if err != nil {
			return fail(ManagerExitUnresolved, "inspect manager image %q with %s: %s", ref, engine, engineDetail(err))
		}
		if !present {
			return fail(ManagerExitUnresolved, "manager image %q is not in the local %s store and --pull never forbids pulling it", ref, engine)
		}
	} else if err := r.ensureLocalImage(ctx, "manager", ref); err != nil {
		return fail(ManagerExitUnresolved, "%v", err)
	}

	facts, err := r.readManagerImageFacts(ctx, ref)
	if err != nil {
		return fail(ManagerExitUnresolved, "%v", err)
	}
	doc := buildManagerInspectDocument(ref, source, engine, facts)
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fail(ManagerExitInternal, "encode document: %v", err)
	}
	encoded = append(encoded, '\n')
	if n, err := stdout.Write(encoded); err != nil || n != len(encoded) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return fail(ManagerExitInternal, "write document: %v", err)
	}
	return ManagerExitSuccess
}

// selectManagerEngine picks the engine a container run would drive. The native
// runtime has no manager image, so it is refused rather than guessed around.
func selectManagerEngine(flagValue string, deps managerInspectDeps) (string, error) {
	name := strings.TrimSpace(flagValue)
	if name == "" {
		name = strings.TrimSpace(deps.getenv("LEASH_RUNTIME"))
		if name == nativeRuntimeName {
			// LEASH_RUNTIME selects native for runs; the manager question is
			// about the container engines, so fall through to detection.
			name = ""
		}
	}
	if name == "" {
		for _, candidate := range supportedRuntimes {
			if _, err := deps.lookPath(candidate); err == nil {
				return candidate, nil
			}
		}
		return defaultRuntime, nil
	}
	for _, s := range supportedRuntimes {
		if name == s {
			return name, nil
		}
	}
	if name == nativeRuntimeName {
		return "", fmt.Errorf("the native runtime runs no manager image; pass --runtime docker or podman")
	}
	return "", fmt.Errorf("unsupported runtime %q; supported runtimes: %s", name, strings.Join(supportedRuntimes, ", "))
}

type managerImageFacts struct {
	ID          string
	RepoDigests []string
	Labels      map[string]string
}

// engineImage is the part of an engine's image-inspect object leash reads.
// Docker and Podman share these field names in their JSON, but not in their
// Go templates (Docker's .Id is Podman's .ID), so the whole object is
// requested with {{json .}} and decoded here.
type engineImage struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
	Config      struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

const managerFactsFormat = `{{json .}}`

func (r *runner) readManagerImageFacts(ctx context.Context, ref string) (managerImageFacts, error) {
	out, err := r.rt().Output(ctx, "image", "inspect", "--format", managerFactsFormat, ref)
	if err != nil {
		return managerImageFacts{}, fmt.Errorf("inspect manager image %q: %s", ref, engineDetail(err))
	}
	// Output is combined stdout+stderr: skip any engine warning lines and
	// decode the line that holds the document.
	lastErr := errors.New("no document in engine output")
	for _, line := range bytes.Split([]byte(out), []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var image engineImage
		if err := json.Unmarshal(line, &image); err != nil {
			lastErr = err
			continue
		}
		facts := managerImageFacts{ID: image.ID, RepoDigests: image.RepoDigests, Labels: image.Config.Labels}
		if facts.RepoDigests == nil {
			facts.RepoDigests = []string{}
		}
		return facts, nil
	}
	return managerImageFacts{}, fmt.Errorf("inspect manager image %q: unreadable engine output: %v", ref, lastErr)
}

func buildManagerInspectDocument(ref, source, engine string, facts managerImageFacts) ManagerInspectDocument {
	doc := ManagerInspectDocument{
		SchemaVersion: ManagerInspectSchemaVersion,
		Ref:           ref,
		Source:        source,
		Runtime:       engine,
		ImageID:       facts.ID,
		Digest:        manifestDigest(ref, facts.RepoDigests),
		RepoDigests:   facts.RepoDigests,
		Version:       strings.TrimSpace(facts.Labels[managercontract.LabelVersion]),
		Revision:      strings.TrimSpace(facts.Labels[managercontract.LabelRevision]),
		Capabilities:  []string{},
	}

	var problems []string
	if cli, err := managercontract.ParseCLI(facts.Labels); err != nil {
		problems = append(problems, err.Error())
	} else {
		doc.ContractVersion = cli.ContractVersion
		doc.MinCompatibleContract = cli.MinCompatibleContract
		doc.Capabilities = cli.Capabilities
		doc.CapabilitiesLabeled = cli.CapabilitiesPresent
		doc.PolicyLimits = cli.PolicyLimits
	}

	metadata, err := managercontract.Parse(facts.Labels)
	if err != nil {
		doc.Reason = fmt.Sprintf("manager image is unverifiable: %v", err)
		return doc
	}
	doc.ManagerContract = &ManagerContractRange{Version: metadata.ContractVersion, MinCompatible: metadata.MinCompatibleContract}
	expectedRevision := ""
	if source == imageSourceDefault {
		expectedRevision = expectedManagerRevision
	}
	if err := managercontract.Validate(metadata, requiredManagerContract, expectedRevision); err != nil {
		doc.Reason = fmt.Sprintf("manager image is incompatible: %v", err)
		return doc
	}
	doc.CompatibleWithThisCLI = true
	doc.Reason = fmt.Sprintf("manager contract %d is within the image's range %d..%d", requiredManagerContract, metadata.MinCompatibleContract, metadata.ContractVersion)
	if expectedRevision != "" {
		doc.Reason += " and the revision matches this release"
	}
	if len(problems) > 0 {
		// A malformed CLI-description label does not change what a run would
		// do, but the caller must not read the empty fields as authoritative.
		doc.Reason += "; " + strings.Join(problems, "; ")
	}
	return doc
}

// manifestDigest returns the sha256 manifest digest that identifies ref: the
// digest in a by-digest ref, else the repo digest recorded for ref's
// repository, else "" (a locally built or loaded image has none).
func manifestDigest(ref string, repoDigests []string) string {
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		return ref[at+1:]
	}
	repo := refRepository(ref)
	for _, rd := range repoDigests {
		at := strings.LastIndex(rd, "@")
		if at < 0 {
			continue
		}
		if repo != "" && sameRepository(rd[:at], repo) {
			return rd[at+1:]
		}
	}
	return ""
}

// refRepository strips a tag (but not a registry port) from ref.
func refRepository(ref string) string {
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	if colon := strings.LastIndex(ref, ":"); colon > slash {
		ref = ref[:colon]
	}
	return ref
}

// sameRepository compares repositories, tolerating the docker.io/library/
// prefixes engines add to short names.
func sameRepository(a, b string) bool {
	norm := func(s string) string {
		s = strings.TrimPrefix(s, "docker.io/")
		s = strings.TrimPrefix(s, "library/")
		return s
	}
	return norm(a) == norm(b)
}
