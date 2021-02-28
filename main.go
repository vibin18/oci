package main

import (
	"context"
	"encoding/json"
"fmt"
	"github.com/containers/image/transports/alltransports"
	"io"
"os"
"strings"
"text/tabwriter"
"text/template"
	"time"

	"github.com/containers/common/pkg/report"
"github.com/containers/common/pkg/retry"
"github.com/containers/image/v5/docker"
"github.com/containers/image/v5/image"
"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/pkg/"
	"github.com/containers/skopeo/version"
// "github.com/containers/image/v5/transports"
"github.com/containers/image/v5/types"
"github.com/containers/skopeo/cmd/skopeo/inspect"
v1 "github.com/opencontainers/image-spec/specs-go/v1"
"github.com/pkg/errors"
"github.com/sirupsen/logrus"
//"github.com/spf13/cobra"
)

//##############################################################################
type optionalBool struct {
	present bool
	value   bool
}

type optionalString struct {
	present bool
	value   string
}
type globalOptions struct {
	debug              bool          // Enable debug output
	tlsVerify          optionalBool  // Require HTTPS and verify certificates (for docker: and docker-daemon:)
	policyPath         string        // Path to a signature verification policy file
	insecurePolicy     bool          // Use an "allow everything" signature verification policy
	registriesDirPath  string        // Path to a "registries.d" registry configuration directory
	overrideArch       string        // Architecture to use for choosing images, instead of the runtime one
	overrideOS         string        // OS to use for choosing images, instead of the runtime one
	overrideVariant    string        // Architecture variant to use for choosing images, instead of the runtime one
	commandTimeout     time.Duration // Timeout for the command execution
	registriesConfPath string        // Path to the "registries.conf" file
	tmpDir             string        // Path to use for big temporary files
}

// sharedImageOptions collects CLI flags which are image-related, but do not change across images.
// This really should be a part of globalOptions, but that would break existing users of (skopeo copy --authfile=).
type sharedImageOptions struct {
	authFilePath string // Path to a */containers/auth.json
}

// dockerImageOptions collects CLI flags specific to the "docker" transport, which are
// the same across subcommands, but may be different for each image
// (e.g. may differ between the source and destination of a copy)
type dockerImageOptions struct {
	global         *globalOptions      // May be shared across several imageOptions instances.
	shared         *sharedImageOptions // May be shared across several imageOptions instances.
	authFilePath   optionalString      // Path to a */containers/auth.json (prefixed version to override shared image option).
	credsOption    optionalString      // username[:password] for accessing a registry
	registryToken  optionalString      // token to be used directly as a Bearer token when accessing the registry
	dockerCertPath string              // A directory using Docker-like *.{crt,cert,key} files for connecting to a registry or a daemon
	tlsVerify      optionalBool        // Require HTTPS and verify certificates (for docker: and docker-daemon:)
	noCreds        bool                // Access the registry anonymously
}

// imageOptions collects CLI flags which are the same across subcommands, but may be different for each image
// (e.g. may differ between the source and destination of a copy)
type imageOptions struct {
	dockerImageOptions
	sharedBlobDir    string // A directory to use for OCI blobs, shared across repositories
	dockerDaemonHost string // docker-daemon: host to connect to
}
//##############################################################



type inspectOptions struct {
	global    *globalOptions
	image     *imageOptions
	retryOpts *retry.RetryOptions
	format    string
	raw       bool // Output the raw manifest instead of parsing information about the image
	config    bool // Output the raw config blob instead of parsing information about the image
}

//func inspectCmd(global *globalOptions) *cobra.Command {
//	sharedFlags, sharedOpts := sharedImageFlags()
//	imageFlags, imageOpts := imageFlags(global, sharedOpts, "", "")
//	retryFlags, retryOpts := retryFlags()
//	opts := inspectOptions{
//		global:    global,
//		image:     imageOpts,
//		retryOpts: retryOpts,
//	}
//	cmd := &cobra.Command{
//		Use:   "inspect [command options] IMAGE-NAME",
//		Short: "Inspect image IMAGE-NAME",
//		Long: fmt.Sprintf(`Return low-level information about "IMAGE-NAME" in a registry/transport
//Supported transports:
//%s
//
//See skopeo(1) section "IMAGE NAMES" for the expected format
//`, strings.Join(transports.ListNames(), ", ")),
//		RunE: commandAction(opts.run),
//		Example: `skopeo inspect docker://registry.fedoraproject.org/fedora
//  skopeo inspect --config docker://docker.io/alpine
//  skopeo inspect  --format "Name: {{.Name}} Digest: {{.Digest}}" docker://registry.access.redhat.com/ubi8`,
//	}
//	adjustUsage(cmd)
//	flags := cmd.Flags()
//	flags.BoolVar(&opts.raw, "raw", false, "output raw manifest or configuration")
//	flags.BoolVar(&opts.config, "config", false, "output configuration")
//	flags.StringVarP(&opts.format, "format", "f", "", "Format the output to a Go template")
//	flags.AddFlagSet(&sharedFlags)
//	flags.AddFlagSet(&imageFlags)
//	flags.AddFlagSet(&retryFlags)
//	return cmd
//}

// commandTimeoutContext returns a context.Context and a cancellation callback based on opts.
// The caller should usually "defer cancel()" immediately after calling this.
func (opts *globalOptions) commandTimeoutContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	var cancel context.CancelFunc = func() {}
	if opts.commandTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.commandTimeout)
	}
	return ctx, cancel
}

func reexecIfNecessaryForImages(inputImageNames ...string) error {
	return nil
}

func getDockerAuth(creds string) (*types.DockerAuthConfig, error) {
	username, password, err := parseCreds(creds)
	if err != nil {
		return nil, err
	}
	return &types.DockerAuthConfig{
		Username: username,
		Password: password,
	}, nil
}

func parseCreds(creds string) (string, string, error) {
	if creds == "" {
		return "", "", errors.New("credentials can't be empty")
	}
	up := strings.SplitN(creds, ":", 2)
	if len(up) == 1 {
		return up[0], "", nil
	}
	if up[0] == "" {
		return "", "", errors.New("username can't be empty")
	}
	return up[0], up[1], nil
}


// newSystemContext returns a *types.SystemContext corresponding to opts.
// It is guaranteed to return a fresh instance, so it is safe to make additional updates to it.
func (opts *imageOptions) newSystemContext() (*types.SystemContext, error) {
	// *types.SystemContext instance from globalOptions
	//  imageOptions option overrides the instance if both are present.
	ctx := opts.global.newSystemContext()
	ctx.DockerCertPath = opts.dockerCertPath
	ctx.OCISharedBlobDirPath = opts.sharedBlobDir
	ctx.AuthFilePath = opts.shared.authFilePath
	ctx.DockerDaemonHost = opts.dockerDaemonHost
	ctx.DockerDaemonCertPath = opts.dockerCertPath
	if opts.dockerImageOptions.authFilePath.present {
		ctx.AuthFilePath = opts.dockerImageOptions.authFilePath.value
	}
	if opts.tlsVerify.present {
		ctx.DockerDaemonInsecureSkipTLSVerify = !opts.tlsVerify.value
	}
	if opts.tlsVerify.present {
		ctx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(!opts.tlsVerify.value)
	}
	if opts.credsOption.present && opts.noCreds {
		return nil, errors.New("creds and no-creds cannot be specified at the same time")
	}
	if opts.credsOption.present {
		var err error
		ctx.DockerAuthConfig, err = getDockerAuth(opts.credsOption.value)
		if err != nil {
			return nil, err
		}
	}
	if opts.registryToken.present {
		ctx.DockerBearerRegistryToken = opts.registryToken.value
	}
	if opts.noCreds {
		ctx.DockerAuthConfig = &types.DockerAuthConfig{}
	}

	return ctx, nil
}

var defaultUserAgent = "skopeo/" + version.Version

func (opts *globalOptions) newSystemContext() *types.SystemContext {
	ctx := &types.SystemContext{
		RegistriesDirPath:        opts.registriesDirPath,
		ArchitectureChoice:       opts.overrideArch,
		OSChoice:                 opts.overrideOS,
		VariantChoice:            opts.overrideVariant,
		SystemRegistriesConfPath: opts.registriesConfPath,
		BigFilesTemporaryDir:     opts.tmpDir,
		DockerRegistryUserAgent:  defaultUserAgent,
	}
	// DEPRECATED: We support this for backward compatibility, but override it if a per-image flag is provided.
	if opts.tlsVerify.present {
		ctx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(!opts.tlsVerify.value)
	}
	return ctx
}

//// newSystemContext returns a *types.SystemContext corresponding to opts.
//// It is guaranteed to return a fresh instance, so it is safe to make additional updates to it.
//func (opts *imageDestOptions) newSystemContext() (*types.SystemContext, error) {
//	ctx, err := opts.imageOptions.newSystemContext()
//	if err != nil {
//		return nil, err
//	}
//
//	ctx.DirForceCompress = opts.dirForceCompression
//	ctx.OCIAcceptUncompressedLayers = opts.ociAcceptUncompressedLayers
//	if opts.compressionFormat != "" {
//		cf, err := compression.AlgorithmByName(opts.compressionFormat)
//		if err != nil {
//			return nil, err
//		}
//		ctx.CompressionFormat = &cf
//	}
//	if opts.compressionLevel.present {
//		ctx.CompressionLevel = &opts.compressionLevel.value
//	}
//	return ctx, err
//}



// parseImageSource converts image URL-like string to an ImageSource.
// The caller must call .Close() on the returned ImageSource.
func parseImageSource(ctx context.Context, opts *imageOptions, name string) (types.ImageSource, error) {
	ref, err := alltransports.ParseImageName(name)
	if err != nil {
		return nil, err
	}
	sys, err := opts.newSystemContext()
	if err != nil {
		return nil, err
	}
	return ref.NewImageSource(ctx, sys)
}

func (opts *inspectOptions) run(args []string, stdout io.Writer) (retErr error) {
	var (
		rawManifest []byte
		src         types.ImageSource
		imgInspect  *types.ImageInspectInfo
		data        []interface{}
	)
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 1 {
		return errors.New("Exactly one argument expected")
	}
	if opts.raw && opts.format != "" {
		return errors.New("raw output does not support format option")
	}
	imageName := args[0]

	if err := reexecIfNecessaryForImages(imageName); err != nil {
		return err
	}

	sys, err := opts.image.newSystemContext()
	if err != nil {
		return err
	}

	if err := retry.RetryIfNecessary(ctx, func() error {
		src, err = parseImageSource(ctx, opts.image, imageName)
		return err
	}, opts.retryOpts); err != nil {
		return errors.Wrapf(err, "Error parsing image name %q", imageName)
	}

	defer func() {
		if err := src.Close(); err != nil {
			retErr = errors.Wrapf(retErr, fmt.Sprintf("(could not close image: %v) ", err))
		}
	}()

	if err := retry.RetryIfNecessary(ctx, func() error {
		rawManifest, _, err = src.GetManifest(ctx, nil)
		return err
	}, opts.retryOpts); err != nil {
		return errors.Wrapf(err, "Error retrieving manifest for image")
	}

	if opts.raw && !opts.config {
		_, err := stdout.Write(rawManifest)
		if err != nil {
			return fmt.Errorf("Error writing manifest to standard output: %v", err)
		}

		return nil
	}

	img, err := image.FromUnparsedImage(ctx, sys, image.UnparsedInstance(src, nil))
	if err != nil {
		return errors.Wrapf(err, "Error parsing manifest for image")
	}

	if opts.config && opts.raw {
		var configBlob []byte
		if err := retry.RetryIfNecessary(ctx, func() error {
			configBlob, err = img.ConfigBlob(ctx)
			return err
		}, opts.retryOpts); err != nil {
			return errors.Wrapf(err, "Error reading configuration blob")
		}
		_, err = stdout.Write(configBlob)
		if err != nil {
			return errors.Wrapf(err, "Error writing configuration blob to standard output")
		}
		return nil
	} else if opts.config {
		var config *v1.Image
		if err := retry.RetryIfNecessary(ctx, func() error {
			config, err = img.OCIConfig(ctx)
			return err
		}, opts.retryOpts); err != nil {
			return errors.Wrapf(err, "Error reading OCI-formatted configuration data")
		}
		if report.IsJSON(opts.format) || opts.format == "" {
			var out []byte
			out, err = json.MarshalIndent(config, "", "    ")
			if err == nil {
				fmt.Fprintf(stdout, "%s\n", string(out))
			}
		} else {
			row := "{{range . }}" + report.NormalizeFormat(opts.format) + "{{end}}"
			data = append(data, config)
			err = printTmpl(row, data)
		}
		if err != nil {
			return errors.Wrapf(err, "Error writing OCI-formatted configuration data to standard output")
		}
		return nil
	}

	if err := retry.RetryIfNecessary(ctx, func() error {
		imgInspect, err = img.Inspect(ctx)
		return err
	}, opts.retryOpts); err != nil {
		return err
	}

	outputData := inspect.Output{
		Name: "", // Set below if DockerReference() is known
		Tag:  imgInspect.Tag,
		// Digest is set below.
		RepoTags:      []string{}, // Possibly overridden for docker.Transport.
		Created:       imgInspect.Created,
		DockerVersion: imgInspect.DockerVersion,
		Labels:        imgInspect.Labels,
		Architecture:  imgInspect.Architecture,
		Os:            imgInspect.Os,
		Layers:        imgInspect.Layers,
		Env:           imgInspect.Env,
	}
	outputData.Digest, err = manifest.Digest(rawManifest)
	if err != nil {
		return errors.Wrapf(err, "Error computing manifest digest")
	}
	if dockerRef := img.Reference().DockerReference(); dockerRef != nil {
		outputData.Name = dockerRef.Name()
	}
	if img.Reference().Transport() == docker.Transport {
		sys, err := opts.image.newSystemContext()
		if err != nil {
			return err
		}
		outputData.RepoTags, err = docker.GetRepositoryTags(ctx, sys, img.Reference())
		if err != nil {
			// some registries may decide to block the "list all tags" endpoint
			// gracefully allow the inspect to continue in this case. Currently
			// the IBM Bluemix container registry has this restriction.
			// In addition, AWS ECR rejects it with 403 (Forbidden) if the "ecr:ListImages"
			// action is not allowed.
			if !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "403") {
				return errors.Wrapf(err, "Error determining repository tags")
			}
			logrus.Warnf("Registry disallows tag list retrieval; skipping")
		}
	}
	if report.IsJSON(opts.format) || opts.format == "" {
		out, err := json.MarshalIndent(outputData, "", "    ")
		if err == nil {
			fmt.Fprintf(stdout, "%s\n", string(out))
		}
		return err
	}
	row := "{{range . }}" + report.NormalizeFormat(opts.format) + "{{end}}"
	data = append(data, outputData)
	return printTmpl(row, data)
}

func inspectNormalize(row string) string {
	r := strings.NewReplacer(
		".ImageID", ".Image",
	)
	return r.Replace(row)
}

func printTmpl(row string, data []interface{}) error {
	t, err := template.New("skopeo inspect").Parse(row)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 8, 2, 2, ' ', 0)
	return t.Execute(w, data)
}
