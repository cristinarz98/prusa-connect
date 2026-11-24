package config_test

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/prusa3d/prusa-connect/internal/app/config"
	"github.com/prusa3d/prusa-connect/internal/app/resource"
)

// manifestPath is the ConfigMap the published Kubernetes manifest set carries.
// The cluster half of that set cannot be exercised without a cluster; the file
// it hands the process can be, and this is where it is read by the same loader
// the server runs.
const manifestPath = "deploy/kubernetes/configmap.yaml"

// manifestKey is the key inside it that becomes the file.
const manifestKey = "config.yaml"

// deploymentPath is the Deployment that mounts the ConfigMap and the volumes
// the core writes to.
const deploymentPath = "deploy/kubernetes/deployment.yaml"

// TestTheKubernetesConfigMapIsAConfigurationThisLoaderAccepts runs the shipped
// manifest's configuration through Load and Validate. The core decodes its own
// block with unknown keys refused, so a key renamed in Go and left behind in the
// manifest stops a tenant at startup, and nothing else in the tree would see it.
func TestTheKubernetesConfigMapIsAConfigurationThisLoaderAccepts(t *testing.T) {
	t.Parallel()

	path := manifestAsFile(t)

	core, err := config.Load(path)
	require.NoError(t, err, "the manifest's %s is not a configuration this loader reads", manifestKey)
	require.NoError(t, core.Validate(), "the manifest's %s does not validate", manifestKey)
}

// TestTheKubernetesConfigMapWritesOnlyWhereAVolumeIsMounted holds the failure
// that stops a tenant under a read-only root filesystem. Every write path
// derives from the directory holding the configuration file when its key is
// unset, and in this deployment that directory is the ConfigMap mount, which is
// read-only. The core then stops at startup with `mkdir config/config.d:
// read-only file system`, or an extension install fails writing beside the
// file.
//
// Each path is resolved by the loader, as the pod would see it, and then held
// to sitting under a volume the Deployment mounts writable.
func TestTheKubernetesConfigMapWritesOnlyWhereAVolumeIsMounted(t *testing.T) {
	t.Parallel()

	path := manifestAsFile(t)

	core, err := config.Load(path)
	require.NoError(t, err)

	pod := serverContainer(t)
	file := pod.configFile(t)

	for key, written := range writePaths(core) {
		inPod := asInThePod(written, filepath.Dir(path), filepath.Dir(file))

		require.True(t, strings.HasPrefix(inPod, "/"),
			"%s is %q. A relative path resolves from the container's working directory, "+
				"and a Deployment mounts its volumes at absolute paths", key, written)

		require.True(t, pod.writableMountCovers(inPod),
			"%s resolves to %q in the pod, and %s mounts no writable volume over it. "+
				"The root filesystem and the ConfigMap mount are both read-only, so the "+
				"core cannot write there", key, inPod, deploymentPath)
	}
}

// TestTheKubernetesConfigMapDeclaresAResourceThatLoads reads the same file
// through the resource loader. A declaration that fails there is not refused at
// startup: it is dropped into Failures, and the instance simply never runs.
func TestTheKubernetesConfigMapDeclaresAResourceThatLoads(t *testing.T) {
	t.Parallel()

	document, err := resource.Load(resource.Paths{File: manifestAsFile(t)})
	require.NoError(t, err)
	require.Empty(t, document.Failures, "the manifest declares a resource that will not load")
	require.NotEmpty(t, document.Instances,
		"the manifest declares no resource instance, so this gate compares nothing")
}

// TestAnUnsetWritePathLandsBesideTheConfigurationFile is the positive control
// for the check above. It proves the assertion measures something: with the
// keys left out, every write path derives into the directory the file sits in,
// which in the Deployment is the read-only mount.
func TestAnUnsetWritePathLandsBesideTheConfigurationFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	require.NoError(t, os.WriteFile(path, []byte("core:\n  principal: operator\n"), 0o600))

	core, err := config.Load(path)
	require.NoError(t, err)

	for key, written := range writePaths(core) {
		require.Equal(t, filepath.ToSlash(dir), filepath.ToSlash(filepath.Dir(filepath.Dir(written))),
			"an unset %s no longer derives from the configuration file's directory, so the "+
				"check that the manifest sets it is measuring nothing", key)
	}
}

// writePaths is every path the core writes that the loader resolves, keyed by
// the configuration key that moves it. A path added to the loader and left
// unset in the manifest lands beside the file, so it belongs here.
func writePaths(core config.Core) map[string]string {
	paths := map[string]string{
		"core.overlay":        core.Overlay,
		"core.modules":        core.Modules,
		"core.authz.database": core.Authz.Database,
	}

	// Only with a local account store, the one case the loader fills it.
	if core.Auth.Accounts != "" {
		paths["core.auth.accounts"] = core.Auth.Accounts
	}

	return paths
}

// asInThePod is a path the loader resolved against the test's copy of the file,
// moved to where the same path lands when the file sits where the Deployment
// mounts it. A path the manifest sets outright is returned as it is.
func asInThePod(resolved, testDir, podDir string) string {
	slashed := filepath.ToSlash(resolved)
	from := filepath.ToSlash(testDir)

	if slashed == from || strings.HasPrefix(slashed, from+"/") {
		return path.Join(podDir, strings.TrimPrefix(slashed, from))
	}

	return slashed
}

// podContainer is the part of the Deployment's one container these tests read.
type podContainer struct {
	Args         []string `yaml:"args"`
	VolumeMounts []struct {
		MountPath string `yaml:"mountPath"`
		ReadOnly  bool   `yaml:"readOnly"`
	} `yaml:"volumeMounts"`
}

// serverContainer is the one container the shipped Deployment runs.
func serverContainer(t *testing.T) podContainer {
	t.Helper()

	var deployment struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []podContainer `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}

	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(deploymentPath)))
	require.NoError(t, err, "reading %s", deploymentPath)
	require.NoError(t, yaml.Unmarshal(content, &deployment), "%s does not parse as yaml", deploymentPath)

	containers := deployment.Spec.Template.Spec.Containers
	require.Len(t, containers, 1, "%s runs one process, in one container", deploymentPath)
	require.NotEmpty(t, containers[0].VolumeMounts,
		"%s mounts nothing, so this gate compares nothing", deploymentPath)

	return containers[0]
}

// configFile is the file the container passes to -config.
func (c podContainer) configFile(t *testing.T) string {
	t.Helper()

	for i, arg := range c.Args {
		if arg == "-config" && i+1 < len(c.Args) {
			return c.Args[i+1]
		}

		if value, found := strings.CutPrefix(arg, "-config="); found {
			return value
		}
	}

	require.FailNow(t, "the container passes no -config", "%s", deploymentPath)

	return ""
}

// writableMountCovers reports whether a writable mount sits at or above a path.
func (c podContainer) writableMountCovers(written string) bool {
	for _, mount := range c.VolumeMounts {
		if mount.ReadOnly {
			continue
		}

		root := strings.TrimSuffix(mount.MountPath, "/")
		if written == root || strings.HasPrefix(written, root+"/") {
			return true
		}
	}

	return false
}

// manifestAsFile is the manifest's configuration written to a file, which is the
// only shape the loader reads. It fails the run when the key is absent, so a
// renamed key cannot leave these tests passing over an empty string.
func manifestAsFile(t *testing.T) string {
	t.Helper()

	var manifest struct {
		Data map[string]string `yaml:"data"`
	}

	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(manifestPath)))
	require.NoError(t, err, "reading %s", manifestPath)
	require.NoError(t, yaml.Unmarshal(content, &manifest), "%s does not parse as yaml", manifestPath)

	body := manifest.Data[manifestKey]
	require.NotEmpty(t, body, "%s carries no %s, so this gate reads nothing", manifestPath, manifestKey)

	path := filepath.Join(t.TempDir(), manifestKey)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	return path
}

// repositoryRoot is the directory holding go.mod, found by walking up from the
// package under test.
func repositoryRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "no go.mod above the working directory")

		dir = parent
	}
}
