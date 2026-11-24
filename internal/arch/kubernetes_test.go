package arch_test

import (
	"path"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The published manifest set. A cluster is what would run it, and there is
// none here, so these gates hold every claim the files make about each other
// and about the image.
const (
	deploymentPath  = "deploy/kubernetes/deployment.yaml"
	kubeServicePath = "deploy/kubernetes/service.yaml"
	configMapPath   = "deploy/kubernetes/configmap.yaml"
	probesPath      = "scripts/check-container-probes.sh"
)

// hardening pairs a Kubernetes setting with the compose setting that means the
// same thing. The image is hardened in `docker compose up` and has to be
// hardened the same way on a cluster, and the two files spell every one of
// these differently.
var hardening = []struct { //nolint:gochecknoglobals // the pairing table.
	kubernetes string
	compose    string
}{
	{kubernetes: "readOnlyRootFilesystem", compose: "read_only"},
	{kubernetes: "allowPrivilegeEscalation", compose: "no-new-privileges"},
	{kubernetes: "drop", compose: "cap_drop"},
}

// TestTheDeploymentRunsTheCoreAgainstTheConfigMapItMounts holds the two
// mistakes that produce a running pod serving the wrong thing.
//
// The image's entry point is the binary, and the binary also answers to
// `serve`, which reaches the retired server and 404s on every path the probes
// read. So the manifest names the server it runs rather than leaving a reader
// of it to know what the binary does with no word at all. And the core derives
// both of its write paths from the directory holding its configuration file, so
// -config has to name the file inside the ConfigMap mount rather than a path
// that does not exist.
func TestTheDeploymentRunsTheCoreAgainstTheConfigMapItMounts(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	core, _ := subcommands(t, root)
	container := serverContainer(t, root)

	if len(container.Args) == 0 || container.Args[0] != core {
		t.Fatalf("%s runs %q, and the core is reached by %q.\n"+
			"The entry point is the binary, which also answers to the retired server's own word.",
			deploymentPath, strings.Join(container.Args, " "), core)
	}

	file := argumentValue(container.Args, "-config")
	if file == "" {
		t.Fatalf("%s passes no -config. The default is config/config.yaml relative to the "+
			"image's working directory, and nothing is mounted there.", deploymentPath)
	}

	mount := mountNamed(t, container, configVolumeName(t, root))
	if !strings.HasPrefix(file, mount.MountPath+"/") {
		t.Errorf("%s reads %s and mounts the ConfigMap at %s.\n"+
			"The core would find no file there and start on defaults, so every key an "+
			"operator set in the ConfigMap would be ignored in silence.",
			deploymentPath, file, mount.MountPath)
	}

	if mount.SubPath != "" {
		t.Errorf("%s mounts the ConfigMap with subPath %q.\n"+
			"Kubernetes documents subPath as the one mount mode that never receives an "+
			"update, and the whole directory is mountable here because the writable path "+
			"is somewhere else.", deploymentPath, mount.SubPath)
	}

	if !mount.ReadOnly {
		t.Errorf("%s mounts the ConfigMap writable. The operator's file is read and never "+
			"written, and a writable mount invites an edit the next rollout discards.",
			deploymentPath)
	}
}

// TestEveryPathTheDeploymentWritesHasAVolumeUnderIt is the failure the read-only
// root filesystem produces. The core creates the directory for the
// authorization graph at startup, and stops with `mkdir config/config.d:
// read-only file system` when nothing is mounted over it. An extension install
// writes under core.modules and fails the same way.
func TestEveryPathTheDeploymentWritesHasAVolumeUnderIt(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	container := serverContainer(t, root)
	settings := manifestConfiguration(t, root)

	written := map[string]string{
		"core.overlay":                        settings.Core.Overlay,
		"core.modules":                        settings.Core.Modules,
		"core.authz.database":                 settings.Core.Authz.Database,
		"resources.storage.local.config.root": settings.Resources.Storage["local"].Config.Root,
		// A cluster's ConfigMap holds no pairing, so the core writes it beside
		// the overlay at its first start, which is betaportal.Path. This
		// package imports nothing else internal (ADR-20260824-kkr), so the
		// name is written out.
		"the Beta Portal pairing": path.Join(path.Dir(settings.Core.Overlay), "beta-portal-pairing.json"),
		// Each installed extension keeps its data in a folder beside
		// core.modules, which is moduleDataRoot in internal/app.
		"the extensions' data": path.Join(path.Dir(settings.Core.Modules), "module-data"),
	}

	for key, path := range written {
		if path == "" {
			t.Fatalf("the ConfigMap sets no %s, so this gate has nothing to look for", key)
		}

		if !writableMountCovers(container, path) {
			t.Errorf("the ConfigMap writes %s to %s and %s mounts no writable volume over it.\n"+
				"The root filesystem is immutable, so the core stops at startup.",
				key, path, deploymentPath)
		}
	}
}

// TestEveryProbePathIsOneTheImageIsProvedToServe keeps the manifest's probes
// tied to the only thing that ran a real container. A liveness probe on a path
// the core does not serve restarts a healthy process every failureThreshold.
func TestEveryProbePathIsOneTheImageIsProvedToServe(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	container := serverContainer(t, root)
	proved := captureFields(t, probePathsPattern, read(t, root, probesPath), probesPath)

	for name, probe := range map[string]kubeProbe{
		"startupProbe":   container.StartupProbe,
		"livenessProbe":  container.LivenessProbe,
		"readinessProbe": container.ReadinessProbe,
	} {
		if probe.HTTPGet.Path == "" {
			t.Errorf("%s declares no %s", deploymentPath, name)

			continue
		}

		if !contains(proved, probe.HTTPGet.Path) {
			t.Errorf("%s reads %s and %s proves %v answer 200.\n"+
				"Nothing has run a container against that path.",
				name, probe.HTTPGet.Path, probesPath, proved)
		}
	}

	if container.LivenessProbe.HTTPGet.Path == container.ReadinessProbe.HTTPGet.Path {
		t.Errorf("liveness and readiness both read %s.\n"+
			"They answer different questions: a pod refusing traffic on purpose is not a "+
			"pod to restart, and one path cannot say both.", container.LivenessProbe.HTTPGet.Path)
	}
}

// TestTheManifestSetAgreesOnOnePort walks the port from the address the core
// binds through to the Service a caller reaches.
func TestTheManifestSetAgreesOnOnePort(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	container := serverContainer(t, root)
	addr := manifestConfiguration(t, root).Core.API.Addr

	_, port, found := strings.Cut(addr, ":")
	if !found || port == "" {
		t.Fatalf("the ConfigMap sets core.api.addr to %q, which names no port", addr)
	}

	bound, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("core.api.addr is %q: %v", addr, err)
	}

	if len(container.Ports) != 1 || container.Ports[0].ContainerPort != bound {
		t.Fatalf("the ConfigMap binds %s and %s declares %v.\n"+
			"A containerPort that disagrees with the address is a probe and a Service "+
			"pointed at nothing.", addr, deploymentPath, container.Ports)
	}

	var service kubeService

	decode(t, read(t, root, kubeServicePath), kubeServicePath, &service)

	if len(service.Spec.Ports) != 1 {
		t.Fatalf("%s declares %d ports and the core binds one listener",
			kubeServicePath, len(service.Spec.Ports))
	}

	if target := service.Spec.Ports[0].TargetPort; target != container.Ports[0].Name {
		t.Errorf("%s sends traffic to %q and the container names its port %q",
			kubeServicePath, target, container.Ports[0].Name)
	}
}

// TestTheDeploymentRunsAsTheUserTheImageBuilds. The uid is fixed at build time
// so a volume can be owned by a number somebody can predict, and a manifest
// naming a different one gets permission denied on every write.
func TestTheDeploymentRunsAsTheUserTheImageBuilds(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	dockerfile := read(t, root, dockerfilePath)
	pod := podSpec(t, root)

	for _, want := range []struct {
		arg   string
		named string
		got   *int
	}{
		{arg: "APP_UID", named: "runAsUser", got: pod.SecurityContext.RunAsUser},
		{arg: "APP_GID", named: "runAsGroup", got: pod.SecurityContext.RunAsGroup},
		{arg: "APP_GID", named: "fsGroup", got: pod.SecurityContext.FSGroup},
	} {
		built := buildArgument(t, dockerfile, want.arg)

		if want.got == nil {
			t.Errorf("%s sets no %s, and the image runs as %s %d",
				deploymentPath, want.named, want.arg, built)

			continue
		}

		if *want.got != built {
			t.Errorf("%s sets %s to %d and the image builds %s as %d",
				deploymentPath, want.named, *want.got, want.arg, built)
		}
	}

	if pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Errorf("%s does not set runAsNonRoot. The image runs as a fixed unprivileged uid, "+
			"and this is what makes the kubelet refuse an image that does not.", deploymentPath)
	}
}

// TestTheDeploymentIsHardenedTheWayComposeIs pairs each Kubernetes setting with
// the compose setting that means the same thing. A cluster deployment that is
// hardened less than `docker compose up` is the drift this catches.
func TestTheDeploymentIsHardenedTheWayComposeIs(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	manifest := read(t, root, deploymentPath)
	compose := read(t, root, servicePath)

	for _, pair := range hardening {
		if !strings.Contains(compose, pair.compose) {
			t.Fatalf("%s no longer sets %s, so this gate compares the manifest against nothing",
				servicePath, pair.compose)
		}

		if !strings.Contains(manifest, pair.kubernetes) {
			t.Errorf("%s sets %s and %s sets no %s",
				servicePath, pair.compose, deploymentPath, pair.kubernetes)
		}
	}

	container := serverContainer(t, root)

	if container.SecurityContext.ReadOnlyRootFilesystem == nil ||
		!*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Error("the container does not set readOnlyRootFilesystem, and compose sets read_only")
	}

	if container.SecurityContext.AllowPrivilegeEscalation == nil ||
		*container.SecurityContext.AllowPrivilegeEscalation {
		t.Error("the container allows privilege escalation, and compose sets no-new-privileges")
	}

	if got := container.SecurityContext.Capabilities.Drop; len(got) != 1 || got[0] != "ALL" {
		t.Errorf("the container drops %v, and compose drops ALL", got)
	}
}

// TestTheShutdownBudgetFitsInsideTheGracePeriod. core.shutdown_timeout bounds
// the drain and then bounds waiting for the supervision plane, so a grace period
// at or below it means the orchestrator kills the drain it asked for.
func TestTheShutdownBudgetFitsInsideTheGracePeriod(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	settings := manifestConfiguration(t, root)

	budget, err := time.ParseDuration(settings.Core.ShutdownTimeout)
	if err != nil {
		t.Fatalf("core.shutdown_timeout is %q: %v", settings.Core.ShutdownTimeout, err)
	}

	grace := time.Duration(podSpec(t, root).TerminationGracePeriodSeconds) * time.Second
	if grace <= budget {
		t.Errorf("terminationGracePeriodSeconds is %s and core.shutdown_timeout is %s.\n"+
			"The drain runs inside that budget, so the pod is killed part way through it.",
			grace, budget)
	}
}

// TestTheDeploymentStaysAtOneWriter. The authorization graph is SQLite on a
// ReadWriteOnce claim. A second replica cannot attach the claim, and a rolling
// update waits for a pod that never starts.
func TestTheDeploymentStaysAtOneWriter(t *testing.T) {
	t.Parallel()

	deployment := loadDeployment(t, repoRoot(t))

	replicas := "no"
	if deployment.Spec.Replicas != nil {
		replicas = strconv.Itoa(*deployment.Spec.Replicas)
	}

	if replicas != "1" {
		t.Errorf("%s declares %s replicas. The authorization graph is one SQLite file on a "+
			"ReadWriteOnce claim, and one process writes it.", deploymentPath, replicas)
	}

	if deployment.Spec.Strategy.Type != "Recreate" {
		t.Errorf("%s rolls out with %q. A RollingUpdate starts the new pod first, and it "+
			"cannot attach a ReadWriteOnce claim the old one still holds.",
			deploymentPath, deployment.Spec.Strategy.Type)
	}
}
