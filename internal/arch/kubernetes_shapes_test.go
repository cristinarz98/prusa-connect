package arch_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// probePathsPattern reads the paths scripts/check-container-probes.sh proves a
// real container answers 200 on. The manifest's probes are compared against
// that list rather than against a copy of it.
var probePathsPattern = regexp.MustCompile(`(?m)^PATHS="([^"]*)"`)

// buildArgPattern reads a Dockerfile build argument's default value.
var buildArgPattern = `(?m)^ARG %s=(\S+)`

// kubeDeployment is the part of a Deployment these gates read.
type kubeDeployment struct {
	Spec struct {
		Replicas *int `yaml:"replicas"`
		Strategy struct {
			Type string `yaml:"type"`
		} `yaml:"strategy"`
		Template struct {
			Spec kubePodSpec `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type kubePodSpec struct {
	TerminationGracePeriodSeconds int `yaml:"terminationGracePeriodSeconds"`
	SecurityContext               struct {
		RunAsNonRoot *bool `yaml:"runAsNonRoot"`
		RunAsUser    *int  `yaml:"runAsUser"`
		RunAsGroup   *int  `yaml:"runAsGroup"`
		FSGroup      *int  `yaml:"fsGroup"`
	} `yaml:"securityContext"`
	Containers []kubeContainer `yaml:"containers"`
	Volumes    []struct {
		Name string `yaml:"name"`
	} `yaml:"volumes"`
}

type kubeContainer struct {
	Name  string   `yaml:"name"`
	Args  []string `yaml:"args"`
	Ports []struct {
		Name          string `yaml:"name"`
		ContainerPort int    `yaml:"containerPort"`
	} `yaml:"ports"`
	SecurityContext struct {
		AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
		ReadOnlyRootFilesystem   *bool `yaml:"readOnlyRootFilesystem"`
		Capabilities             struct {
			Drop []string `yaml:"drop"`
		} `yaml:"capabilities"`
	} `yaml:"securityContext"`
	StartupProbe   kubeProbe         `yaml:"startupProbe"`
	LivenessProbe  kubeProbe         `yaml:"livenessProbe"`
	ReadinessProbe kubeProbe         `yaml:"readinessProbe"`
	VolumeMounts   []kubeVolumeMount `yaml:"volumeMounts"`
}

type kubeProbe struct {
	HTTPGet struct {
		Path string `yaml:"path"`
		Port string `yaml:"port"`
	} `yaml:"httpGet"`
}

type kubeVolumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
	SubPath   string `yaml:"subPath"`
	ReadOnly  bool   `yaml:"readOnly"`
}

type kubeService struct {
	Spec struct {
		Ports []struct {
			Name       string `yaml:"name"`
			Port       int    `yaml:"port"`
			TargetPort string `yaml:"targetPort"`
		} `yaml:"ports"`
	} `yaml:"spec"`
}

// manifestSettings is the part of the ConfigMap's configuration file these
// gates read. The loader in internal/app/config reads the rest of it, in
// internal/app/config/kubernetes_manifest_test.go: internal/arch imports no
// other internal package (ADR-20260824-kkr), so this is a second reading of the same
// bytes and never a second definition of what they mean.
type manifestSettings struct {
	Core struct {
		API struct {
			Addr string `yaml:"addr"`
		} `yaml:"api"`
		Overlay string `yaml:"overlay"`
		Modules string `yaml:"modules"`
		Authz   struct {
			Database string `yaml:"database"`
		} `yaml:"authz"`
		ShutdownTimeout string `yaml:"shutdown_timeout"`
	} `yaml:"core"`
	Resources struct {
		Storage map[string]struct {
			Config struct {
				Root string `yaml:"root"`
			} `yaml:"config"`
		} `yaml:"storage"`
	} `yaml:"resources"`
}

// loadDeployment is the Deployment, decoded. Anything missing fails the run
// rather than reading as a zero value.
func loadDeployment(t *testing.T, root string) kubeDeployment {
	t.Helper()

	var deployment kubeDeployment

	decode(t, read(t, root, deploymentPath), deploymentPath, &deployment)

	if len(deployment.Spec.Template.Spec.Containers) == 0 {
		t.Fatalf("%s declares no container, so these gates read nothing", deploymentPath)
	}

	return deployment
}

func podSpec(t *testing.T, root string) kubePodSpec {
	t.Helper()

	return loadDeployment(t, root).Spec.Template.Spec
}

// serverContainer is the one container the pod runs.
func serverContainer(t *testing.T, root string) kubeContainer {
	t.Helper()

	containers := podSpec(t, root).Containers
	if len(containers) != 1 {
		t.Fatalf("%s runs %d containers and this deployment is one process",
			deploymentPath, len(containers))
	}

	return containers[0]
}

// manifestConfiguration is the configuration file the ConfigMap carries.
func manifestConfiguration(t *testing.T, root string) manifestSettings {
	t.Helper()

	var manifest struct {
		Data map[string]string `yaml:"data"`
	}

	decode(t, read(t, root, configMapPath), configMapPath, &manifest)

	body := manifest.Data["config.yaml"]
	if strings.TrimSpace(body) == "" {
		t.Fatalf("%s carries no config.yaml, so these gates read nothing", configMapPath)
	}

	var settings manifestSettings

	decode(t, body, configMapPath+" data.config.yaml", &settings)

	return settings
}

// configVolumeName is the volume the ConfigMap is mounted through, read from the
// pod's volume list rather than assumed.
func configVolumeName(t *testing.T, root string) string {
	t.Helper()

	var deployment struct {
		Spec struct {
			Template struct {
				Spec struct {
					Volumes []struct {
						Name      string `yaml:"name"`
						ConfigMap *struct {
							Name string `yaml:"name"`
						} `yaml:"configMap"`
					} `yaml:"volumes"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}

	decode(t, read(t, root, deploymentPath), deploymentPath, &deployment)

	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.ConfigMap != nil {
			return volume.Name
		}
	}

	t.Fatalf("%s mounts no ConfigMap, so the operator's file reaches the pod by no route",
		deploymentPath)

	return ""
}

// mountNamed is one of the container's mounts, by volume name.
func mountNamed(t *testing.T, container kubeContainer, name string) kubeVolumeMount {
	t.Helper()

	for _, mount := range container.VolumeMounts {
		if mount.Name == name {
			return mount
		}
	}

	t.Fatalf("%s declares volume %q and the container does not mount it", deploymentPath, name)

	return kubeVolumeMount{}
}

// writableMountCovers reports whether a writable mount sits at or above a path
// the process writes.
func writableMountCovers(container kubeContainer, path string) bool {
	for _, mount := range container.VolumeMounts {
		if mount.ReadOnly {
			continue
		}

		if path == mount.MountPath || strings.HasPrefix(path, mount.MountPath+"/") {
			return true
		}
	}

	return false
}

// argumentValue is the value that follows a flag in a container's argument list.
func argumentValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}

		if value, found := strings.CutPrefix(arg, flag+"="); found {
			return value
		}
	}

	return ""
}

// buildArgument is a Dockerfile ARG's default, as a number.
func buildArgument(t *testing.T, dockerfile, name string) int {
	t.Helper()

	pattern := regexp.MustCompile(strings.Replace(buildArgPattern, "%s", name, 1))

	match := pattern.FindStringSubmatch(dockerfile)
	if match == nil {
		t.Fatalf("%s declares no ARG %s, so this gate compares against nothing",
			dockerfilePath, name)
	}

	value, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("ARG %s is %q, which is not a number: %v", name, match[1], err)
	}

	return value
}

// decode reads a yaml document into shape, failing the run when it does not
// parse. Every gate here reads a file somebody hand-edits.
func decode(t *testing.T, content, path string, into any) {
	t.Helper()

	if err := yaml.Unmarshal([]byte(content), into); err != nil {
		t.Fatalf("%s does not parse as yaml: %v", path, err)
	}
}
