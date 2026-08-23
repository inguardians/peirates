package model

import "time"

// ServerInfo describes the active Kubernetes API connection and credential.
type ServerInfo struct {
	APIServer      string
	Token          string
	TokenName      string
	ClientCertData string
	ClientKeyData  string
	ClientCertName string
	CAPath         string
	CACertData     string
	Namespace      string
	UseAuthCanI    bool
	IgnoreTLS      bool
}

// PodNamespaceContainerTuple identifies a container in a Kubernetes pod.
type PodNamespaceContainerTuple struct {
	PodName       string
	PodNamespace  string
	ContainerName string
}

// KubeRoles is the response shape used when parsing Kubernetes roles.
type KubeRoles struct {
	APIVersion string `json:"apiVersion"`
	Items      []struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Annotations struct {
				KubectlKubernetesIoLastAppliedConfiguration string `json:"kubectl.kubernetes.io/last-applied-configuration"`
			} `json:"annotations"`
			CreationTimestamp time.Time `json:"creationTimestamp"`
			Name              string    `json:"name"`
			Namespace         string    `json:"namespace"`
			ResourceVersion   string    `json:"resourceVersion"`
			SelfLink          string    `json:"selfLink"`
			UID               string    `json:"uid"`
		} `json:"metadata"`
		Rules []struct {
			APIGroups []string `json:"apiGroups"`
			Resources []string `json:"resources"`
			Verbs     []string `json:"verbs"`
		} `json:"rules"`
	} `json:"items"`
	Kind     string `json:"kind"`
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
		SelfLink        string `json:"selfLink"`
	} `json:"metadata"`
}

// PodDetails is the response shape used when parsing Kubernetes pods.
type PodDetails struct {
	APIVersion string `json:"apiVersion"`
	Items      []Pod  `json:"items"`
	Kind       string `json:"kind"`
	Metadata   struct {
		ResourceVersion string `json:"resourceVersion"`
		SelfLink        string `json:"selfLink"`
	} `json:"metadata"`
}

// Pod contains the pod fields consumed by Peirates.
type Pod struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Annotations struct {
			KubectlKubernetesIoLastAppliedConfiguration string `json:"kubectl.kubernetes.io/last-applied-configuration"`
		} `json:"annotations"`
		CreationTimestamp time.Time `json:"creationTimestamp"`
		Labels            struct {
			App string `json:"app"`
		} `json:"labels"`
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion"`
		SelfLink        string `json:"selfLink"`
		UID             string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		Containers []struct {
			Image           string `json:"image"`
			ImagePullPolicy string `json:"imagePullPolicy"`
			Name            string `json:"name"`
			Ports           []struct {
				ContainerPort int    `json:"containerPort"`
				Protocol      string `json:"protocol"`
			} `json:"ports"`
			Resources                struct{} `json:"resources"`
			TerminationMessagePath   string   `json:"terminationMessagePath"`
			TerminationMessagePolicy string   `json:"terminationMessagePolicy"`
			VolumeMounts             []struct {
				MountPath string `json:"mountPath"`
				Name      string `json:"name"`
				ReadOnly  bool   `json:"readOnly"`
			} `json:"volumeMounts"`
		} `json:"containers"`
		DNSPolicy    string `json:"dnsPolicy"`
		NodeName     string `json:"nodeName"`
		NodeSelector struct {
			KubernetesIoHostname string `json:"kubernetes.io/hostname"`
		} `json:"nodeSelector"`
		RestartPolicy                 string   `json:"restartPolicy"`
		SchedulerName                 string   `json:"schedulerName"`
		SecurityContext               struct{} `json:"securityContext"`
		ServiceAccount                string   `json:"serviceAccount"`
		ServiceAccountName            string   `json:"serviceAccountName"`
		TerminationGracePeriodSeconds int      `json:"terminationGracePeriodSeconds"`
		Tolerations                   []struct {
			Effect            string `json:"effect"`
			Key               string `json:"key"`
			Operator          string `json:"operator"`
			TolerationSeconds int    `json:"tolerationSeconds"`
		} `json:"tolerations"`
		Volumes []struct {
			HostPath struct {
				Path string `json:"path"`
				Type string `json:"type"`
			} `json:"hostPath,omitempty"`
			Name   string `json:"name"`
			Secret struct {
				DefaultMode int    `json:"defaultMode"`
				SecretName  string `json:"secretName"`
			} `json:"secret,omitempty"`
		} `json:"volumes"`
	} `json:"spec"`
	Status struct {
		Conditions []struct {
			LastProbeTime      interface{} `json:"lastProbeTime"`
			LastTransitionTime time.Time   `json:"lastTransitionTime"`
			Status             string      `json:"status"`
			Type               string      `json:"type"`
		} `json:"conditions"`
		ContainerStatuses []struct {
			ContainerID string `json:"containerID"`
			Image       string `json:"image"`
			ImageID     string `json:"imageID"`
			LastState   struct {
				Terminated struct {
					ContainerID string    `json:"containerID"`
					ExitCode    int       `json:"exitCode"`
					FinishedAt  time.Time `json:"finishedAt"`
					Reason      string    `json:"reason"`
					StartedAt   time.Time `json:"startedAt"`
				} `json:"terminated"`
			} `json:"lastState"`
			Name         string `json:"name"`
			Ready        bool   `json:"ready"`
			RestartCount int    `json:"restartCount"`
			State        struct {
				Running *struct {
					StartedAt time.Time `json:"startedAt"`
				} `json:"running"`
			} `json:"state"`
		} `json:"containerStatuses"`
		HostIP    string    `json:"hostIP"`
		Phase     string    `json:"phase"`
		PodIP     string    `json:"podIP"`
		QosClass  string    `json:"qosClass"`
		StartTime time.Time `json:"startTime"`
	} `json:"status"`
}
