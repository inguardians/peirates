package app

import (
	"os"

	"github.com/inguardians/peirates/internal/modules"
)

func newModuleRegistry(session *Session) *modules.Registry {
	registry := modules.NewRegistry()
	registry.Register(func() modules.Result { os.Exit(0); return modules.Continue }, "exit", "quit")
	registry.Register(func() modules.Result {
		_ = kubectlInteractive(session.Connection, session.LogToFile, session.OutputFileName)
		return modules.Continue
	}, "kubectl")
	registry.Register(func() modules.Result {
		switchServiceAccounts(session.ServiceAccounts, &session.Connection, session.LogToFile, session.OutputFileName)
		return modules.Continue
	}, "switch-sa")
	registry.Register(func() modules.Result {
		listServiceAccounts(session.ServiceAccounts, session.Connection, session.LogToFile, session.OutputFileName)
		return modules.Continue
	}, "list-sa")
	registry.Register(func() modules.Result {
		saMenu(&session.ServiceAccounts, &session.Connection, session.Interactive, session.LogToFile, session.OutputFileName)
		return modules.Continue
	}, "sa-menu")
	registry.Register(func() modules.Result {
		decodeTokenInteractive(session.ServiceAccounts, &session.Connection, session.LogToFile, session.OutputFileName, session.Interactive)
		return modules.Continue
	}, "decode-jwt")
	registry.Register(func() modules.Result { listNamespaces(session.Connection); return modules.Continue }, "list-ns")
	registry.Register(func() modules.Result { menuSwitchNamespaces(&session.Connection); return modules.Continue }, "switch-ns")
	registry.Register(func() modules.Result { interactiveNSMenu(&session.Connection); return modules.Continue }, "ns-menu")
	registry.Register(func() modules.Result { printListOfPods(session.Connection); return modules.Continue }, "get-pods")
	registry.Register(func() modules.Result { GetPodsInfo(session.Connection, &session.Pods); return modules.Continue }, "dump-pod-info")
	registry.Register(func() modules.Result {
		credentials, err := EnterIamCredentialsForAWS()
		if err != nil {
			println("[-] Error entering AWS credentials: ", err)
			return modules.Continue
		}
		session.AWSCredentials = credentials
		println(" New AWS credentials are: \n")
		DisplayAWSIAMCredentials(session.AWSCredentials)
		return modules.Continue
	}, "aws-enter-credentials")
	registry.Register(func() modules.Result {
		assumeAWSrole(session.AWSCredentials, &session.AssumedAWSRole, session.Interactive)
		return modules.Continue
	}, "aws-assume-role")
	registry.Register(func() modules.Result {
		session.AssumedAWSRole.AccessKeyID = ""
		session.AssumedAWSRole.accountName = ""
		return modules.Continue
	}, "aws-empty-assumed-role")
	registry.Register(func() modules.Result {
		certMenu(&session.ClientCertificates, &session.Connection, session.Interactive)
		return modules.Continue
	}, "cert-menu")
	registry.Register(func() modules.Result { listSecrets(&session.Connection); return modules.Continue }, "list-secrets")
	registry.Register(func() modules.Result {
		getServiceAccountTokenFromSecret(session.Connection, &session.ServiceAccounts, session.Interactive)
		return modules.Continue
	}, "secret-to-sa")
	registry.Register(func() modules.Result { findVolumeMounts(session.Connection, &session.Pods); return modules.Continue }, "find-volume-mounts")
	registry.Register(func() modules.Result {
		attackHostPathMount(session.Connection, session.Interactive)
		return modules.Continue
	}, "attack-pod-hostpath-mount")
	registry.Register(func() modules.Result {
		result, err := getAWSToken(session.Interactive)
		if err != nil {
			session.AWSCredentials = result
		}
		return modules.Continue
	}, "aws-get-token")
	registry.Register(func() modules.Result { getGCPToken(session.Interactive); return modules.Continue }, "gcp-get-token")
	registry.Register(func() modules.Result { attackKubeEnvGCP(session.Interactive); return modules.Continue }, "gcp-attack-kube-env")
	registry.Register(func() modules.Result {
		if err := KopsAttackGCP(&session.ServiceAccounts); err != nil {
			println("Kops attack failed on GCP.")
		}
		pauseToHitEnter(session.Interactive)
		return modules.Continue
	}, "gcp-attack-kops-1")
	registry.Register(func() modules.Result {
		KopsAttackAWS(&session.ServiceAccounts, session.AWSCredentials, session.AssumedAWSRole, session.Interactive)
		return modules.Continue
	}, "aws-attack-kops-1")
	registry.Register(func() modules.Result {
		awsS3ListBucketsMenu(session.AWSCredentials, session.AssumedAWSRole)
		return modules.Continue
	}, "aws-s3-ls")
	registry.Register(func() modules.Result {
		awsS3ListBucketObjectsMenu(session.AWSCredentials, session.AssumedAWSRole)
		return modules.Continue
	}, "aws-s3-ls-objects")
	registry.Register(func() modules.Result { execInPodMenu(session.Connection, session.Interactive); return modules.Continue }, "exec-via-api")
	registry.Register(func() modules.Result {
		ExecuteCodeOnKubelet(session.Connection, &session.ServiceAccounts)
		return modules.Continue
	}, "exec-via-kubelet")
	registry.Register(func() modules.Result { _ = createLeakyVesselPod(session.Connection); return modules.Continue }, "leakyvessels")
	registry.Register(func() modules.Result {
		println("\nAttempting to steal secrets from the node filesystem - this will return no output if run in a container or if /var/lib/kubelet is inaccessible.\n")
		gatherPodCredentials(&session.ServiceAccounts, true, true)
		return modules.Continue
	}, "nodefs-steal-secrets")
	registry.Register(func() modules.Result { println("Item not yet implemented"); return modules.Continue }, "nodefs-secrets-list")
	registry.Register(func() modules.Result { injectAndExecMenu(session.Connection); return modules.Continue }, "inject-and-exec")
	registry.Register(func() modules.Result {
		curl(session.Interactive, session.LogToFile, session.OutputFileName)
		return modules.Continue
	}, "curl")
	registry.Register(func() modules.Result {
		setAuthCanIMenu(&session.Connection.UseAuthCanI, session.Interactive)
		return modules.Continue
	}, "set-auth-can-i")
	registry.Register(func() modules.Result { tcpScan(session.Interactive); return modules.Continue }, "tcpscan")
	registry.Register(func() modules.Result { _ = enumerateDNS(); return modules.Continue }, "enumerate-dns")
	registry.Register(func() modules.Result { _ = runBash(); return modules.Continue }, "bash")
	registry.Register(func() modules.Result { _ = runSH(); return modules.Continue }, "sh")
	registry.Register(func() modules.Result { session.FullMenu = true; return modules.Refresh }, "full")
	registry.Register(func() modules.Result { session.FullMenu = false; return modules.Refresh }, "short")
	return registry
}
