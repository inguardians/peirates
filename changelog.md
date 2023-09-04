## v1.1.13

- Added cloud provider detection from @devsecfranklin
- Bump gopkg.in/yaml.v3 to avoid DoS risk on filesystem
- Added a function to get eth0 IP addr and put in banner
- Parse the current pod's service account name from its JWT
- Cleaned up menu formatting

## v1.1.12

- Added a second variation of kubectl-try-all that tries a command as every service account collected, no longer stopping on the first success. (Idea from @Malachi-the-Ninja)

## v1.1.11

Added image building and K8S deployment functions from @devsecfranklin
Improved error handling on CoreDNS wildcard trick
Added another kubelet kubeconfig file path and handled errors better
Added a credits.md file and added a developer to it: @devsecfranklin

## v1.1.10

- fixed kubelet cert/key pulling code to handle kubelet kubeconfig files with embedded user cert/key pairs
- updated kubeconfig file parsing to parse via the YAML library, which is much more resilient

## v1.1.9

- Updated recovering service account tokens from the node filesystem to handle the ServiceAccount admission controller

## v1.1.8

- Beta feature: one-shot (non-interactive) menu items work, but are under-documented in the UI.
- New feature (GA): harvest secrets from the node filesystem is now available on-menu and -m one-shot

## v1.1.7

- Alpha feature: one-shot (non-interactive) menu items work, but are under-documented in the UI.
- New feature (GA) : service discovery via CoreDNS wildcard SRV request using methodology posted by @ raesene

## v1.1.6

- Alpha feature: allows you to run menu items from the command-line in a one-shot method, to allow scripting

## v1.1.5

- added feature to better name secrets found on node using the pod's etc-hosts file
- we now avoid adding duplicate service accounts from the kubelet secret gathering
- shell command takes multiple commands

## v1.1.4

- refactored curl feature
- made a bugfix to using node certs

## v1.1.3

- added quick commands for switching service accounts and namespace, without having to navigate submenus
- bugfix - kubectl logic had dropped namespace context

## v1.1.2

- added a kubectl-try-all feature - tries every service account and client cert that peirates has gathered it has until it finds one that can do the command.

## v1.1.1

- execute shell commands from the main menu via "shell [args]"
- execute kubectl commands from the menu via "kubectl [args]"
- kubectl no longer locks you to namespace context - can be overridden with -n or --all-namespaces

## v1.1.0

- Peirates can now be run outside of a pod.
- Peirates automatically gathers kubelet cert/key pairs from the node filesystem
- Peirates automatically gathers pods secrets from the node filesystem

## v1.0.36

- Peirates now uses kubelet certs if run on a node
- -u (API Server URL) replaces -i (IP address/name of API server) and -p (port of API server)
- Peirates does not require an API server to be specified to start, only to run relevant commands.

## v1.0.35

- Updated GCP metadata API token parsing for Google's change

## v1.0.34

- Added JWT parsing

## v1.0.33

- Simple TCP portscan functionality

## v1.0.32

- Many changes to appease the linter.
- Regexp compiles to appease the linter, will also speed things a tiny bit.
- Namespace switching checks inputs better.
- More inputs trim whitespace.

## v1.0.31

- adds an AWS version of the kops state bucket attack
- This also refactors some of our AWS code.

## v1.0.30

- You can now toggle Peirates' checking if each action is permitted by RBAC before doing it.
- Added sub-menu item prose in addition to numbers.

## v1.0.29

- adds custom headers to curl and IP address discovery for hostPath mounting trick

## v1.0.28a

- Bugfix release - curl had been crashing when HTTP/s requests had no parameters.

## v1.0.28

- This version adds a curl-style feature, such that the user can make arbitrary GET and POST requests.

## v1.0.27

- This release adds non-numeric aliases for menu items and makes a few code-cleanups.

## v1.0.25
 
- Added AWS S3 bucket list and content list capabilities

## v1.0.24

- Added error fall through to the injection into other pods, making this more beautiful.

## v1.0.23

- Updated version number and cleaned up print statements.

## v1.0.22

- Implemented the insert-peirates-into-another-pod - more coming.

## v1.0.21

- Changed a path for service accounts mounted into pods from /run/secrets/... to /var/run/secrets/...

## v1.0.20

- This release adds a flexible kubectl menu item, allowing you to use the service account tokens you've acquired flexibly to perform actions that don't yet have menu items.

## v1.0.19
- Refactored URL requests and JSON parsing

## v1.0.18
- Allowed for long-running kube-exec commands by excepting them from the timers

## v1.0.17

- In this release, we've adjusted the service account token-gathering functions to store the tokens automatically for re-use

## v1.0.16

- Added ability to switch to a service account at the time you enter it.
- Minor UI changes.

## v1.0.15

- Final "Break Glass" release for demos

## v1.0.14

- See <https://github.com/inguardians/peirates/commits/v1.0.14>

## v1.0.11

- This release adds credential theft via GCS, refactors the menu and is the current pre-conference "break glass" release, having received testing at thoroughness level 4/5.

## v1.0.10

- Auth checks added to avoid crashes when requested action isn't allowed

## v1.0.9

- Reverse TCP shell added
