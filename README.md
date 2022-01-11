# Understanding the Kubernetes Attack Surface

## The attack
- An example of a Kubernetes attack has similar steps to any other kind of cyber attack
- Reconaissance: Finding information about a host, like IP addresses or open ports
- Data gathering: get information from the specific target, like software versions or a schema of how the application works
- Exploitation: Use the information gathered to exploit a hole in the system that allows us to gain foothold, like running a container for ourselves
- Post exploitation: once in the system, use the foothold to escape to a more privileged environment and exploit the required info, like database and credential dumping
- In the case of Kubernetes, access to a worker node can provide a lot of useful information, like listening ports of important resources like dashboards or API servers

## The 4 C's of Cloud Native security
- Cloud native security involves 4 main points
- Cloud: the infrastructure that hosts a cluster, like network configuration and host hardening, datacenter security, account access authentication and authorization
- Cluster: Control remote access to the docker daemon and Kubernetes API with network hardening, authentication and authorization
- Containers: Control that a container is sandboxed and does not have more privileges than strictly necessary so foothold cannot be achieved, and privilege cannot be escalated
- Code: Keep security best practices on your application's code, like avoiding hardcoding credentials in your application configuration

# Cluster setup and hardening

## CIS Benchmarks
- We need to keep a valid security benchmark to protect systems and customer data
- Limit access, authentication and authorization
- Implement network hardening
- make sure no unnecessary services are enabled that could act as an entrypoint
- Make sure filesystem permissions are not more permissive than necessary
- Enable logging and auditing to have a change registry on the system
- Security benchmarks are a set of standard rules that validate that a system is considered secure
- CIS Benchmark is a widely used baseline to check how protected against cyber threats a system is
- Benchmarks for all platforms and levels of infrastructure: Operative Systems both desktop and mobile, Cloud Providers, Network hardware vendors, desktop software and server software
- CIS-CAT tools help you validate a benchmark against an environment and will output a report you can use to apply any needed changes

## CIS Benchmark for Kubernetes
- CIS has a specific benchmark for Kubernetes intended for auditors, security specialists and system administrators
- Recommendations about master node configuration files for fundamental cluster elements, like API server settings
- Benchmarks for communication using TLS
- We can use the CIS-CAT Pro toolset to scan a Kubernetes cluster against benchmark specifications

## Kube-bench
- Open source tool from AquaSecurity
- Used to scan if a cluster is securely configured
- Based on the CIS Benchmark
- Can be deployed as a container, a job, or used as a binary

## Kubernetes security primitives
- Focus on securing the environment at a kubernetes cluster level
- kube-apiserver controls access to the entire cluster, so it has to be our biggest line of defense
- Controls who can access the cluster (authentication) and what can they do (authorization)
- Users authenticate with username and password pairs, username and token pairs, certificates, external methods like LDAP, and for the case of applications, Service Accounts
- Authorization is handled based in roles. We can also use Attribute-based authorization, Node-based authorization or webhooks
- Communication accross the cluster needs to be secured using TLS
- Pod access is open by default to all other pods by default unless limited

## Authentication
- Accessing a cluster requires authentication by users and applications
- Depending on the user's role, we can give them one permission set or another
- Administrators can get role-wide permissions to manage the cluster. Developers, in turn, can be limited to only creating and destroying resources in a specific namespace
- All access to the cluster is managed by the kube-apiserver, which authenticates each request before processing it
- Users authenticate with username and password pairs, username and token pairs, certificates, external methods like LDAP, and for the case of applications, Service Accounts
- Static password and token files consist of a list of users on a CSV with the columns password, username and user ID. This file is then passed to the kube-apiserver as a variable, and requires a restart to be applied if it changes
- We can have an optional group column to group users inside groups to make permissions easier to handle

## Service accounts
- Used for authentication, autorization and access control for services, like pods
- User accounts are used by people, service accounts are used by tools and applications
- Used to interact with the cluster, like a web application that queries the Kubernetes API to list running pods
- ServiceAccounts automatically create a linked token stored as a secret that can authenticate the ServiceAccount to interact with the cluster
- You can mount the ServiceAccount token secret to a pod as a volume, which allows the application to read the secret automatically
- Each namespace has its own Default ServiceAccount, which is added to every pod in the namespace by default, even if not specified
- This can be prevented by setting `automountServiceAccountToken` to `false` on the pod spec
- ServiceAccount secrets are mounted by default to `/var/run/secrets/kubernetes.io/serviceaccount` inside the pod
- You can list the files inside the pod mounted folder and see the 3 files: token, namespace anc ca.crt
- The token itself is stored in the token file
- This token only has permission to run basic Kubernetes API queries
- To change the token on a pod, the pod must be deleted and recreated
- If changes are made to a deployment on a ServiceAccount, a rollout will be triggered

## TLS Certificates in Kubernetes
- Communication between Kubernetes nodes need to be secure and protected with TLS
- Services inside the cluster also need to use TLS for communication
- In terms of server components, kube-apiserver exposes an HTTPS service to interact with the cluster and has a certificate pair, etcd server and kubelet are other server services that also have their own certificate pairs
- In terms of client components, the elements needed to authenticate against the cluster, wethere we're users or administrators. Clients can be user, like an administrator applying a kubernetes manifest, or kube-scheduler, which is considered a client querying data from the kube-apiserver, and thus have their own certificate pairs
- same applies to kube-controllermanager and kube-proxy, both acting as clients in the Kubernetes ecosystem with their own certificate pairs recognized in the kube-apiserver component
- kube-apiserver acts as a client to etcd-server and the kubelet, and have certificates authororized to access them
- All of these certificates are validated against the certificate authority of the cluster

## Generating TLS certificate pairs
- First create a private key for the certificate
- Generate a Certificate Signing request for the certificate
- Accept the signing request using the accepted CA to generate the certificate
- To add permissions to a new user certificate, specify the group on the certificate signing request
- You can use these certificates to authenticate against Kubernetes, either in https requests or by using a kubeconfig file
- The same procedure is followed for server certificates, like the etcd-server certificate pair
- You can add several options to your certificate signing request with an OpenSSL configuration file
- If the cluster is installed using kubeadm, these certificates are handled automatically

## Viewing certificates on a cluster
- Certificates are natively added to Kubernetes as a resource definition
- These certificates can be found under `/etc/kubernetes/` for server components. You can check for certificate locations on the kube-apiserver manifest, by default on `/etc/kubernetes/manifests/kube-apiserver.yaml`
- Decoding a certificate with the OpenSSL command will provide metadata on the certificate like the common name, validity, alternative DNS names
- Requirements for each cerificate are listed on the kubernetes documentation

## Kubernetes Certificates API
- Generating and adding new certificates manually can be hard to keep track of when the cluster users grow
- You can handle these certificate requests using Kubernetes API objects named certificate signing requests, where you provide the CSR encoded in base64
- Once the object is created, you can see certificate signing requests, and approve or deny as needed
- These certificates are now elements in the cluster and can be extracted and used
- This process is handled by the kube-controllermanager cluster element

## KubeConfig
- Running API queries and authenticating with the certs through the HTTP endpoint every time can get tedious
- `kubectl` allows this to work a lot faster
- We can configure a kubectl configuration file with our certificates to speed up the authentication process for requests
- This file is separated between clusters, users and contexts
- Clusters keeps a list of accessible clusters
- Users keeps a lists of users available to the kubectl commands and their credentials
- Contexts keeps a list of what clusters accept what users
- You can configure contexts with additional settings, like switching to a new default namespace

## API Groups
- Kubernetes API endpoints are used to check astatus and to do actions on a cluster, like checking the cluster version, querying logs, or looking at cluster metrics
- `/api` (core group) and `/apis` (named group) control cluster management
- The core group controls core components like namespaces, pods, events, nodes, configmaps or secrets
- The named group stores newer API elements that are added to Kubernetes, like apps, extensions, storage, authentication and certificates
- Inside each we have elements we can use. For example apps has deployments, replicasets and statefulsets, while networking has networkpolicies, or certificates have certificate signing requests
- Each API group (apps, authentication...) has API resources on it (deployments, replicasets...), and each API resources has a set of available actions, named words (list, get, create, delete...)
- Most of these require authentication and authorization. If accessing without it, we will get a Forbidden error as a result of this action

## Authorization
- Authentication defines a user can access the cluster
- Authorization defines what a user can do on the cluster
- This is needed to limit what a user can do on the cluster. A developer does not need permissions to the production namespace, for example
- This also limits impact if a certificate pair is leaked to a malicious third party
- Authorization can be handled by different mechanisms: node-based, attribute-based, role-based or by webhooks
- Node-based authorization allows a kubelet to check and update information about the node it runs on, handled by the node authorizer on the kube-apiserver
- In terms of external access to the cluster, we can handle this by creating a policy definition to a policy file that the kube-apiserver reads as attribute-based access control. Any modification to it requires a restart of the kube-apiserver
- This can be avoided using role-based access control, which allows us to define roles with specific permissions, and associate users and certificates to a role. This is checked with every request, and reflects immediately when modified for changes
- Webhooks are used to delegate access control and authorization to external tools, like Open Policy Agent
- Modes are configured on the authorization mode directive on kube-apiserver and are checked sequentially until one allows access or you run out of authentication modes

## RBAC: Role Bindings
- We first create a role object that specifies what the role is, and what credentials associated with that role can do to what resources
- Each rule definition has 3 elements: apiGroups (what API groups this affects), resources that this applies to, and actions that the authenticated user can take on these resources
- You can have multiple rules for a single role
- To link a user to a role we create a roleBinding, a resource that defines that a user gets the permissions of a specific role
- We can link one or more users or groups to a single role
- Roles and RoleBindings are namespace-scoped, so only apply to the namespace you create them on
- You can also allow access to specific pods, instead of all pods in a namespace, using ResourceName
- you can use `kubectl auth can-i [action] [resource]` to check permissions to a specific actions
- You can apply a ClusterRole like `admin` to a namespaced RoleBinding and it will only apply to the namespace the rolebinding is created on

## RBAC: Cluster Role Bindings
- Roles are namespace-scoped, meaning they are created within namespaces and can only apply to that namespace
- Some resources are not namespace-scoped but cluster-scoped, like nodes, persistent volumes, namespaces or certificate signing requests
- Cluster Roles and Cluster Role bindings are used to authorize users to access cluster-scoped resources
- Work in the same way as roles and rolebindings, but they don't require a namespace declaration
- You can create a clusterrole for namespaced resources as well, and a user will, for example, have access to viewing and creating pods in the entire cluster, not just in a specific namespace

## Kubelet security
- Kubelet is the equivalent of a ship captain. Handles contact with a master ship and schedules containers on the ship
- Communication between the master and the kubelet nodes should be protected to avoid communication issues and private information leakage
- Kubelet handles the state of containers on its node, and can run any container on it as requested
- Kubeadm always has to be installed manually, it will not be installed by kubeadm
- Configuration is stored in the runtime command of the kubelet and in the `kubelet-config.yaml` file
- CLI specifications override the configuration file specifications
- Runtime configuration can be ckecked by looking at what the kubelet process is reading as config file
- The kubelet listens on 2 different ports: one that allows for full access (10250) and one that allows for unauthenticated read-only access (10255)
- We can make sure the kubelet only responds to requests from the kube-apiserver. By default anyone can make requests to the kubelet on port 10250 or 10255, like seeing running pods or getting system logs
- Authentication can limit this by setting the `anonymous-auth` flag to `false` on the kubelet configuration file
- After this is disabled, you can authenticate to accessing the kubelet either with certificate-based or token-based authentication. This needs you to specify the CA that accepts certificates that will query this service with the `client-ca-file` directive
- Authorization allows to set the kubelet up so it will check authorization against the kube-apiserver before responding to a request in case it has a set of permissions that do not allow the request
- You can disable the read-only port by setting its port setting to 0

## kubectl proxy and port-forwarding
- kubectl is used to interact with the cluster without having to authenticate every request manually
- It can access local or remote clusters
- We can also access kube-apiserver directly through port 6443, which requires authentication for every http request
- Another option is to start a proxy with kubectl with the `kubectl proxy` command, which will start a local proxy that listens to HTTP API requests, authenticates them, and forwards them to the kube-apiserver
- This also allows sending requests to any non-exposed service on the cluster by forwarding local ports to Kubernetes service ports 
- This can also be simplified with `kubectl port-forward`, which will forward a local port to a remote kubernetes port within the cluster, with the syntax `kubectl port-forward service/[service or pod name] [local port]:[remote port]`

## Kubernetes dashboard security
- Kubernetes can be managed through a Web UI when installed
- by default not exposed to the public with an ingress
- Accessed with the `kubectl port-forward` utility and requires a token or kubeconfig file to login
- As this has complete cluster access, it needs to be properly secured
- The instructions on the documentation provide a Service Account that will grant admin access to the cluster and should be used with caution
- Limit the permissions granted to the ServiceAccount you create, and its assigned roles and RoleBindings

## Verify platform binaries before deploying
- It is important to verify that the critical Kubernetes binaries have not been compromised
- The checksum hashes can be found on the Kubernetes github releases page
- Check this sha512 calculation with `shasum` to verify if a binary is valid and has not been tampered with

## Cluster upgrade
- It is not mandatory that all kubernetes components are all the same version
- Elements cannot be at a newer version than the kube-apiserver
- controller-manager and kube-scheduler can be 1 version behind
- kubelet and kube-proxy can be 2 versions behind
- kubectl can be one version over or under
- This allows us to upgrade the cluster by parts without interrupting service
- 3 versions are supported at a time: the current version and the two earlier ones
- The recommended approach is upgrading one version at a time
- We can upgrade the cluster with `kubeadm upgrade [plan/apply]`
- First we upgrade the master nodes, then we upgrade the workers
- While the master is down for upgrades, the cluster is still running workloads on worker nodes, we just can't make changes
- When the master is upgraded we can upgrade workers one by one so we keep service unaffected
- We can also add new, already upgraded nodes to the cluster and cordon the old ones, move the workloads to the new nodes and remove the old nodes
- remember the kubelet runs on each node, so you need to ssh into the node to upgrade it
- After an upgrade we need to mark nodes as scheduleable again

## Network policies
- By default all pods in the cluster can communicate with any other pod
- Network policies are objects in Kubernetes that limit network access to and from pods
- Network policies are attached to one or more pods
- We link network policies to pods based on labels
- first we specify the ingress rule on the network policy
- When the network policy is created we tag the pod in a way that it will link the policy to the pod
- Network policies are enforced by your networking provider in the cluster
- Not all support network policies. For example, Flannel does not support network policies
- You can still create network policies even if they are not applied but your network provider

## Ingress
- Service NodePorts require us to use a port over 35000 that has to be in the URL unless you use a proxy
- If we are on a cloud provider we can use a LoadBalancer type Service, which allows the requests to enter through a cloud load balancer that handles routing
- If we add more services, we need more load balancers, which can get expensive, and configuring SSL gets complicated
- Ingresses are scalable layer 7 load balancers that are native to Kubernetes
- Still needs to be exposed through a cloud load balancer, but after that all configuration lives in Kubernetes
- We deploy an ingress controller (nginx, haproxy, traefik), and ingress resources (routing rules)
- Ingress controllers have intelligence built in to detect new rules and resources automatically
- A special build of nginx is used for the nginx ingress controller
- Settings are stored inside a configmap
- We need to provice the namespace, name and ports that the ingress controller will use
- After the ingress controller is created we will add ingress rules, which will route traffic depending on rules like domain name or visited URL
- Kind is Ingress, and on spec we will specify what pod or pods we will target depending on our rules
- We can see these rules with `kubectl get ingress`
- Rules are applied consecutively until one matches

## Docker service configuration
- Kubernetes, as of version 1.23, uses Docker as its underlying container runtime (Deprecated as of Kubernetes 1.24)
- Kubernetes uses the docker daemon to run container
- If the docker daemon is not starting, you can use the `dockerd` (with `--debug` flag optionally) to check for errors
- When docker starts, by default it listens on an internal unix socket for communication between host processes, so it's only accessible from the host, by default `/var/run/docker.sock`
- We can make docker listen on a TCP daemon port (2375 by default) which makes the docker daemon remotely accessible, and the `docker` cli would now be capable of targeting this remote docker machine
- This exposed port is unauthenticated by default and has unencrypted traffic
- Encryption can be enabled with TLS flags and a certificate pair
- This is exposed in the port 2376, instead of the unencrypted 2375
- Either setup on the running command on the service, or store it in `/etc/docker/daemon.json`
- No priority is considered when launching the docker daemon. If you specify debug to be on in the `daemon.json` file and try to launch `dockerd --debug=false`, an error will occur at launch time

## Securing the docker daemon
- An attacker with access to the docker daemon can work with any docker resource in that host
- This attacker could stop and delete containers, exfliltrate or delete data, run their own malicious containers like a cryptominer, or escalate privileges with a privileged container
- They can use this elevated access to target other hosts on the network
- To protect the host that the docker daemon is in remember to disable password-based authentication, enable SSH key pair authentication only, limit root login, and determine which users need access to this machine to limit impact
- Only expose the docker port if absolutely necessary, and protect it with TLS and through a private-facing interface only so it is not internet-facing

# System hardening

## Least privilege principle
- Reducing attack surface is critical to avoid spread of attackers and limit impact
- Limit access to the cluster nodes
- Use RBAC to limit what users can do
- Routinely remove obsolete packages and update software
- Restrict network access to the cluster nodes
- Restrict obsolete and unnecessary kernel modules
- Identify and lock unnecessary open ports

## Limit node access
- Limit exposure of the control plane node to the internet, only allow it through a VPN
- Only give node access to whoever needs it: Administrators probably will, but developers do not need ssh access to nodes
- Limit this SSH access to user accounts for auditing purposes
- Disable root login for users that will not need it

## SSH hardening
- SSH is used to login into remote servers with a shell
- Provide the user and target IP or domain you want to connect to
- Uses password authentication by default, can be insecure
- Disable the password authentication and enable cryptographic key pair authentication only by setting `PasswordAuthentication=no` in the `/etc/ssh/sshd_config` configuration file
- Disable root login through SSH with the flag `PermitRootLogin=no` in the `/etc/ssh/sshd_config` configuration file
- These changes require you to restart the `sshd` daemon to apply them
- Generate a key with `ssh-keygen`
- Copy the generated key with `ssh-copy-id`
- The key is installed in the `authorized_keys` file in the user's home directory under the `.ssh` hidden folder

## Linux privilege escalation
- Some commands on Linux require you to run commands as administrator
- We can use the `sudo` command for this, which allows us to run commands as administrator if allowed
- Users will provide their own password to authenticate to administrator permission level
- Users allowed and their configuration is stored in the `/etc/sudoers` configuration file
- We can limit users to only run certain commands as administrator
- Format for this file is: `[user or group, if it starts with %] [allowed hosts from which the command is allowed]=([users as which the user can run a command as]:[groups as which the user can run a command as]) [NOPASSWD optionally to not require password entry yo tun the command]:[Commands the specified user can run as administrator]`

## Remove obsolete packages and services
- Always recommended to keep systems as light as possible
- Do not include any unnecesary packages, like webservers in a Kubernetes node
- Existing and needed packages need to be updated regularly to avoid vulnerabilities
- Check the running services in the machine
- Disable and stop any unneeded services on the machine

## Restricting kernel modules
- The linux kernel has a modular design capable of dynamically loading new features to the kernel, like loading new graphics drivers into the system
- We can use the `modprobe` to manually load new modules into the kernel
- `lsmod` will list the currently loaded kernel modules
- Kubernetes can load certain networking modules into the kernel when some sockets are created
- Blacklist unnecesary modules to prevent them from loading, like the `scte` and `dccp` modules
- to blacklist them, add a line like `blacklist sctp` to the `/etc/modprobe.d/blacklist.conf` configuration file
- After adding the blacklist, reboot the node and check that the module is unloaded

## Identifying and disabling open ports
- Some of the unwanted processes running in the sytem can open ports giving access to an unnecessary service
- This is a potential security risk which should be avoided, so these ports need to be disabled
- Check for open ports with `netstat -an | grep LISTEN` to check for listening ports
- You can check what a port is used for with the `/etc/services` file, which states known port numbers and their purpose
- Identify which process is listening on the port, if it is needed, and stop the process if you see fit
- Kubernetes necessary ports are listed in the official documentation
- Different Kubernetes distributions might require different ports, like Openshift or Rancher

## Minimize IAM roles
- When using public cloud to host Kubernetes access is handled by IAM, or Identity and Access Management
- You should limit what these users can do on your cloud environment by applying the principle of least privilege
- Give only the required permissions to users, nothing more

## Restrict network access
- Services listening on external ports are accessible by any source by default if listening on the external-facing interface
- Limit who can connect to these sockets with a firewall
- Many levels of firewall can be used. If machine-level control is needed, use a software firewall like `ufw`
- Cloud providers have their own implementations for this, like virtual appliances or security groups

## UFW basics
- `ufw` is a software firewall implemented in ubuntu
- the command line interface allows the implementation of simple rules
- Uses `iptables` as a backend
- When enabled, all ports are closed by default unless manually allowed
- Rules allow fine control over sources, like only allowing SSH access from an SSH jump host's IP address, or only allowing webserver access for local IP ranges
- the firewall is disabled by default on install. We will add rules before enabling it
- Allow all **outgoing** connections by default with `ufw default allow outgoing`
- Deny all **incoming** connections by default with `ufw default deny incoming`
- Add allow rules as needed with the format `ufw allow from [Source IP range, can be "any"] to [target interfaces, can be "any"] port [target port] proto [tcp/udp]`
- To sepcifically deny a certain port from any source, use `ufw deny [port]`, though this is unnecessary as we block connections by default
- To apply these rules run `ufw enable`
- Make sure your rules will not block your connection to the target host
- Check your firewall status with `ufw status`
- To delete a specific rule, use `ufw delete [rule]`, for example from our last example, `ufw delete deny 8080`
- You can also use the line number. To delete the third rule, use `ufw delete 3`

## Linux syscalls
- The kernel handles communication between the hardware and system processes
- Communication is separated between userspace (where user applications run) and kernelspace (where the kernel works with kernel code and device drivers)
- When a userspace application wants to write to a file, they will make a system call to the kernel that will tell it to execute the binary that will write to disk and memory
- the `strace` utility is useful to ckeck the system calls a process runs by putting it before a command, like `strace touch /tmp/test.txt`
- The output will give us information about the syscall used, the command that was executed, the array of arguments passed to the command, and the environment variables inherited by the system call
- You can also `strace` a running command by providing the PID of the running process: `strace -p [PID]`

## Aquasec Tracee
- Tool used to trace system calls from a container
- Requires certain bind mounts to a container and some privileged capabilities to work properly
- This allows to trace a specific command for syscalls, or to trace all syscalls in a host system based on its processes
- You can also trace the syscalls of containers in the system, which will allow us to debug specific containers and their syscalls

## Restrict syscalls with seccomp
- We can allow programs to use only certain syscalls
- There are around 435 different syscalls in the kernel available
- Having programs be able to use them all increases our attack surface and can be limited
- seccomp, or secure computing, is a linux kernel feature that allows us to limit what syscalls a program can make to the kernel
- you can check if seccomp is enabled on your kernel with the pertinent kernel file under `/boot/config-[kernel name]` as the variables `CONFIG_SECCOMP`, `CONFIG_SECCOMP_FILTER` and `CONFIG_HAVE_ARCH_SECCOMP_FILTER`
- We can check if a process has seccomp enabled by looking for `Seccomp` on the `/proc/[Process ID]/status` file
- A value of `2` means seccomp is enabled on the process
- modes can be 0 (disabled), 1 (strict, only allows read, write and exit), and 2 (selectively filters syscalls)
- Docker has a built-in seccomp filter that it uses by default for containers if not specififed
- Allows about 60 of the linux syscalls by default for containers and blocks others like rebooting, mounting filesystems or loading kernel modules
- You can either identify the needed seccomp capabilities needed and whitelist them, or blacklist the seccomp capabilities that you may not want. The first one is more secure, the second option is simpler
- You can use custom seccomp policies at a container level to restrict or allow kernel syscalls as needed without modifying the defaults
- you can use `seccomp=unconfined` to enable all syscalls in a container, but this is considered very insecure
- Even then, docker has some security guardrails that still prevent certain syscalls

## Seccomp in Kubernetes
- By default Docker locks syscalls with seccomp by default, however, Kubernetes does not
- you can use the `amicontained` docker image to check what a container is capable of by default or with the applied profile, by running `docker run r.j3ss.co/amicontained amicontained`
- the same can be found by running this contained in a Kubernetes pod
- We can use a pod definition snippet to set seccomp profiles for a pod, which can be the default definition provided by docker, or a local seccomp definition file, which must be relative to `/var/lib/kubelet/seccomp/`
- We can also disallow privilege escalation on a pod, which is not set by default
- If a syscall needed to run is not available, the container will fail with code `ContainerCannotRun`

## AppArmor
- Seccomp allows big scale actions, like not allowing filesystem actions
- This does not allow for fine-grained control like restricting specific directories
- For that we need to use AppArmor, a Linux security module installed on most Linux systems
- Check if it is installed and running with `systemctl status apparmor`
- Needs to load the apparmor kernel module on the nodes where a container will run
- This can be ckecked by looking for a `Y` on the `/sys/module/apparmor/parameters/enabled` file or with `aa-status`
- AppArmor loads profiles into the kernel to apply security controls
- Check loaded profiles on the `/sys/kernel/security/apparmor/profiles` file
- Profiles are text files that define what resources an application can access
- Check the current status of AppArmor with `aa-status`
- Profiles can be loaded in 3 modes: enforce (monitors and enforces rules to any application fitting the profile), complain (allows the actions but logs them as events to a log) and unconfined (allows any task and does not log the events)

## Creating AppArmor profiles
- AppArmor profiles can look complex to write from scratch
- Instead of manually creating profiles, we can use `apparmor-utils` to use some tools that simplify the process
- We can use `aa-genprof` to generate a profile that will fit an application. For example, `aa-genprof add_data.sh` will create a profile by looking into what the application does and building a profile from that
- We will then get questions about what events apparmor needs to allow or deny, and we will create the profile accordingly
- When finished and saved, the new profile will be loaded in enforce mode, and is stored under `/etc/apparmor.d/`
- To load new apparmor profiles, run `apparmor_parser [apparmor profile file]`. If nothing is returned, the profile loaded successfully
- To unload a profile, do the same but with the `-R` flag, then symlink the script to the disable folder, like `ln -s /etc/apparmor.d/[profile] /etc/apparmor.d/disable/`

## AppArmor in Kubernetes
- Apparmor is supported in Kubernetes 1.23
- This requires worker nodes to have apparmor enabled to work
- the container runtime should have apparmor support for this feature to work
- A profile that will be used needs to first be loaded in all nodes where the pod can be scheduled
- The profile is applied at a acontainer level with an annotation on the pod definition file

## Linux capabilities
- Linux processes are classified as privileged or unprivileged
- Unprivileged processses run as UID non-zero and have set restrictions that the privileged containers do not have
- We can give unprivileged containers some kernel capabilities to allow some of the privileged tools it might need without giving them all
- To check what capabilities a command needs we can make use of `getcap [binary]`, like `getcap /usr/bin/ping`
- We can also check the capabilities of a running process with `getpcaps [process ID]`
- Capabilities can be added to and dropped from a container with a declaration to its definition

# Minimize microservice vulnerabilities

## Security contexts
- Used to define a set of security standards for Kubernetes resources, instead of at a container level
- This standard at a pod level will carry down into the container level
- To specify it we add the securityContext block under the spec in the pod definition
- Capabilities are only supported on the container level, not pod level

## Admission controllers
- Until now, we've ran commands against kube-apiserver
- When a request gets to kube-apiserver it goes through authentication with certificate pairs
- User also goes through authorization to know if they can perform that action, with role-based access control
- Limited to kubernetes resources, we cannot go beyond, like reviewing what image is being used and only wanting tagged images, or enforcing certain labels
- This is what admission controllers provide, better security and consistency control in resources
- Control values like rate limiting request, setting the default storage class for certain resources, checking if a namespace exists
- Admission controllers handle sanity ckecks like if the namespce exists, or decisions like if the namespace should be created. This last one is not enabled by default
- Check the enabled admission controllers with `kube-apiserver -h | grep enable-admission-plugins` (run it inside the kube-apiserver pod if you installed the cluster with kubeadm)
- To enable new admission controllers, add them to the startup command of kube-apiserver, either in the system service or in the static pod manifest
- You can disable admission controllers in the same way with the disable admission controllers flag

## Validating and Mutating admission controllers
- The admission controllers which for example check if a namespace exists before creating a pod are validating admission controller
- Another type is mutating admission controllers, like DefaultStorageClass. It changes data on definitions
- For example if a storage class is not set, it will be modified to be equal to the default storage class
- There may be admission controllers that do both types
- Generally mutating admission controllers are applied first, and validating admission controllers second, so any mutated change can be then validated
- If any admission controller returns an error in the chain, the request is rejected
- We can write our own admission controllers with admission webhooks
- We will run an admission webhook server with our own logic, which gets admission review json objects to test
- When the request is checked, it returns an admission review json which validates or rejects the request
- After setting the server up we will create a Kubernetes element targeting the webhook server that gets called based on the rules we specify

## Pod security policies
- Some dangerous configurations can be added to containers, like running as privileged user with UID 0, or adding root kernel capabilities
- These are security vulnerabilities we should avoid
- We can policy this with pod security policies, which callow us to not admit pods being created with certain pod configurations
- This is enabled as an admission controller named PodSecurityPolicy
- Compares a request against a set of rules, and if it isn't accepted, it will not create the pod
- We can create our own pod security policy objects inside Kubernetes as a resource, which will apply against every pod creation request
- Before enabling the admission controller we need to create an element that can access pod security policies by default
- We will first need to grant a role and rolebinding that allow default serviceaccounts to access pod security policies

## Open Policy Agent
- Handles authorization for user actions
- Absatracts authorization logic from your applications
- OPA verifies authorization requests and returns the result to your application to handle
- First we will run an OPA server, then we load configuration rules into it to validate
- Written in its own format called Rego policy format
- Has several modules available to work with your applications, like HTTP requests and responses
- Handles checking input values conditionally to check if they are met 
- We can remotely provide rules for OPA by sending a PUT request referring to the rule file
- THe HTTP API can also show currently loaded rules
- When a rule is loaded we can just make a call to OPA from our application and send a POST request to it to apply the rules
- OPA will verify the request and return either authorized or unauthorized in json, and your app will handle this response as you see fit

## Open Policy Agent in Kubernetes
- Used to implement advanced levels of restrictions in Kubernetes policies
- Instead of building a webhook server and writing validation logic we can connect Open Policy Agent to Kubernetes to replace custom admission controllers
- We can deploy OPA in Kubernetes and point the admission controllers to its service
- OPA has its own package module to check kubernetes admission requests natively with our rules
- An example is to only allow images that come from trusted registries and deny any other image
- OPA only has information about the newly created objects, not about the already existing objects by default
- If we need other data from Kubernetes we can import a package to get Kubernetes information about existing resources like pods, and use it in our comparation ruleset
- OPA gets this information from kube-management, which is deployed as a sidecar to OPA to pull cluster information from Kubernetes
- We can create OPA policies as configmaps inside Kubernetes and kube-management will automatically load them into OPA
- Deployed as a deployment and service in the opa namespace, to which we will target our validating webhooks
- The newer version of deploying OPA is using OPA Gatekeeper

## Managing Kubernetes secrets
- We should avoid storing values like passwords in plain text in our application
- We can store users and hosts in a ConfigMap, like a mysql target host
- This should not be used for sensitive information like passwords
- Secrets store data in an encoded format
- Secrets are only sent to nodes that need it and are not written to disk, only memory
- When using a declarative approach we must provide them in an encoded format using `echo -n '[secret]' | base64`
- Secrets can be attached to pods to be used as environment variables with `envFrom` into a pod container
- We can mount an entire configmap as environment variables, a single value, or all the configmap separated into files, as a volume, a file for each secret entry

## Container sandboxing
- Virtual machines run their own Operating System with a dedicated kernel
- This is very isolated between virtual machines
- Containers however share the same kernel
- From the host, a container is just another process
- The host can see all processes on all containers
- The container can only see its own processes, because they have their own process namespace
- Containers all make system calls to the same shared kernel, which can be used to escape the container and get into the host, which is a very important security breach
- For this we need container sandboxing, which is a set of techniques used to isolate resources from other processes
- Examples are apparmor, seccomp, and privilege limitation
- If we run a lot of different containers with different purposes, maintaining seccomp profiles will get very complicated

## gVisor
- Tool made by Google that filters syscalls before a container gets to the kernel
- When a program wants to make a syscall, it is actually making a call to gVisor
- It acts as a sort of "proxy" between the container and the kernel
- The main component is Sentry, an application-level "kernel" written for the container
- Intercepts and responds to system calls
- Components implement access to certain critical resources, like Gofer which is used to access filesystem files
- Uses its own network stack, isolated from the operating system's kernel-level networking
- Each container has its own dedicated gVisor kernel component
- Not all applications will work with gVisor, you need to test it and check if it suits your workload 

## kata containers
- Another way of container isolation
- Kata separates each container into its own lightweight virtual machine with its own kernel
- If a single container abuses its resources, only that container will fail, while the rest stay unaffected
- Virtual machines from Kata are light and performance-focused
- Even then the machines will use some more resources than a bare container does
- Requires nested virtualization on your virtual machine

## Runtime classes
- Docker is just an API frontend to run containers with backend container runtimes like containerd and runc
- kata containers and gVisor use their own continer runtimes
- As these runtimes are OCI-compatible, we can use docker commands to run kata or gVisor containers seamlessly

## Using runtimes in Kubernetes
- Runtimes are controlled in Kubernetes using Runtime classes
- After creating the runtime class (`runsc` for gVisor, `kata` for Kata) we can run containers with it
- The runtime needs to be installed in the node where the container will run
- To specify the runtime we just add the runtime class name to the pod definition file
- If we run a pod with gVisor and check the system processes from the host, we will not see the container processes, as it is using an isolated kernel to run them now

## One way SSL vs Mutual SSL
- The usual, default mode of TLS is one-way TLS, where the client verifies the server certificate
- This solution does not verify the client certificate, it validates your identity in other ways like passwords and email
- Mutual TLS is used to verify client identity as well, like in a communication between two banks, where it is important that the client bank is verified to act on the second bank
- The same certificate process is followed both ways to verify TLS, as both act as clients and as servers in the exchange

## Pod to pod encryption with mTLS
- By default, data transfer between pods is unencrypted
- This is open to an attacker sniffing communications, like sniffing a password from a webserver-to-database pod to pod communication
- To avoid this we implement mTLS or Mutual TLS in pod-to-pod communication
- Mutual authentication allows pods to validate their identity and make sure an attacker cannot pass for a target and look into traffic
- This could be handled app by app, but handling encryption mismatches in a lot of applications will get complicated
- We handle this mTLS communication with third party programs, like `istio` and `linkerd` which we use as a service mesh
- `istio` handles this communication with a sidecar container which sends and recieves encrypted data, decrypts it and passes it to the main container
- External apps not communicating with the `istio` sidecar in TLS mode can still work by sending unencrypted traffic, if the `istio` sidecar is configured to handle it
- Alternatively, we can configure it to only accept mTLS traffic, which is more secure, but it may break some applications

# Supply chain security

## Minimize base image footprint
- Base container images should be as small as possible
- Avoid installed software that you do not need
- Avoid potentially vulnerable software that you may need to maintain
- Control what images are your containers based on and what software they include
- Containers should be ephimeral and scalable
- Data should be stored outside of the container, like in a volume
- Use the best suiting parent image for your purpose, like if you're building a webserver, use the `httpd` image
- Keep your images up to date for vulnerability patching frequently
- Use images that are as slim and minimal as possible
- Use multi-stage builds so Docker can reuse as much layers as possible to keep storage under control

## Image security
- If a registry is not specified, an image will be pulled from the default registry configured
- By default images are pulled from `library` on docker hub, maintained by the Docker team
- If using internal images that should not be publicly available, we should pull these images from the private registry while logged in to the private registry
- Kubernetes needs a full image name including the registry, and for us to provide an image pull secret to the pod with the name `regcred`

## Whitelist allowed registries
- A vulnerable or malicious image hosted on an external registry is a potential security risk
- We want to control what registry images can be pulled from
- Disallow any unneeded registries to avoid this vulnerability
- This can be handled by admission controllers or Open Policy Agent services
- We can also use an internal admission controller, `ImagePolicyWebhook` to handle this easier
- Authentication for this webhook is handled by a kubeconfig file
- The webhook needs to be enabled in the `kube-apiserver` configuration, as it is not enabled by default
- We also need to provide this kubeconfig admission control config file for the kube-apiserver

## Static analysis of user workloads
- We may want to enforce security standards before a file is applied
- Static analysis allows us to compare a declarative file against a set of standards
- KubeSec is an example of a tool that can do this job
- Helps analyzing a resource and will warn of potential security issues, and score it, while it suggests fixes for your security issue
- Scan files with `kubesec scan [yaml definition file]`
- You can also run kubesec as a webserver to paste yaml files in it

## Scan images for known vulnerabilities
- Known vulnerabilities are kept in databases like the CVE registry
- Applications leverage this CVE database as open data to scan software and containers
- Unchecked vulnerabilities can allow an attacker to infiltrate your system, escalate privileges, steal data and cause a lot of problems
- Vulnerabilities are rated in criticality based on impact. A higher number means higher impact on your system data and availability
- It is important to keep track of what our platforms and applications use and if we need to patch any vulnerabilities
- Trivy is a simple and comprehebsive container vulnerability scanner that can be integrated with CI/CD pipelines
- We scan an image by running `trivy image [image]`, which will output a result in the terminal with the vulnerability scan about the image
- We can filter by severity levels, or check what vulnerabilities can we fix by just updating the software version
- We can also scan tar archives of images
- Keep best practices of always scanning new images, using admission controllers to scan images, keep a repository of scanned and known good images, and integrate this scanning into your CI/CD pipeline

# Monitoring, Logging and Runtime Security

## Behavioral analytics of syscall processes
- We need observability into what happens in the cluster to monitor for anomalous events
- Information is key to understand an attack, like access logs, CPU and RAM usage, or cluster audit logs and workload changes
- Notifications and alerts are key to respond as quickly as possible to incidents
- Resource limitations can help in avoiding resources being used up by one rogue workload
- These techniques all contribute to limiting attack reach and severity
- An example of an extensive event monitoring tool is Falco, which can monitor and analyze suspicious behaviors and alert about them

## Falco overview
- Falco needs to see what applications are asking to the system kernel, so it needs to run between containers and the kernel
- Falco can monitor the kernel through eBPF, which is a safer and less intrusive monitoring option
- Falco will monitor library usage and analyze this usage with policy rules through its internal policy engine
- This information can then be sent to an alert channel
- Falco will need to be installed as a host package into every cluster node and start its service
- Falco being isolated from Kubernetes is useful in case of a breach, because a Kubernetes problem will not affect its monitoring capabilities
- Falco can also be executed as a DaemonSet, available through Helm

## Using Falco to detect threats
- After Falco is running we will need to start adding rules to it so it can monitor suspicious behavior
- Some default rules exist on Falco's DaemonSet, like an alert for a shell running in a container, for which it will provide timestamp, namespace, command executed, and target pod where the command ran. Another example of alert is someone attempting to read the `/etc/shadow` file
- The Falco rules file is configured in a yaml format
- Contains Falco's rules (we can sate names, descriptions, conditions, output and priority), lists to help us in rule condition simplification, and macros which are expressions that can be reused in several rules to avoid code repetition

## Falco configuration
- The Falco configuration file is located by default at `/etc/falco/falco.yaml`
- Rules are loaded from a rules file list, to which we can add new custom rules as we see fit
- Events are logged as text by default, but can be logged in `json`
- We can set the minimum priority required to be logged into the Falco alert logs
- We can set output channels where Falco will send alert findings. By default it sends to standard output, but it can also log to external services like Slack, or send to an arbitrary http endpoint
- To apply Falco configuration changes we need to reload the configuration file
- We can reload the Falco configuration without restarting the service by sending a `SIGHUP` to the Falco process's PID

## Mutable vs Immutable infrastructure
- A piece of infastructure being mutable means it can change over time
- This deviation can be dangerous, for example if we miss some dependencies in a server
- This will turn into an issue when deploying changes, as some may fail
- An approach with immutable infrastructure means that the servers never internally change, and when we need to apply a change, the servers are just replaced with the new version so they never need to be updated or modified
- This approach avoids configuration drift
- This is a good approach for containers: containers themselves don't change internally and are ephimeral, and when we need a big change applied, we replace the container with the new version
- An attacker could use a mutable container to keep their own code running unnoticed, as immutability is not ensured

## Ensure immutability of containers at runtime
- We have several ways of making Kubernetes ensure our pods keep a state of immutability
- We can make sure that we cannot write to the container filesystem to avoid changes by setting the read only root filesystem
- Just adding this field may break the application running in the container if it needs to write to certain directories, like cache or log files
- We will make use of volumes to specify directories that will be considered mounts, which will allow for writing
- Another example is if we try to run the container as privileged and try to make some changes, like changing the swappiness of the SWAP, which is a pseudo-filesystem, will change regardless and in this case affect the host swappiness, even though we set the root filesystem as read-only
- We can enforce this by using pod security policies

## Audit logs and access monitoring
- Kubernetes can hold auditing events when an operations is executed
- this is handled by `kube-apiserver`, as all requests have to go through it
- We want to monitor only specific events that we care about
- We set this with audit policy objects, which specify under what rules are events logged, from what namespace do we want to monitor events, what objects, and for what operations. We can even monitor events for a specific resource name
- Auditing is disabled by default
- We need to configure the `kube-apiserver` component to use this log, like a local pathm and specify the audit policy file we want to use
- We can specify log control flags, like setting how many days of logs we want to retain, and how many logs we want to keep or how big they can be

# Useful bookmarks 
- [Create a ServiceAccount](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server)
- [Add a ServiceAccount to a pod](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server)
- [Create a Certificate Signing Request](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#create-certificatesigningrequest)
- [Approve or deny a Certificate Signing Request](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#approval-rejection-kubectl)
- [Create a Role](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-example)
- [Create a RoleBinding](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-example)
- [RoleBinding/ClusterRoleBinding subject examples](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-binding-examples)
- [Create a ClusterRole](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#clusterrole-example)
- [Create a ClusterRoleBinding](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#clusterrolebinding-example)
- [Check authorizations to a specific action](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access)
- [Check the Kubernetes API through kubectl proxy](https://kubernetes.io/docs/tasks/extend-kubernetes/http-proxy-access-api/#using-kubectl-to-start-a-proxy-server)
- [ort-forward local ports to pod/service ports](https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/#forward-a-local-port-to-a-port-on-the-pod)
- [Deploy the Kubernetes dashboard UI](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/?ref=hackernoon.com#deploying-the-dashboard-ui)
- [Access the Kubernetes dashboard UI](https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/?ref=hackernoon.com#command-line-proxy)
- [Source code release reference](https://kubernetes.io/releases/)
- [Upgrade a Kubernetes cluster](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/#upgrading-control-plane-nodes)
- [Network Policy example](https://kubernetes.io/docs/concepts/services-networking/network-policies/#networkpolicy-resource)
- [Network policy selectors](https://kubernetes.io/docs/concepts/services-networking/network-policies/#behavior-of-to-and-from-selectors)i
- [Create an ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/#the-ingress-resource)
- [Add a default backend](https://kubernetes.io/docs/concepts/services-networking/ingress/#resource-backend)
- [Disable SSL forcing, to allow ingress access in the env (some examples fail without it set to `false` by default)](https://github.com/kubernetes/ingress-nginx/blob/e9c297e74dd20601a7bec89b86d36e75d323c5ce/docs/user-guide/tls.md#server-side-https-enforcement-through-redirect)
- [Kubelet seccomp local profile location](https://kubernetes.io/docs/tutorials/security/seccomp/#create-a-local-kubernetes-cluster-with-kind)
- [Use the underlying container runtime's default seccomp configuration](https://kubernetes.io/docs/tutorials/security/seccomp/#create-pod-that-uses-the-container-runtime-default-seccomp-profile)
- [Add a seccomp profile to a pod definition](https://kubernetes.io/docs/tutorials/security/seccomp/#create-pod-with-seccomp-profile-that-causes-violation)
- [Useful apparmor commands](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation#manuals)
- [Create an AppArmor profile](https://gitlab.com/apparmor/apparmor/-/wikis/Profiling_with_tools#basic-process)
- [Load an AppArmor profile](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Failures#updating-the-policy)
- [Add an AppArmor profile to a pod](https://kubernetes.io/docs/tutorials/security/apparmor/#example)
- [Disable an AppArmor profile](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Failures#disabling-the-profile)
- [Set pod-level security context values](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod)
- [Set container-level security context values](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-container)
- [Set container-level capabilities](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [Check which admission controllers are on by default](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#which-plugins-are-enabled-by-default)
- [Enable admission controllers for kube-apiserver](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#how-do-i-turn-on-an-admission-controller)
- [Disable admission controllers for kube-apiserver](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#how-do-i-turn-off-an-admission-controller)
- [Create a TLS secret](https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets)
- [Authorize service accounts to check and use pod security policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#via-rbac)
- [Create a pod security policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#create-a-policy-and-a-pod)
- [Value reference for pod security policies](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#policy-reference)
- [Create a configmap from a file (useful for rego configmap generation)](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/#create-configmaps-from-files)
- [Imperatively create a secret for env variables](https://kubernetes.io/docs/concepts/configuration/secret/#use-case-pods-with-prod-test-credentials)
- [Declaratively create a secret for env variables](https://kubernetes.io/docs/concepts/configuration/secret/#use-case-as-container-environment-variables)
- [Attach secret as environment variables to a container (all the entries)](https://kubernetes.io/docs/concepts/configuration/secret/#use-case-as-container-environment-variables)
- [Attach a single secret into a container as an env variable](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables)
- [Mounting secrets as a volume to a container (all the entries)](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod)
- [Create a runtime class](https://kubernetes.io/docs/concepts/containers/runtime-class/#2-create-the-corresponding-runtimeclass-resources)
- [Use the runtime class on a pod](https://kubernetes.io/docs/concepts/containers/runtime-class/#usage)
- [Create a private registry secret](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/#create-a-secret-by-providing-credentials-on-the-command-line)
- [Add the pull secret to a pod definition](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/#create-a-pod-that-uses-your-secret)
- [Install trivy](https://aquasecurity.github.io/trivy/v0.22.0/getting-started/installation/)
- [Scan a docker image with trivy](https://aquasecurity.github.io/trivy/v0.22.0/vulnerability/scanning/image/#container-images)
- [Scan a tarball of a docker image with Trivy](https://aquasecurity.github.io/trivy/v0.22.0/vulnerability/scanning/image/#tar-files)
- [Filter output by severity](https://aquasecurity.github.io/trivy/v0.22.0/misconfiguration/options/filter/#by-severity)
- [Save trivy output as json](https://aquasecurity.github.io/trivy/v0.22.0/vulnerability/examples/report/#json)
- [Install Falco](https://falco.org/docs/getting-started/installation/)
- [Falco rules documentation](https://falco.org/docs/rules/)
- [Hot reload Falco configuration](https://falco.org/docs/getting-started/running/#hot-reload)
- [Possible values for immutability, like read-only rootfs](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Set read-only root filesystem for immutability](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-container)
- [Add EmptyDir volume for immutability workaround](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir-configuration-example)
- [Write a Kubernetes audit policy](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-policy)
- [Add the Audit policy to kube-apiserver and mount it in](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#log-backend)
