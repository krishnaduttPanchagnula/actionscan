<!-- source: https://trivy.dev/latest/docs/ecosystem/cicd/ -->
<!-- fetched: 2026-10-22T12:41:13Z via curl text-extract -->

CI/CD - Trivy 
 Skip to content
You're not viewing the latest version of the documentation.
 Click here to go to latest. 
 Trivy
 CI/CD
 Initializing search
 GitHub
 Home
 Getting Started
 Tutorials
 User Guide
 Ecosystem
 Contributing
 Enterprise
 Trivy
 GitHub
 Home
 Getting Started
 Getting Started
 First steps
 Installation
 Signature Verification
 FAQ
 Tutorials
 Tutorials
 Overview
 CI/CD
 CI/CD
 Overview
 GitHub Actions
 CircleCI
 Travis CI
 GitLab CI
 Bitbucket Pipelines
 AWS CodePipeline
 AWS Security Hub
 Azure
 Kubernetes
 Kubernetes
 Cluster Scanning
 Kyverno
 GitOps
 Misconfiguration
 Misconfiguration
 Terraform scanning
 Custom Checks with Rego
 Signing
 Signing
 Vulnerability Scan Record Attestation
 Shell
 Shell
 Completion
 Additional Resources
 Additional Resources
 Additional Resources
 Community References
 CKS Reference
 User Guide
 User Guide
 Overview
 Target
 Target
 Container Image
 Filesystem
 Rootfs
 Code Repository
 Virtual Machine Image
 Kubernetes
 SBOM
 Scanner
 Scanner
 Vulnerability
 Misconfiguration
 Misconfiguration
 Overview
 Configuration
 Policy
 Policy
 Built-in Checks
 Custom Checks
 Custom Checks
 Overview
 Data
 Combine
 Selectors
 Schemas
 Testing
 Debugging Policies
 Contribute Checks
 Secret
 License
 Cryptographic Asset
 Coverage
 Coverage
 Overview
 OS
 OS
 Overview
 AlmaLinux
 Alpine Linux
 Amazon Linux
 Azure Linux (CBL-Mariner)
 Bottlerocket
 CentOS
 Chainguard
 CoreOS
 Debian
 Echo
 MinimOS
 Oracle Linux
 Photon OS
 Red Hat
 Rocky Linux
 SUSE
 Ubuntu
 Wolfi
 Google Distroless (Images)
 Language
 Language
 Overview
 C/C++
 Dart
 .NET
 Elixir
 Go
 Java
 Julia
 Node.js
 PHP
 Python
 Ruby
 Rust
 Swift
 IaC
 IaC
 Overview
 Ansible
 Azure ARM Template
 CloudFormation
 Docker
 Helm
 Kubernetes
 Terraform
 Others
 Others
 Overview
 ActiveState Images
 Bitnami Images
 Conda
 RapidFort Images
 Root.io Images
 Seal Security
 RPM Archives
 Kubernetes
 Configuration
 Configuration
 Overview
 Filtering
 Selecting Files
 Reporting
 Cache
 Databases
 Others
 Supply Chain
 Supply Chain
 SBOM
 Attestation
 Attestation
 SBOM
 Cosign Vulnerability Scan Record
 SBOM Attestation in Rekor
 VEX
 VEX
 Overview
 VEX Repository
 Local VEX Files
 VEX SBOM Reference
 VEX Attestation
 Compliance
 Compliance
 Built-in Compliance
 Custom Compliance
 Plugins
 Plugins
 Overview
 User guide
 Developer guide
 Advanced
 Advanced
 Modules
 Connectivity and Network considerations
 Self-Hosting Trivy's Databases
 Container Image
 Container Image
 Embed in Dockerfile
 Unpacked container image filesystem
 Private Docker Registries
 Private Docker Registries
 Overview
 Docker Hub
 AWS ECR (Elastic Container Registry)
 GAR (Google Artifact Registry)
 ACR (Azure Container Registry)
 Self-Hosted
 Usage Telemetry
 References
 References
 Configuration
 Configuration
 CLI
 CLI
 Overview
 Clean
 Config
 Convert
 Filesystem
 Image
 Kubernetes
 Module
 Module
 Module
 Module Install
 Module Uninstall
 Plugin
 Plugin
 Plugin
 Plugin Info
 Plugin Install
 Plugin List
 Plugin Run
 Plugin Uninstall
 Plugin Update
 Plugin Upgrade
 Plugin Search
 Registry
 Registry
 Registry
 Registry Login
 Registry Logout
 Repository
 Rootfs
 SBOM
 Server
 Version
 VEX
 VEX
 VEX
 VEX Download
 VEX Init
 VEX List
 VEX Repo
 VM
 Config file
 Modes
 Modes
 Standalone
 Client/Server
 Compatibility and Stability
 Troubleshooting
 Terminology
 Abbreviations
 Ecosystem
 Ecosystem
 Overview
 CI/CD
 CI/CD
 Table of contents
 Azure DevOps (Official)
 GitHub Actions
 trivy-action (Official)
 trivy-action (Community)
 trivy-github-issues (Community)
 Buildkite Plugin (Community)
 Dagger (Community)
 Semaphore (Community)
 CircleCI (Community)
 Woodpecker CI (Community)
 Concourse CI (Community)
 SecObserve GitHub actions and GitLab templates (Community)
 IDE and Dev tools
 Production and Clouds
 Reporting
 Contributing
 Contributing
 Principles
 How to contribute
 How to contribute
 Issues
 Discussions
 Pull Requests
 Contribute Rego Checks
 Contribute Rego Checks
 Overview
 Add Service Support
 Contribute Vulnerability Data Sources
 Contribute Vulnerability Data Sources
 Overview
 Add Vulnerability Advisory Source
 Maintainer
 Maintainer
 PR Review
 Release Flow
 Backporting
 Help Wanted
 Triage
 Enterprise
 Enterprise
 Comparison
 Contact Us
 Table of contents
 Azure DevOps (Official)
 GitHub Actions
 trivy-action (Official)
 trivy-action (Community)
 trivy-github-issues (Community)
 Buildkite Plugin (Community)
 Dagger (Community)
 Semaphore (Community)
 CircleCI (Community)
 Woodpecker CI (Community)
 Concourse CI (Community)
 SecObserve GitHub actions and GitLab templates (Community)
 CI/CD Integrations ¶ 
 Azure DevOps (Official) ¶ 
 Azure Devops is Microsoft Azure cloud native CI/CD service.
 Trivy has a "Azure Devops Pipelines Task" for Trivy, that lets you easily introduce security scanning into your workflow, with an integrated Azure Devops UI.
 👉 Get it at: https://github.com/aquasecurity/trivy-azure-pipelines-task 
 GitHub Actions ¶ 
 GitHub Actions is GitHub's native CI/CD and job orchestration service.
 trivy-action (Official) ¶ 
 GitHub Action for integrating Trivy into your GitHub pipeline
 👉 Get it at: https://github.com/aquasecurity/trivy-action 
 trivy-action (Community) ¶ 
 GitHub Action to scan vulnerability using Trivy. If vulnerabilities are found by Trivy, it creates a GitHub Issue.
 👉 Get it at: https://github.com/marketplace/actions/trivy-action 
 trivy-github-issues (Community) ¶ 
 In this action, Trivy scans the dependency files such as package-lock.json and go.sum in your repository, then create GitHub issues according to the result.
 👉 Get it at: https://github.com/marketplace/actions/trivy-github-issues 
 Buildkite Plugin (Community) ¶ 
 The trivy buildkite plugin provides a convenient mechanism for running the open-source trivy static analysis tool on your project. 
 👉 Get it at: https://github.com/equinixmetal-buildkite/trivy-buildkite-plugin 
 Dagger (Community) ¶ 
 Dagger is CI/CD as code that runs anywhere.
 The Dagger module for Trivy provides functions for scanning container images from registries as well as Dagger Container objects from any Dagger SDK (e.g. Go, Python, Node.js, etc).
 👉 Get it at: https://daggerverse.dev/mod/github.com/jpadams/daggerverse/trivy 
 Semaphore (Community) ¶ 
 Semaphore is a CI/CD service.
 You can use Trivy in Semaphore for scanning code, containers, infrastructure, and Kubernetes in Semaphore workflow.
 👉 Get it at: https://docs.semaphore.io/using-semaphore/recipes/trivy 
 CircleCI (Community) ¶ 
 CircleCI is a CI/CD service.
 You can use the Trivy Orb for Circle CI to introduce security scanning into your workflow.
 👉 Get it at: https://circleci.com/developer/orbs/orb/fifteen5/trivy-orb 
Source: https://github.com/15five/trivy-orb 
 Woodpecker CI (Community) ¶ 
 Example Trivy step in pipeline
 pipeline:
 securitycheck:
 image: aquasec/trivy:latest
 commands:
 # use any trivy command, if exit code is 0 woodpecker marks it as passed, else it assumes it failed
 - trivy fs --exit-code 1 --skip-dirs web/ --skip-dirs docs/ --severity MEDIUM,HIGH,CRITICAL .
 Woodpecker does use Trivy itself so you can see it in use there .
 Concourse CI (Community) ¶ 
 Concourse CI is a CI/CD service.
 You can use Trivy Resource in Concourse for scanning containers and introducing security scanning into your workflow.
It has capabilities to fail the pipeline, create issues, alert communication channels (using respective resources) based on Trivy scan output.
 👉 Get it at: https://github.com/Comcast/trivy-resource/ 
 SecObserve GitHub actions and GitLab templates (Community) ¶ 
 SecObserve GitHub actions and GitLab templates run various vulnerability scanners, providing uniform methods and parameters for launching the tools.
 The Trivy integration supports scanning Docker images and local filesystems for vulnerabilities as well as scanning IaC files for misconfigurations.
 👉 Get it at: https://github.com/SecObserve/secobserve_actions_templates 
 Previous
 Overview
 Next
 IDE and Dev tools
