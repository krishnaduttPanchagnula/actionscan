<!-- source: https://www.checkov.io/5.Policy%20Index/github_actions.html -->
<!-- fetched: 2026-10-22T12:41:24Z via curl text-extract -->

github_actions resource scans - checkov 
 Checkov home 
 Docs 
 Quick start 
 Overview 
 Integrations 
 Download 
 Docs 
 Quick start 
 Overview 
 Integrations 
 Checkov Documentation 
 1.Welcome 
 What is Checkov? 
 Terms and Concepts 
 Quick Start 
 Feature Descriptions 
 Migration 
 2.Basics 
 Installing Checkov 
 CLI Command Reference 
 Suppressing and Skipping Policies 
 Hard and soft fail 
 Scanning Credentials and Secrets 
 Reviewing Scan Results 
 Visualizing Checkov Output 
 Handling Variables 
 3.Custom Policies 
 Custom Policies Overview 
 Python Custom Policies 
 YAML Custom Policies 
 Custom YAML Policies Examples 
 Sharing Custom Policies 
 4.Integrations 
 Jenkins 
 Bitbucket Cloud Pipelines 
 GitHub Actions 
 GitLab CI 
 Kubernetes 
 Pre-Commit Hooks 
 Docker 
 5.Policy Index 
 all resource scans 
 ansible resource scans 
 argo_workflows resource scans 
 arm resource scans 
 azure_pipelines resource scans 
 bicep resource scans 
 bitbucket_configuration resource scans 
 bitbucket_pipelines resource scans 
 circleci_pipelines resource scans 
 cloudformation resource scans 
 dockerfile resource scans 
 github_actions resource scans (auto generated) 
 github_configuration resource scans 
 gitlab_ci resource scans 
 gitlab_configuration resource scans 
 kubernetes resource scans 
 openapi resource scans 
 secrets resource scans 
 serverless resource scans 
 terraform resource scans 
 6.Contribution 
 Checkov Runner Contribution Guide 
 Implementing CI Metadata extractor 
 Implementing ImageReferencer 
 Contribution Overview 
 Contribute Python-Based Policies 
 Contribute YAML-based Policies 
 Contribute New Terraform Provider 
 Contribute New Argo Workflows configuration policy 
 Contribute New Azure Pipelines configuration policy 
 Contribute New Bitbucket configuration policy 
 Contribute New GitHub configuration policy 
 Contribute New Gitlab configuration policy 
 7.Scan Examples 
 Terraform Plan Scanning 
 Terraform Scanning 
 Helm 
 Kustomize 
 AWS SAM configuration scanning 
 Ansible configuration scanning 
 Argo Workflows configuration scanning 
 Azure ARM templates configuration scanning 
 Azure Pipelines configuration scanning 
 Azure Bicep configuration scanning 
 Bitbucket configuration scanning 
 AWS CDK configuration scanning 
 Cloudformation configuration scanning 
 Dockerfile configuration scanning 
 GitHub configuration scanning 
 Gitlab configuration scanning 
 Kubernetes configuration scanning 
 OpenAPI configuration scanning 
 SCA scanning 
 Serverless framework configuration scanning 
 8.Outputs 
 CSV 
 CycloneDX BOM 
 GitLab SAST 
 JUnit XML 
 SARIF 
 Docs 
 5.policy index
 github_actions resource scans
 Edit on GitHub
 github_actions resource scans (auto generated)
 Id 
 Type 
 Entity 
 Policy 
 IaC 
 Resource Link 
 0 
 CKV_GHA_1 
 jobs 
 jobs 
 Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS isn’t true on environment variables 
 github_actions 
 AllowUnsecureCommandsOnJob.py 
 1 
 CKV_GHA_1 
 jobs 
 jobs.*.steps[] 
 Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS isn’t true on environment variables 
 github_actions 
 AllowUnsecureCommandsOnJob.py 
 2 
 CKV_GHA_2 
 jobs 
 jobs 
 Ensure run commands are not vulnerable to shell injection 
 github_actions 
 ShellInjection.py 
 3 
 CKV_GHA_2 
 jobs 
 jobs.*.steps[] 
 Ensure run commands are not vulnerable to shell injection 
 github_actions 
 ShellInjection.py 
 4 
 CKV_GHA_3 
 jobs 
 jobs 
 Suspicious use of curl with secrets 
 github_actions 
 SuspectCurlInScript.py 
 5 
 CKV_GHA_3 
 jobs 
 jobs.*.steps[] 
 Suspicious use of curl with secrets 
 github_actions 
 SuspectCurlInScript.py 
 6 
 CKV_GHA_4 
 jobs 
 jobs 
 Suspicious use of netcat with IP address 
 github_actions 
 ReverseShellNetcat.py 
 7 
 CKV_GHA_4 
 jobs 
 jobs.*.steps[] 
 Suspicious use of netcat with IP address 
 github_actions 
 ReverseShellNetcat.py 
 8 
 CKV_GHA_5 
 jobs 
 jobs 
 Found artifact build without evidence of cosign sign execution in pipeline 
 github_actions 
 CosignArtifacts.py 
 9 
 CKV_GHA_6 
 jobs 
 jobs 
 Found artifact build without evidence of cosign sbom attestation in pipeline 
 github_actions 
 CosignSBOM.py 
 10 
 CKV_GHA_7 
 jobs 
 on 
 The build output cannot be affected by user parameters other than the build entry point and the top-level source location. GitHub Actions workflow_dispatch inputs MUST be empty. 
 github_actions 
 EmptyWorkflowDispatch.py 
 11 
 CKV2_GHA_1 
 resource 
 permissions 
 Ensure top-level permissions are not set to write-all 
 github_actions 
 ReadOnlyTopLevelPermissions.yaml 
 Powered By
 Slack Community 
 Prisma Cloud 
 Terms of use 
 GitHub 
 Docs 
 Privacy policy
