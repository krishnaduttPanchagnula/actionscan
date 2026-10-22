<!-- source: https://www.checkov.io/4.Integrations/GitHub%20Actions.html -->
<!-- fetched: 2026-10-22T12:41:23Z via curl text-extract -->

GitHub Actions - checkov 
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
 Integrate Checkov with GitHub Actions 
 Use a Checkov Action from the Marketplace 
 Create Your Own Action: Basic Set-up 
 Example Results 
 Action Failure 
 Pipeline Success 
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
 github_actions resource scans 
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
 4.integrations
 GitHub Actions
 Edit on GitHub
 Integrate Checkov with GitHub Actions
 Integrating Checkov into GitHub Actions provides a simple, automatic way of applying policies to your Terraform code both during pull request review and as part of any build process.
 Use a Checkov Action from the Marketplace
 Check out our pre-made action .
 Create Your Own Action: Basic Set-up
 Add a new step in the workflow.yml .
 ├───.github
│ └───workflows
 Here is a basic example:
 --- 
 name : Checkov 
 on : 
 push : 
 branches : 
 - master 
 jobs : 
 build : 
 runs-on : ubuntu-latest 
 steps : 
 - uses : actions/checkout@v2 
 - name : Set up Python 3.9 
 uses : actions/setup-python@v4 
 with : 
 python-version : 3.9 
 - name : Test with Checkov 
 id : checkov 
 uses : bridgecrewio/checkov-action@master 
 with : 
 directory : example/examplea 
 framework : terraform 
 Example Results
 Any time after you push your code to GitHub, it will run your job. If Checkov finds any errors, it will fail the build.
 Action Failure
 In the original examples code, the file aws_efs_file_system.sharedstore.tf is not set to encrypted:
 resource "aws_efs_file_system" "sharedstore" { 
 creation_token = var . efs [ "creation_token" ] 
 lifecycle_policy { 
 transition_to_ia = var . efs [ "transition_to_ia" ] 
 } 
 kms_key_id = var . efs [ "kms_key_id" ] 
 encrypted = false 
 performance_mode = var . efs [ "performance_mode" ] 
 provisioned_throughput_in_mibps = var . efs [ "provisioned_throughput_in_mibps" ] 
 throughput_mode = var . efs [ "throughput_mode" ] 
 } 
 This will fail a Checkov test:
 Pipeline Success
 The previous error can be fixed by setting the value of encryption to true .
 Read more details on using Python in GitHub Actions. 
 Powered By
 Slack Community 
 Prisma Cloud 
 Terms of use 
 GitHub 
 Docs 
 Privacy policy
