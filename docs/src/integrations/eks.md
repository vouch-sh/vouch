# EKS (Kubernetes)

This chapter describes how Vouch integrates with Amazon EKS for Kubernetes authentication, chaining through AWS credential issuance.

## Configuration

```
~/.kube/config:
  users:
  - name: vouch-my-cluster
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: aws
        args: ["eks", "get-token", "--cluster-name", "my-cluster"]
        env:
        - name: AWS_PROFILE
          value: vouch-my-cluster

How it works:
1. kubectl calls aws eks get-token via exec credential plugin
2. AWS CLI uses credential_process to call vouch credential aws
3. vouch exchanges access token for OIDC token, calls STS AssumeRoleWithWebIdentity
4. AWS CLI uses the temporary credentials to get an EKS bearer token
5. kubectl presents token to EKS API server
6. EKS validates via IAM and Access Entries for RBAC
```

## Setup

**`vouch setup eks` creates:**
- AWS profile in `~/.aws/config` with `credential_process` pointing to vouch
- Kubeconfig user and context configured to use `aws eks get-token`
- No cluster-side OIDC configuration needed — uses IAM-based auth via EKS Access Entries

## EKS Access Entries Setup

```bash
# Grant IAM role access to the EKS cluster
aws eks create-access-entry \
  --cluster-name my-cluster \
  --principal-arn arn:aws:iam::123456789:role/vouch-developer \
  --type STANDARD

# Associate an access policy
aws eks associate-access-policy \
  --cluster-name my-cluster \
  --principal-arn arn:aws:iam::123456789:role/vouch-developer \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy \
  --access-scope type=cluster
```
