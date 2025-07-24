#!/usr/bin/env bash

# Configuration from bootstrap_cluster_wide_components.sh
export CLUSTER=platformctf_limbo
export REGION=eu-west-1

# Check if team name is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <team-name>"
    echo "Example: $0 team-alpha"
    echo "         $0 team-bravo"
    exit 1
fi

TEAM=$1

echo "Creating CTF environment for team: $TEAM"

# Deploy the team's Kubernetes namespace and challenges
helm upgrade --install $TEAM ./player --set playerName=$TEAM --create-namespace
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

# 2.1  IAM role that the API server trusts
echo "Creating IAM role: ctf-${TEAM}"
aws iam create-role \
  --role-name ctf-${TEAM} \
  --assume-role-policy-document '{
      "Version":"2012-10-17",
      "Statement":[{
        "Effect":"Allow",
        "Principal":{"AWS":"*"},
        "Action":"sts:AssumeRole"
      }]
    }'

# 2.2  Map that role to an RBAC username inside the cluster
echo "Creating EKS IAM identity mapping"
eksctl create iamidentitymapping \
  --cluster  $CLUSTER \
  --region   $REGION \
  --arn      arn:aws:iam::${ACCOUNT}:role/ctf-${TEAM} \
  --username $TEAM \
  --group    ctf-players

# 2.3  Lightweight IAM **user** that can assume the role
echo "Creating IAM user: ctf-user-${TEAM}"
aws iam create-user --user-name ctf-user-${TEAM}

# Create the policy document with proper variable substitution
POLICY_DOC='{
     "Version":"2012-10-17",
     "Statement":[{
         "Effect":"Allow",
         "Action":"sts:AssumeRole",
         "Resource":"arn:aws:iam::'${ACCOUNT}':role/ctf-'${TEAM}'"
     }]
   }'

aws iam put-user-policy --user-name ctf-user-${TEAM} --policy-name AssumeTeamRole --policy-document "$POLICY_DOC"
CREDS=$(aws iam create-access-key --user-name ctf-user-${TEAM})

# 2.4  Generate a kubeconfig that hard‑codes the role‑arn
echo "Generating kubeconfig file"
aws eks update-kubeconfig                \
     --name $CLUSTER                     \
     --region $REGION                    \
     --role-arn arn:aws:iam::${ACCOUNT}:role/ctf-${TEAM} \
     --alias ${TEAM}                     \
     --kubeconfig kubeconfig_${TEAM}

# 2.5  Pin the default namespace in that file
kubectl --kubeconfig kubeconfig_${TEAM} config set-context ${TEAM} --namespace=${TEAM}

# 2.6  Hand over: provide kubeconfig + the JSON creds block from $CREDS
zip ${TEAM}_bundle.zip kubeconfig_${TEAM}

echo ""
echo "✅ Team $TEAM environment created successfully!"
echo ""
echo "📦 Team bundle: ${TEAM}_bundle.zip"
echo "🔑 AWS Access Keys:"
echo "$CREDS"
echo ""
echo "export AWS_ACCESS_KEY_ID=<from_admin> export AWS_SECRET_ACCESS_KEY=<from_admin> export AWS_DEFAULT_REGION=eu-west-1"
echo "kubectl --kubeconfig kubeconfig_team-a get pods"
echo "Send ${TEAM}_bundle.zip plus the AWS keys above securely to the team."
