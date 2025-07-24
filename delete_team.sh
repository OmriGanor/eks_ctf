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

echo "🗑️  Deleting CTF environment for team: $TEAM"
echo ""

# Confirmation prompt
read -p "Are you sure you want to delete ALL resources for $TEAM? This cannot be undone. (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Deletion cancelled."
    exit 0
fi

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
ERRORS=0

echo "Starting cleanup..."

# 1. Delete Helm deployment
echo "🔄 Deleting Helm deployment..."
if helm uninstall $TEAM --namespace $TEAM 2>/dev/null; then
    echo "✅ Helm deployment deleted"
else
    echo "❌ Failed to delete Helm deployment (may not exist)"
    ((ERRORS++))
fi

# Wait a moment for namespace cleanup
sleep 5

# 2. Delete namespace if it still exists
echo "🔄 Deleting namespace..."
if kubectl delete namespace $TEAM --ignore-not-found=true; then
    echo "✅ Namespace deleted"
else
    echo "⚠️  Namespace may not exist or failed to delete"
fi

# 3. Delete IAM identity mapping
echo "🔄 Removing EKS IAM identity mapping..."
if eksctl delete iamidentitymapping \
  --cluster $CLUSTER \
  --region $REGION \
  --arn arn:aws:iam::${ACCOUNT}:role/ctf-${TEAM} 2>/dev/null; then
    echo "✅ IAM identity mapping removed"
else
    echo "❌ Failed to remove IAM identity mapping (may not exist)"
    ((ERRORS++))
fi

# 4. Delete access keys for the user
echo "🔄 Deleting IAM user access keys..."
ACCESS_KEYS=$(aws iam list-access-keys --user-name ctf-user-${TEAM} --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
if [ -n "$ACCESS_KEYS" ]; then
    for key in $ACCESS_KEYS; do
        if aws iam delete-access-key --user-name ctf-user-${TEAM} --access-key-id $key 2>/dev/null; then
            echo "✅ Access key $key deleted"
        else
            echo "❌ Failed to delete access key $key"
            ((ERRORS++))
        fi
    done
else
    echo "ℹ️  No access keys found for user"
fi

# 5. Delete user policy
echo "🔄 Deleting IAM user policy..."
if aws iam delete-user-policy --user-name ctf-user-${TEAM} --policy-name AssumeTeamRole 2>/dev/null; then
    echo "✅ User policy deleted"
else
    echo "❌ Failed to delete user policy (may not exist)"
    ((ERRORS++))
fi

# 6. Delete IAM user
echo "🔄 Deleting IAM user..."
if aws iam delete-user --user-name ctf-user-${TEAM} 2>/dev/null; then
    echo "✅ IAM user deleted"
else
    echo "❌ Failed to delete IAM user (may not exist)"
    ((ERRORS++))
fi

# 7. Delete IAM role
echo "🔄 Deleting IAM role..."
if aws iam delete-role --role-name ctf-${TEAM} 2>/dev/null; then
    echo "✅ IAM role deleted"
else
    echo "❌ Failed to delete IAM role (may not exist)"
    ((ERRORS++))
fi

# 8. Clean up local files
echo "🔄 Cleaning up local files..."
FILES_DELETED=0

if [ -f "kubeconfig_${TEAM}" ]; then
    rm "kubeconfig_${TEAM}"
    echo "✅ Deleted kubeconfig_${TEAM}"
    ((FILES_DELETED++))
fi

if [ -f "${TEAM}_bundle.zip" ]; then
    rm "${TEAM}_bundle.zip"
    echo "✅ Deleted ${TEAM}_bundle.zip"
    ((FILES_DELETED++))
fi

if [ $FILES_DELETED -eq 0 ]; then
    echo "ℹ️  No local files found to clean up"
fi

echo ""
echo "🏁 Cleanup completed for team: $TEAM"

if [ $ERRORS -eq 0 ]; then
    echo "✅ All resources successfully deleted!"
else
    echo "⚠️  Completed with $ERRORS errors (some resources may not have existed)"
fi

echo ""
echo "Summary of deleted resources:"
echo "- Helm deployment: $TEAM"
echo "- Kubernetes namespace: $TEAM"
echo "- IAM role: ctf-${TEAM}"
echo "- IAM user: ctf-user-${TEAM}"
echo "- EKS IAM identity mapping"
echo "- Local files: kubeconfig_${TEAM}, ${TEAM}_bundle.zip" 