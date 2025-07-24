TEAM=team-a                       # <‑‑ loop this block for every team

# Deploy the team's Kubernetes namespace and challenges
helm upgrade --install $TEAM ./player --set playerName=$TEAM --create-namespace
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

# 2.1  IAM role that the API server trusts
aws iam create-role \
  --role-name ctf-${TEAM} \
  --assume-role-policy-document '{
      "Version":"2012-10-17",
      "Statement":[{
        "Effect":"Allow",
        "Principal":{"AWS":"*"},              # we’ll constrain via the user below
        "Action":"sts:AssumeRole"
      }]
    }'

# 2.2  Map that role to an RBAC username inside the cluster
eksctl create iamidentitymapping \
  --cluster  $CLUSTER \
  --region   $REGION \
  --arn      arn:aws:iam::'"$ACCOUNT"':role/ctf-'"$TEAM" \
  --username $TEAM \
  --group    ctf-players                # any K8s group you like :contentReference[oaicite:0]{index=0}

# 2.3  Lightweight IAM **user** that can assume the role
aws iam create-user --user-name ctf-user-${TEAM}
aws iam put-user-policy   --user-name ctf-user-${TEAM} --policy-name AssumeTeamRole \
  --policy-document '{
     "Version":"2012-10-17",
     "Statement":[{
         "Effect":"Allow",
         "Action":"sts:AssumeRole",
         "Resource":"arn:aws:iam::'"$ACCOUNT"':role/ctf-'"$TEAM"'"
     }]
   }'
CREDS=$(aws iam create-access-key --user-name ctf-user-${TEAM})

# 2.4  Generate a kubeconfig that hard‑codes the role‑arn
aws eks update-kubeconfig                \
     --name $CLUSTER                     \
     --region $REGION                    \
     --role-arn arn:aws:iam::${ACCOUNT}:role/ctf-${TEAM} \
     --alias ${TEAM}                     \
     --kubeconfig kubeconfig_${TEAM}     :contentReference[oaicite:1]{index=1}

# 2.5  Pin the default namespace in that file
kubectl --kubeconfig kubeconfig_${TEAM} config set-context ${TEAM} --namespace=${TEAM}

# 2.6  Hand over: provide kubeconfig + the JSON creds block from $CREDS
zip ${TEAM}_bundle.zip kubeconfig_${TEAM}
echo "Send ${TEAM}_bundle.zip plus these AWS keys securely to the team."
