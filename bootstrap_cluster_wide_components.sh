export CLUSTER=platformctf_limbo
export REGION=eu-west-1

# 1.1  (safety) deny wildcard RBAC except system namespaces
#kubectl apply -f cluster/baseline/cluster-network-deny.yaml

# 1.2  Install TrivialJob CRD + controller (phase‑2 payload lives in kube‑system)
# kubectl apply -f challenges/phase2/crd-trivialjob.yaml
# kubectl apply -f challenges/phase2/trivialjob-controller.yaml

# # 1.3  Deploy Silly‑CSI DaemonSet (harmless until a team requests its StorageClass)
# kubectl apply -f challenges/phase2/silly-csi-driver.yaml

# 1.4  Deploy the game chart (includes CTFd as subchart) in namespace ctfd
helm dependency update game/
helm -n ctfd upgrade --install --create-namespace platformctf ./game

