export CLUSTER=platformctf_limbo
export REGION=eu-west-1

helm dependency update game/
helm -n ctfd upgrade --install --create-namespace platformctf ./game

