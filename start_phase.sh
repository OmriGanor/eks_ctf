#!/usr/bin/env bash
TEAM=$1
PHASE=$2

if [ -z "$TEAM" ] || [ -z "$PHASE" ]; then
    echo "Usage: $0 <team> <phase>"
    echo "Example: $0 team-a 2"
    exit 1
fi

echo "Starting Phase $PHASE for team $TEAM"

# Deploy Kubernetes challenges for the team
helm upgrade ${TEAM} ctf/player \
     --reuse-values            \
     --set playerName=${TEAM} \
     --set phase=${PHASE}

# Update CTFd challenge visibility for the new phase
if [ -f "manage_ctf_phases.py" ]; then
    echo "Updating CTFd challenge visibility for Phase $PHASE..."
    python3 manage_ctf_phases.py $PHASE
else
    echo "Warning: manage_ctf_phases.py not found. CTFd challenges not updated."
    echo "You may need to manually update challenge visibility in CTFd."
fi

echo "Phase $PHASE started for team $TEAM"
