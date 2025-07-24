#!/usr/bin/env bash

# Configuration - Update these for your CTFd instance
CTFD_URL="${CTFD_URL:-http://your-ctfd-url}"
CTFD_USERNAME="${CTFD_USERNAME:-admin}"
CTFD_PASSWORD="${CTFD_PASSWORD:-admin}"

TEAM=$1
PHASE=$2

if [ -z "$TEAM" ] || [ -z "$PHASE" ]; then
    echo "Usage: $0 <team> <phase>"
    echo "Example: $0 team-a 2"
    echo ""
    echo "CTFd Configuration:"
    echo "  Set CTFD_URL, CTFD_USERNAME, CTFD_PASSWORD environment variables"
    echo "  or update the defaults at the top of this script"
    echo ""
    echo "Current CTFd URL: $CTFD_URL"
    exit 1
fi

# Check if CTFd configuration is still default
if [ "$CTFD_URL" = "http://your-ctfd-url" ]; then
    echo "Warning: CTFd URL is not configured. Please set CTFD_URL environment variable"
    echo "or update the script configuration. Skipping CTFd integration."
    SKIP_CTFD=true
fi

echo "Starting Phase $PHASE for team $TEAM"

# Deploy Kubernetes challenges for the team
helm upgrade ${TEAM} ctf/player \
     --reuse-values            \
     --set playerName=${TEAM} \
     --set phase=${PHASE}

# Update CTFd challenge visibility for the new phase
if [ -f "manage_ctf_phases.py" ] && [ "$SKIP_CTFD" != "true" ]; then
    echo "Updating CTFd challenge visibility for Phase $PHASE..."
    python3 manage_ctf_phases.py \
        --url "$CTFD_URL" \
        --username "$CTFD_USERNAME" \
        --password "$CTFD_PASSWORD" \
        --phase "$PHASE"
else
    if [ "$SKIP_CTFD" = "true" ]; then
        echo "Skipping CTFd update due to configuration issue."
    elif [ ! -f "manage_ctf_phases.py" ]; then
        echo "Warning: manage_ctf_phases.py not found. CTFd challenges not updated."
    fi
    echo "You may need to manually update challenge visibility in CTFd."
fi

echo "Phase $PHASE started for team $TEAM"
