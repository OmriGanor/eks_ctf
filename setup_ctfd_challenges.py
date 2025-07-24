#!/usr/bin/env python3
"""
Script to automatically create CTFd challenges for the Kubernetes CTF.
Run this after deploying CTFd to populate it with your challenges.

Usage:
    python3 setup_ctfd_challenges.py --url http://your-ctfd-url --username admin --password admin
    
Flags are loaded from Helm deployments. All teams use the same flags:
    python3 setup_ctfd_challenges.py --url http://your-ctfd-url --username admin --password admin
"""

import requests
import yaml
import click
import sys
import os
from pathlib import Path
from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class Challenge(BaseModel):
    """Pydantic model for CTF challenge definition"""
    name: str
    category: str
    description: str
    value: int = Field(gt=0, description="Point value must be positive")
    type: str = "standard"
    hints: List[str] = Field(default_factory=list)
    flag_key: str = Field(description="Key to look up flag values")


# Challenge definitions based on your Kubernetes challenges
CHALLENGES = [
    Challenge(
        flag_key="warmup",
        name="Warmup",
        category="Kubernetes Basics", 
        description="""Welcome to the Kubernetes CTF! Your team has been given access to a Kubernetes cluster.

Start by exploring your namespace and find the deployment that's running.
Check the logs of the pod to find your first flag.

Commands to get started:
- `kubectl get pods`
- `kubectl logs <pod-name>`""",
        value=50,
        hints=[
            "Look for a deployment called 'warmup'",
            "Check the container logs for output"
        ]
    ),
    Challenge(
        flag_key="leakySecret",
        name="Leaky Secret",
        category="RBAC & Secrets",
        description="""There's a secret in your namespace that contains a flag, but you can't read it directly.
However, you have been granted special permissions to "watch" secrets.

Use kubectl to monitor changes to secrets and capture the flag.

Hint: Check the secret's annotation for guidance.""",
        value=100,
        hints=[
            "You can only WATCH secrets, not GET them",
            "Use `kubectl get secrets` to find the secret name",
            "Try `kubectl get secret <name> --watch`"
        ]
    ),
    Challenge(
        flag_key="misScopedSA",
        name="Token Theft",
        category="Service Accounts",
        description="""Service accounts in Kubernetes have tokens that can be used for authentication.
Find a way to access a service account token that gives you elevated privileges.""",
        value=150,
        hints=[
            "Look for service accounts in your namespace",
            "Service account tokens are mounted in pods"
        ]
    ),
    Challenge(
        flag_key="netpol101",
        name="Network Policy Bypass",
        category="Network Security",
        description="""Network policies control traffic between pods. Find a way to bypass 
the network restrictions to reach a protected service.""",
        value=200,
        hints=[
            "Check what network policies exist",
            "ICMP traffic might be handled differently"
        ]
    ),
    Challenge(
        flag_key="sillyCSI",
        name="Host Path Escape",
        category="Storage & Volumes",
        description="""A custom CSI driver has been deployed. Investigate how you can 
abuse it to access the host filesystem.""",
        value=250,
        hints=[
            "Look for custom storage classes",
            "CSI drivers can expose host paths"
        ]
    ),
    Challenge(
        flag_key="trivialJob",
        name="Controller Compromise",
        category="Custom Resources",
        description="""A custom controller has been deployed for TrivialJob resources.
Find a way to exploit this controller to gain elevated access.""",
        value=300,
        hints=[
            "Custom resources might have CRDs",
            "Controllers often run with elevated privileges"
        ]
    ),
    Challenge(
        flag_key="podEscape",
        name="Kernel Space Access",
        category="Container Escape",
        description="""Break out of your container constraints and access the underlying 
kernel space to find the flag.""",
        value=400,
        hints=[
            "Look for privileged containers",
            "Host namespaces can provide escape routes"
        ]
    ),
    Challenge(
        flag_key="escalation",
        name="Cluster Admin",
        category="Privilege Escalation",
        description="""Achieve cluster-admin privileges through any means necessary.
The ultimate flag awaits those who can take control of the entire cluster.""",
        value=500,
        hints=[
            "Chain together previous vulnerabilities",
            "Look for service accounts with cluster-wide permissions"
        ]
    )
]




class CTFdAPI:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
        self.login(username, password)

    def login(self, username, password):
        """Login to CTFd and get session token"""
        # Get login page to get nonce
        login_page = self.session.get(f"{self.base_url}/login")
        if login_page.status_code != 200:
            raise Exception(f"Failed to access login page: {login_page.status_code}")

        # Extract CSRF token from login page
        import re
        csrf_match = re.search(r"'csrfNonce':\s*[\"']([^\"']+)[\"']", login_page.text)
        if not csrf_match:
            raise Exception("Could not find CSRF token in login page")
        
        csrf_token = csrf_match.group(1)

        login_data = {
            'name': username,
            'password': password,
            'nonce': csrf_token
        }

        resp = self.session.post(f"{self.base_url}/login", data=login_data)
        print(f"Login response status: {resp.status_code}")
        print(f"Login response URL: {resp.url}")
        print(f"Login response headers: {dict(resp.headers)}")
        
        if resp.status_code != 200 or 'login' in resp.url:
            print(f"Login response text: {resp.text[:500]}")
            raise Exception("Login failed")

        print("Successfully logged in to CTFd")

    def create_challenge(self, challenge: Challenge, flag_values: List[str]) -> Optional[int]:
        """Create a challenge via CTFd API with multiple flag variants"""
        challenge_data = {
            'name': challenge.name,
            'category': challenge.category,
            'description': challenge.description,
            'value': challenge.value,
            'type': challenge.type,
            'state': 'visible'
        }

        # Create the challenge
        resp = self.session.post(f"{self.base_url}/api/v1/challenges",
                                 json=challenge_data)

        if resp.status_code != 200:
            print(f"Failed to create challenge {challenge.name}: {resp.status_code} - {resp.text}")
            return None

        challenge_id = resp.json()['data']['id']
        print(f"Created challenge: {challenge.name} (ID: {challenge_id})")

        # Add all flag variants (one per team)
        for flag_value in flag_values:
            flag_data = {
                'challenge': challenge_id,
                'content': flag_value,
                'type': 'static'
            }

            flag_resp = self.session.post(f"{self.base_url}/api/v1/flags",
                                          json=flag_data)

            if flag_resp.status_code != 200:
                print(f"Failed to add flag {flag_value} for {challenge.name}: {flag_resp.status_code}")
            else:
                print(f"Added flag for {challenge.name}: {flag_value}")

        # Add hints if provided
        for hint_text in challenge.hints:
            hint_data = {
                'challenge': challenge_id,
                'content': hint_text,
                'cost': 0  # Free hints
            }

            hint_resp = self.session.post(f"{self.base_url}/api/v1/hints",
                                          json=hint_data)

            if hint_resp.status_code != 200:
                print(f"Failed to add hint for {challenge.name}: {hint_resp.status_code}")
            else:
                print(f"Added hint for {challenge.name}: {hint_text[:30]}...")

        return challenge_id


def load_flags_from_helm(team_name: str = None) -> Dict[str, str]:
    """Load flag values from any team's Helm deployment (all teams now have identical flags)"""
    # Try to find any deployed team if none specified
    if not team_name:
        try:
            import subprocess
            result = subprocess.run(['helm', 'list', '-q'], capture_output=True, text=True)
            if result.returncode == 0:
                releases = result.stdout.strip().split('\n')
                # Look for team releases (exclude game/platform releases)
                team_releases = [r for r in releases if r.startswith('team-') and r != '']
                if team_releases:
                    team_name = team_releases[0]
                    print(f"Auto-detected team deployment: {team_name}")
        except Exception:
            pass
    
    if team_name:
        try:
            import subprocess
            result = subprocess.run(['helm', 'get', 'values', team_name, '--all'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                values = yaml.safe_load(result.stdout)
                flags = values.get('flags', {})
                if flags:
                    print(f"Loaded flags from Helm deployment: {team_name}")
                    return flags
        except Exception as e:
            print(f"Warning: Failed to get Helm values for {team_name}: {e}")
    
    raise Exception("No Helm deployment found with flags. Please deploy at least one team first.")


def setup_challenges(ctfd: CTFdAPI, team_name: Optional[str] = None) -> None:
    """Set up challenges using flags from Helm deployment"""
    print("Setting up CTF challenges...")
    flags = load_flags_from_helm(team_name)

    for challenge in CHALLENGES:
        flag_value = flags.get(challenge.flag_key, f"CTF{{{challenge.flag_key.upper()}}}")
        ctfd.create_challenge(challenge, [flag_value])


@click.command()
@click.option('--url', required=True, help='CTFd instance URL (e.g., http://localhost:8000)')
@click.option('--username', required=True, help='CTFd admin username')
@click.option('--password', required=True, help='CTFd admin password')
@click.option('--team', help='Specific team deployment to load flags from (optional - will auto-detect if not provided)')
def main(url: str, username: str, password: str, team: Optional[str]):
    """Create CTFd challenges for the Kubernetes CTF.
    
    Flags are always loaded from Helm deployments. All teams use the same flags.
    
    Examples:
        # Auto-detect team deployment and load flags
        python3 setup_ctfd_challenges.py --url http://localhost:8000 --username admin --password admin
        
        # Load flags from specific team deployment
        python3 setup_ctfd_challenges.py --url http://localhost:8000 --username admin --password admin --team team-alpha
    """
    
    # Initialize CTFd API client
    try:
        ctfd = CTFdAPI(url, username, password)
    except Exception as e:
        print(f"Failed to connect to CTFd: {e}")
        sys.exit(1)

    # Setup challenges
    try:
        setup_challenges(ctfd, team)
        print("\nAll challenges created successfully!")
        print(f"Visit {url} to see your challenges")
        print("\nNote: All teams use the same flags and compete for the same challenges.")
    except Exception as e:
        print(f"Failed to setup challenges: {e}")
        print("\nMake sure you have deployed at least one team using:")
        print("helm upgrade --install team-NAME ./player --set playerName=team-NAME --create-namespace")
        sys.exit(1)


if __name__ == "__main__":
    main()
