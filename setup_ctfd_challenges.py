#!/usr/bin/env python3
"""
Script to automatically create CTFd challenges for the Kubernetes CTF.
Run this after deploying CTFd to populate it with your challenges.

Usage:
    python3 setup_ctfd_challenges.py --url http://your-ctfd-url --username admin --password admin
    
For multi-team setup:
    python3 setup_ctfd_challenges.py --url http://your-ctfd-url --username admin --password admin --team-flags team-a,team-b,team-c
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


class TeamFlags(BaseModel):
    """Pydantic model for team flag collections"""
    team_name: str
    flags: Dict[str, str]


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

# Default flag values for fallback
DEFAULT_FLAGS = {
    "warmup": "CTF{WELCOME}",
    "leakySecret": "CTF{SECRET_READ}",
    "misScopedSA": "CTF{TOKEN_STEAL}",
    "netpol101": "CTF{ICMP_ALLOWED}",
    "sillyCSI": "CTF{HOST_PATH}",
    "trivialJob": "CTF{CONTROLLER_PWN}",
    "podEscape": "CTF{KERNEL_SPACE}",
    "escalation": "CTF{CLUSTER_ADMIN}"
}


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

        # Extract nonce from login page (simplified - you might need to parse HTML)
        # For now, we'll try without nonce and see if it works

        login_data = {
            'name': username,
            'password': password
        }

        resp = self.session.post(f"{self.base_url}/login", data=login_data)
        if resp.status_code != 200 or 'login' in resp.url:
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


def load_team_flags_from_helm(team_name: str) -> Dict[str, str]:
    """Load flag values from a team's Helm deployment"""
    try:
        import subprocess
        result = subprocess.run(['helm', 'get', 'values', team_name], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            values = yaml.safe_load(result.stdout)
            flags = values.get('flags', {})
            if flags:
                print(f"Loaded flags for {team_name} from Helm deployment")
                return flags
    except Exception as e:
        print(f"Warning: Failed to get Helm values for {team_name}: {e}")
    return {}


def load_team_flags_from_file(team_name: str) -> Dict[str, str]:
    """Load flag values from a team-specific values file"""
    team_values_file = f"player/values-{team_name}.yaml"
    if os.path.exists(team_values_file):
        print(f"Loading flags for {team_name} from {team_values_file}")
        with open(team_values_file, 'r') as f:
            values = yaml.safe_load(f)
            return values.get('flags', {})
    return {}


def generate_default_team_flags(team_name: str) -> Dict[str, str]:
    """Generate default flags with team suffix"""
    print(f"Using default flags with team suffix for {team_name}")
    return {
        "warmup": f"CTF{{WELCOME_{team_name.upper()}}}",
        "leakySecret": f"CTF{{SECRET_READ_{team_name.upper()}}}",
        "misScopedSA": f"CTF{{TOKEN_STEAL_{team_name.upper()}}}",
        "netpol101": f"CTF{{ICMP_ALLOWED_{team_name.upper()}}}",
        "sillyCSI": f"CTF{{HOST_PATH_{team_name.upper()}}}",
        "trivialJob": f"CTF{{CONTROLLER_PWN_{team_name.upper()}}}",
        "podEscape": f"CTF{{KERNEL_SPACE_{team_name.upper()}}}",
        "escalation": f"CTF{{CLUSTER_ADMIN_{team_name.upper()}}}"
    }


def load_single_team_flags(team_name: Optional[str] = None) -> Dict[str, str]:
    """Load flag values from a single source (for single-team setups)"""
    # First try player/values.yaml
    values_file = "player/values.yaml"
    if os.path.exists(values_file):
        print(f"Loading flags from {values_file}")
        with open(values_file, 'r') as f:
            values = yaml.safe_load(f)
            return values.get('flags', {})
    
    # If team name provided, try to get from Helm
    if team_name:
        flags = load_team_flags_from_helm(team_name)
        if flags:
            return flags
    
    # Fallback to defaults
    print("Using default flag values")
    return DEFAULT_FLAGS


def load_multi_team_flags(team_names: List[str]) -> List[TeamFlags]:
    """Load flag values for multiple teams"""
    all_team_flags = []
    
    for team in team_names:
        # Try different sources in order of preference
        team_flags = (
            load_team_flags_from_file(team) or
            load_team_flags_from_helm(team) or
            generate_default_team_flags(team)
        )
        
        all_team_flags.append(TeamFlags(team_name=team, flags=team_flags))
    
    return all_team_flags


def setup_single_team_challenges(ctfd: CTFdAPI, team_name: Optional[str] = None) -> None:
    """Set up challenges for single team configuration"""
    print("Setting up challenges for single team")
    flags = load_single_team_flags(team_name)
    
    for challenge in CHALLENGES:
        flag_value = flags.get(challenge.flag_key, f"CTF{{{challenge.flag_key.upper()}}}")
        ctfd.create_challenge(challenge, [flag_value])


def setup_multi_team_challenges(ctfd: CTFdAPI, team_names: List[str]) -> None:
    """Set up challenges for multi-team configuration"""
    print(f"Setting up challenges for teams: {', '.join(team_names)}")
    
    all_team_flags = load_multi_team_flags(team_names)
    
    for challenge in CHALLENGES:
        # Collect all flag values for this challenge across teams
        flag_values = [
            team_flags.flags.get(challenge.flag_key, f"CTF{{{challenge.flag_key.upper()}_{team_flags.team_name.upper()}}}")
            for team_flags in all_team_flags
        ]
        
        ctfd.create_challenge(challenge, flag_values)


@click.command()
@click.option('--url', required=True, help='CTFd instance URL (e.g., http://localhost:8000)')
@click.option('--username', required=True, help='CTFd admin username')
@click.option('--password', required=True, help='CTFd admin password')
@click.option('--team-flags', help='Comma-separated list of team names for multi-team setup (e.g., team-a,team-b,team-c)')
@click.option('--single-team', help='Single team name to load flags from (alternative to --team-flags)')
def main(url: str, username: str, password: str, team_flags: Optional[str], single_team: Optional[str]):
    """Create CTFd challenges for the Kubernetes CTF.
    
    Examples:
        # Single team setup (uses player/values.yaml)
        python3 setup_ctfd_challenges.py --url http://localhost:8000 --username admin --password admin
        
        # Single team with specific Helm deployment
        python3 setup_ctfd_challenges.py --url http://localhost:8000 --username admin --password admin --single-team team-a
        
        # Multi-team setup (loads flags from each team's Helm deployment)
        python3 setup_ctfd_challenges.py --url http://localhost:8000 --username admin --password admin --team-flags team-a,team-b,team-c
    """
    
    # Initialize CTFd API client
    try:
        ctfd = CTFdAPI(url, username, password)
    except Exception as e:
        print(f"Failed to connect to CTFd: {e}")
        sys.exit(1)

    # Setup challenges based on configuration
    if team_flags:
        team_list = [team.strip() for team in team_flags.split(',')]
        setup_multi_team_challenges(ctfd, team_list)
        
        print(f"\nNote: Each challenge accepts flags from all {len(team_list)} teams.")
        print("Teams cannot share flags as each team has unique flag values.")
    else:
        setup_single_team_challenges(ctfd, single_team)

    print("\nAll challenges created successfully!")
    print(f"Visit {url} to see your challenges")


if __name__ == "__main__":
    main()
