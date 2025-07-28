#!/usr/bin/env python3
"""
Script to automatically create CTFd challenges for the Kubernetes CTF.
Run this after deploying CTFd to populate it with your challenges.

Usage:
    python3 setup_ctfd_challenges.py --url http://your-ctfd-url --username admin --password admin
    
Flags are loaded from game/values.yaml and player/values.yaml files.
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


# Challenge definitions based on your 5 Kubernetes challenges
CHALLENGES = [
    Challenge(
        flag_key="warmup",
        name="Warmup",
        category="Kubernetes Basics", 
        description="""Welcome to the Kubernetes CTF!""",
        value=50,
        hints=[
        ]
    ),
    Challenge(
        flag_key="leakySecret",
        name="Leaky Secret",
        category="RBAC & Secrets",
        description="""There's a secret in your namespace that contains a flag, but you can't read it directly...""",
        value=100,
        hints=[
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
        ]
    ),
    Challenge(
        flag_key="privilegedEscape",
        name="Privileged Container Escape",
        category="Container Escape",
        description="""Break out of your container constraints and access the underlying 
host system to find the flag.""",
        value=200,
        hints=[
            "Look for privileged containers",
        ]
    ),
    Challenge(
        flag_key="networkSidestep",
        name="Network Sidestep",
        category="Network Security",
        description="""Network policies control traffic between pods. Find a way to bypass 
the network restrictions to reach a protected service.""",
        value=250,
        hints=[
            "Check what network policies exist",
            "Look for ways to bridge networks"
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


def load_flags_from_yaml() -> Dict[str, str]:
    """Load flag values from game/values.yaml and player/values.yaml files"""
    flags = {}
    
    # Load flags from player/values.yaml
    player_values_path = Path("player/values.yaml")
    if player_values_path.exists():
        try:
            with open(player_values_path, 'r') as f:
                player_values = yaml.safe_load(f)
                player_flags = player_values.get('flags', {})
                flags.update(player_flags)
                print(f"Loaded {len(player_flags)} flags from player/values.yaml")
        except Exception as e:
            print(f"Warning: Failed to load player/values.yaml: {e}")
    else:
        print("Warning: player/values.yaml not found")
    
    # Load flags from game/values.yaml
    game_values_path = Path("game/values.yaml")
    if game_values_path.exists():
        try:
            with open(game_values_path, 'r') as f:
                game_values = yaml.safe_load(f)
                game_flags = game_values.get('flags', {})
                flags.update(game_flags)  # This will override any duplicates with game values
                print(f"Loaded {len(game_flags)} flags from game/values.yaml")
        except Exception as e:
            print(f"Warning: Failed to load game/values.yaml: {e}")
    else:
        print("Warning: game/values.yaml not found")
    
    if not flags:
        raise Exception("No flags found in either player/values.yaml or game/values.yaml")
    
    print(f"Total flags loaded: {list(flags.keys())}")
    return flags


def setup_challenges(ctfd: CTFdAPI) -> None:
    """Set up challenges using flags from YAML files"""
    print("Setting up CTF challenges...")
    flags = load_flags_from_yaml()

    for challenge in CHALLENGES:
        flag_value = flags.get(challenge.flag_key, f"CTF{{{challenge.flag_key.upper()}}}")
        if challenge.flag_key not in flags:
            print(f"Warning: Flag '{challenge.flag_key}' not found in YAML files, using default")
        ctfd.create_challenge(challenge, [flag_value])


@click.command()
@click.option('--url', required=True, help='CTFd instance URL (e.g., http://localhost:8000)')
@click.option('--username', required=True, help='CTFd admin username')
@click.option('--password', required=True, help='CTFd admin password')
def main(url: str, username: str, password: str):
    """Create CTFd challenges for the Kubernetes CTF.
    
    Flags are loaded from game/values.yaml and player/values.yaml files.
    
    Examples:
        python3 setup_ctfd_challenges.py --url http://localhost:8000 --username admin --password admin
    """
    
    # Initialize CTFd API client
    try:
        ctfd = CTFdAPI(url, username, password)
    except Exception as e:
        print(f"Failed to connect to CTFd: {e}")
        sys.exit(1)

    # Setup challenges
    try:
        setup_challenges(ctfd)
        print("\nAll challenges created successfully!")
        print(f"Visit {url} to see your challenges")
        print("\nChallenges created:")
        for challenge in CHALLENGES:
            print(f"  - {challenge.name} ({challenge.value} points)")
    except Exception as e:
        print(f"Failed to setup challenges: {e}")
        print("\nMake sure the game/values.yaml and player/values.yaml files exist and contain flag definitions.")
        sys.exit(1)


if __name__ == "__main__":
    main()
