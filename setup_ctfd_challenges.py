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
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        # Allow redirects
        self.session.max_redirects = 5
        self.csrf_token = None
        self.login(username, password)

    def login(self, username, password):
        """Login to CTFd and get session token"""
        print(f"Attempting to login to {self.base_url}")
        
        # First, get the login page to establish session and get CSRF token
        try:
            login_page = self.session.get(f"{self.base_url}/login")
            print(f"Login page status: {login_page.status_code}")
            print(f"Login page URL: {login_page.url}")
            print(f"Session cookies: {dict(self.session.cookies)}")
            
            if login_page.status_code != 200:
                print(f"Login page content: {login_page.text[:200]}")
                raise Exception(f"Failed to access login page: {login_page.status_code}")
        except Exception as e:
            print(f"Error accessing login page: {e}")
            # Try direct API login as fallback
            self._try_api_login(username, password)
            return

        # Always go through login process to ensure proper admin session
        # Don't skip login even if API access works - we need admin privileges

        # Try multiple methods to extract CSRF token
        csrf_token = None
        
        # Method 1: Look for csrfNonce in script tags
        import re
        csrf_match = re.search(r"'csrfNonce':\s*[\"']([^\"']+)[\"']", login_page.text)
        if csrf_match:
            csrf_token = csrf_match.group(1)
            print(f"Found CSRF token via method 1: {csrf_token[:10]}...")
        
        # Method 2: Look for csrf_token in meta tags
        if not csrf_token:
            csrf_match = re.search(r'<meta name="csrf-token" content="([^"]+)"', login_page.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
                print(f"Found CSRF token via method 2: {csrf_token[:10]}...")
        
        # Method 3: Look for csrf in form inputs
        if not csrf_token:
            csrf_match = re.search(r'<input[^>]*name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']', login_page.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
                print(f"Found CSRF token via method 3: {csrf_token[:10]}...")
        
        # Method 4: Look for nonce in form inputs
        if not csrf_token:
            csrf_match = re.search(r'<input[^>]*name=["\']nonce["\'][^>]*value=["\']([^"\']+)["\']', login_page.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
                print(f"Found CSRF token via method 4: {csrf_token[:10]}...")

        # Method 5: Look for csrfNonce in JavaScript
        if not csrf_token:
            csrf_match = re.search(r"'csrfNonce':\s*[\"']([^\"']+)[\"']", login_page.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
                print(f"Found CSRF token via method 5: {csrf_token[:10]}...")

        # Store the CSRF token for later API calls
        self.csrf_token = csrf_token
        if self.csrf_token:
            self.session.headers.update({'X-CSRFToken': self.csrf_token})

        # Try web-based login first
        if self._try_web_login(username, password, csrf_token):
            # Verify admin access after successful login
            self._verify_admin_access()
            return
            
        # If web login fails, try API login
        self._try_api_login(username, password)

    def _try_web_login(self, username, password, csrf_token=None):
        """Try web-based login"""
        print("Attempting web-based login...")
        
        if not csrf_token:
            print("Warning: Could not find CSRF token, trying login without it...")
            login_data = {
                'name': username,
                'password': password
            }
        else:
            login_data = {
                'name': username,
                'password': password,
                'nonce': csrf_token
            }

        print(f"Login data: {login_data}")
        
        # Try form-encoded POST (this is what the actual form does)
        try:
            # Use form-encoded data, exactly like curl
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            resp = self.session.post(f"{self.base_url}/login", 
                                   data=login_data, 
                                   headers=headers,
                                   allow_redirects=True)
            print(f"Form POST response status: {resp.status_code}")
            print(f"Form POST response URL: {resp.url}")
            
            # Check if we were redirected away from login page (success)
            if resp.status_code in [200, 302] and 'login' not in resp.url:
                print("Successfully logged in via Form POST")
                print(f"Final URL: {resp.url}")
                print(f"Session cookies after login: {dict(self.session.cookies)}")
                # Get the updated CSRF token from the response page
                self._update_csrf_token_from_response(resp)
                return True
            elif resp.status_code == 302:  # Redirect after successful login
                print("Successfully logged in (redirect detected)")
                print(f"Redirect URL: {resp.url}")
                print(f"Session cookies after login: {dict(self.session.cookies)}")
                # Get the updated CSRF token from the response page
                self._update_csrf_token_from_response(resp)
                return True
            else:
                print(f"Login failed - still on login page or error: {resp.status_code}")
                print(f"Response URL: {resp.url}")
        except Exception as e:
            print(f"Form POST failed: {e}")
        
        return False

    def _verify_admin_access(self):
        """Verify that we have admin access after login"""
        try:
            # Test admin access by trying to access the admin challenges page
            admin_test = self.session.get(f"{self.base_url}/admin/challenges")
            print(f"Admin access test: {admin_test.status_code}")
            if admin_test.status_code == 200:
                print("✓ Admin access confirmed")
                # Update CSRF token from the admin page
                self._update_csrf_token_from_response(admin_test)
            else:
                print(f"✗ Admin access failed: {admin_test.status_code}")
        except Exception as e:
            print(f"Error verifying admin access: {e}")

    def _update_csrf_token_from_response(self, resp):
        """Update CSRF token from response content"""
        try:
            import re
            # Look for CSRF token in the response
            csrf_match = re.search(r"'csrfNonce':\s*[\"']([^\"']+)[\"']", resp.text)
            if csrf_match:
                new_token = csrf_match.group(1)
                print(f"Updated CSRF token: {new_token[:10]}...")
                self.csrf_token = new_token
                self.session.headers.update({'X-CSRFToken': self.csrf_token})
        except Exception as e:
            print(f"Failed to update CSRF token: {e}")

    def _try_api_login(self, username, password):
        """Try API-based login"""
        print("Attempting API-based login...")
        
        try:
            # Try the API login endpoint
            resp = self.session.post(f"{self.base_url}/api/v1/auth/login", json={
                'name': username,
                'password': password
            })
            print(f"API login response status: {resp.status_code}")
            print(f"API login response: {resp.text[:200]}")
            
            if resp.status_code == 200:
                print("Successfully logged in via API")
                return True
        except Exception as e:
            print(f"API login failed: {e}")
        
        # If all methods fail
        raise Exception("All login methods failed - check credentials and CTFd version compatibility")

    def create_challenge(self, challenge: Challenge, flag_values: List[str]) -> Optional[int]:
        """Create a challenge via CTFd web form submission"""
        # Try API first, then fall back to web form submission
        challenge_data = {
            'name': challenge.name,
            'category': challenge.category,
            'description': challenge.description,
            'value': challenge.value,
            'type': challenge.type,
            'state': 'visible'
        }

        # Try API first
        resp = self.session.post(f"{self.base_url}/api/v1/challenges",
                                 json=challenge_data)
        
        # If API fails with 403, try web form submission
        if resp.status_code == 403:
            print(f"API failed with 403, trying web form submission for {challenge.name}")
            return self._create_challenge_via_web_form(challenge, flag_values[0] if flag_values else f"CTF{{{challenge.flag_key.upper()}}}")

        # Continue with API response handling

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

    def _create_challenge_via_web_form(self, challenge: Challenge, flag_value: str) -> Optional[int]:
        """Create a challenge via web form submission (fallback when API fails)"""
        try:
            # Step 1: Go to the challenge creation page
            print(f"Accessing challenge creation page: {self.base_url}/admin/challenges/new")
            create_page = self.session.get(f"{self.base_url}/admin/challenges/new")
            print(f"Challenge creation page status: {create_page.status_code}")
            print(f"Session cookies: {dict(self.session.cookies)}")
            if create_page.status_code != 200:
                print(f"Failed to access challenge creation page: {create_page.status_code}")
                print(f"Response text: {create_page.text[:500]}")
                return None

            # Step 2: Submit the initial challenge form
            form_data = {
                'name': challenge.name,
                'category': challenge.category,
                'description': challenge.description,
                'value': challenge.value,
                'type': challenge.type,
                'state': 'visible',
                'flag': flag_value,
                'flag_type': 'static',
                'flag_data': ''  # Case sensitive
            }

            # Submit the form
            resp = self.session.post(f"{self.base_url}/admin/challenges/new", 
                                   data=form_data, 
                                   allow_redirects=True)

            if resp.status_code == 200 and '/admin/challenges' in resp.url:
                print(f"Successfully created challenge via web form: {challenge.name}")
                # Try to extract challenge ID from the redirect URL
                import re
                id_match = re.search(r'/admin/challenges/(\d+)', resp.url)
                if id_match:
                    return int(id_match.group(1))
                return 1  # Return a placeholder ID if we can't extract it

            print(f"Web form submission failed: {resp.status_code} - {resp.url}")
            return None

        except Exception as e:
            print(f"Error in web form submission: {e}")
            return None


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
