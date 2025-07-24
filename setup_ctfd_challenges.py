#!/usr/bin/env python3
"""
Script to automatically create CTFd challenges for the Kubernetes CTF.
Run this after deploying CTFd to populate it with your challenges.
"""

import requests
import json
import yaml
import os
from urllib.parse import urljoin

# Configuration
CTFD_URL = "http://your-ctfd-url"  # Update this to your CTFd instance URL
ADMIN_USERNAME = "admin"  # Update with your admin username
ADMIN_PASSWORD = "admin"  # Update with your admin password

# Challenge definitions based on your Kubernetes challenges
CHALLENGE_DEFINITIONS = {
    "warmup": {
        "name": "Warmup",
        "category": "Kubernetes Basics",
        "description": """Welcome to the Kubernetes CTF! Your team has been given access to a Kubernetes cluster.

Start by exploring your namespace and find the deployment that's running.
Check the logs of the pod to find your first flag.

Commands to get started:
- `kubectl get pods`
- `kubectl logs <pod-name>`""",
        "value": 50,
        "type": "standard",
        "hints": [
            "Look for a deployment called 'warmup'",
            "Check the container logs for output"
        ]
    },
    "leakySecret": {
        "name": "Leaky Secret",
        "category": "RBAC & Secrets",
        "description": """There's a secret in your namespace that contains a flag, but you can't read it directly.
However, you have been granted special permissions to "watch" secrets.

Use kubectl to monitor changes to secrets and capture the flag.

Hint: Check the secret's annotation for guidance.""",
        "value": 100,
        "type": "standard",
        "hints": [
            "You can only WATCH secrets, not GET them",
            "Use `kubectl get secrets` to find the secret name",
            "Try `kubectl get secret <name> --watch`"
        ]
    },
    "misScopedSA": {
        "name": "Token Theft",
        "category": "Service Accounts",
        "description": """Service accounts in Kubernetes have tokens that can be used for authentication.
Find a way to access a service account token that gives you elevated privileges.""",
        "value": 150,
        "type": "standard",
        "hints": [
            "Look for service accounts in your namespace",
            "Service account tokens are mounted in pods"
        ]
    },
    "netpol101": {
        "name": "Network Policy Bypass",
        "category": "Network Security",
        "description": """Network policies control traffic between pods. Find a way to bypass 
the network restrictions to reach a protected service.""",
        "value": 200,
        "type": "standard",
        "hints": [
            "Check what network policies exist",
            "ICMP traffic might be handled differently"
        ]
    },
    "sillyCSI": {
        "name": "Host Path Escape",
        "category": "Storage & Volumes",
        "description": """A custom CSI driver has been deployed. Investigate how you can 
abuse it to access the host filesystem.""",
        "value": 250,
        "type": "standard",
        "hints": [
            "Look for custom storage classes",
            "CSI drivers can expose host paths"
        ]
    },
    "trivialJob": {
        "name": "Controller Compromise",
        "category": "Custom Resources",
        "description": """A custom controller has been deployed for TrivialJob resources.
Find a way to exploit this controller to gain elevated access.""",
        "value": 300,
        "type": "standard",
        "hints": [
            "Custom resources might have CRDs",
            "Controllers often run with elevated privileges"
        ]
    },
    "podEscape": {
        "name": "Kernel Space Access",
        "category": "Container Escape",
        "description": """Break out of your container constraints and access the underlying 
kernel space to find the flag.""",
        "value": 400,
        "type": "standard",
        "hints": [
            "Look for privileged containers",
            "Host namespaces can provide escape routes"
        ]
    },
    "escalation": {
        "name": "Cluster Admin",
        "category": "Privilege Escalation",
        "description": """Achieve cluster-admin privileges through any means necessary.
The ultimate flag awaits those who can take control of the entire cluster.""",
        "value": 500,
        "type": "standard",
        "hints": [
            "Chain together previous vulnerabilities",
            "Look for service accounts with cluster-wide permissions"
        ]
    }
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
    
    def create_challenge(self, name, category, description, value, challenge_type, flag_value, hints=None):
        """Create a challenge via CTFd API"""
        challenge_data = {
            'name': name,
            'category': category,
            'description': description,
            'value': value,
            'type': challenge_type,
            'state': 'visible'
        }
        
        # Create the challenge
        resp = self.session.post(f"{self.base_url}/api/v1/challenges", 
                               json=challenge_data)
        
        if resp.status_code != 200:
            print(f"Failed to create challenge {name}: {resp.status_code} - {resp.text}")
            return None
        
        challenge_id = resp.json()['data']['id']
        print(f"Created challenge: {name} (ID: {challenge_id})")
        
        # Add the flag
        flag_data = {
            'challenge': challenge_id,
            'content': flag_value,
            'type': 'static'
        }
        
        flag_resp = self.session.post(f"{self.base_url}/api/v1/flags", 
                                    json=flag_data)
        
        if flag_resp.status_code != 200:
            print(f"Failed to add flag for {name}: {flag_resp.status_code}")
        else:
            print(f"Added flag for {name}")
        
        # Add hints if provided
        if hints:
            for hint_text in hints:
                hint_data = {
                    'challenge': challenge_id,
                    'content': hint_text,
                    'cost': 0  # Free hints
                }
                
                hint_resp = self.session.post(f"{self.base_url}/api/v1/hints", 
                                            json=hint_data)
                
                if hint_resp.status_code != 200:
                    print(f"Failed to add hint for {name}: {hint_resp.status_code}")
                else:
                    print(f"Added hint for {name}: {hint_text[:30]}...")
        
        return challenge_id

def load_flags_from_values():
    """Load flag values from values.yaml"""
    try:
        with open('player/values.yaml', 'r') as f:
            values = yaml.safe_load(f)
            return values.get('flags', {})
    except FileNotFoundError:
        print("Warning: player/values.yaml not found, using default flags")
        return {
            "warmup": "CTF{WELCOME}",
            "leakySecret": "CTF{SECRET_READ}",
            "misScopedSA": "CTF{TOKEN_STEAL}",
            "netpol101": "CTF{ICMP_ALLOWED}",
            "sillyCSI": "CTF{HOST_PATH}",
            "trivialJob": "CTF{CONTROLLER_PWN}",
            "podEscape": "CTF{KERNEL_SPACE}",
            "escalation": "CTF{CLUSTER_ADMIN}"
        }

def main():
    if not CTFD_URL or CTFD_URL == "http://your-ctfd-url":
        print("Please update CTFD_URL in the script with your actual CTFd instance URL")
        return
    
    # Load flags from values.yaml
    flags = load_flags_from_values()
    
    # Initialize CTFd API client
    try:
        ctfd = CTFdAPI(CTFD_URL, ADMIN_USERNAME, ADMIN_PASSWORD)
    except Exception as e:
        print(f"Failed to connect to CTFd: {e}")
        return
    
    # Create challenges
    for flag_key, challenge_def in CHALLENGE_DEFINITIONS.items():
        flag_value = flags.get(flag_key, f"CTF{{{flag_key.upper()}}}")
        
        ctfd.create_challenge(
            name=challenge_def["name"],
            category=challenge_def["category"],
            description=challenge_def["description"],
            value=challenge_def["value"],
            challenge_type=challenge_def["type"],
            flag_value=flag_value,
            hints=challenge_def.get("hints", [])
        )
    
    print("\nAll challenges created successfully!")
    print(f"Visit {CTFD_URL} to see your challenges")

if __name__ == "__main__":
    main() 