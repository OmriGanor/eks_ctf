#!/usr/bin/env python3
"""
Script to manage CTFd challenge phases.
This integrates with your start_phase.sh script to control challenge visibility in CTFd.

Usage:
    python3 manage_ctf_phases.py --url http://your-ctfd-url --username admin --password admin --phase 2
"""

import requests
import json
import sys
import click

# Phase definitions - which challenges are available in each phase
PHASE_CHALLENGES = {
    1: ["Warmup", "Leaky Secret"],
    2: ["Token Theft", "Network Policy Bypass", "Host Path Escape"],
    3: ["Controller Compromise", "Kernel Space Access"],
    4: ["Cluster Admin"]
}

class CTFdPhaseManager:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
        self.login(username, password)
        self.challenges = self.get_all_challenges()
    
    def login(self, username, password):
        """Login to CTFd"""
        login_data = {
            'name': username,
            'password': password
        }
        
        resp = self.session.post(f"{self.base_url}/login", data=login_data)
        if resp.status_code != 200 or 'login' in resp.url:
            raise Exception("Login failed")
        
        print("Successfully logged in to CTFd")
    
    def get_all_challenges(self):
        """Get all challenges from CTFd"""
        resp = self.session.get(f"{self.base_url}/api/v1/challenges")
        if resp.status_code != 200:
            raise Exception(f"Failed to get challenges: {resp.status_code}")
        
        challenges = {}
        for challenge in resp.json()['data']:
            challenges[challenge['name']] = challenge['id']
        
        return challenges
    
    def set_challenge_visibility(self, challenge_name, visible):
        """Set challenge visibility (hidden/visible)"""
        if challenge_name not in self.challenges:
            print(f"Warning: Challenge '{challenge_name}' not found")
            return False
        
        challenge_id = self.challenges[challenge_name]
        state = "visible" if visible else "hidden"
        
        update_data = {"state": state}
        resp = self.session.patch(f"{self.base_url}/api/v1/challenges/{challenge_id}", 
                                json=update_data)
        
        if resp.status_code != 200:
            print(f"Failed to update challenge {challenge_name}: {resp.status_code}")
            return False
        
        action = "shown" if visible else "hidden"
        print(f"Challenge '{challenge_name}' {action}")
        return True
    
    def activate_phase(self, phase_number):
        """Activate a specific phase by showing/hiding appropriate challenges"""
        print(f"\nActivating Phase {phase_number}")
        
        # Hide all challenges first
        for challenge_name in self.challenges:
            self.set_challenge_visibility(challenge_name, False)
        
        # Show challenges for current and previous phases
        for phase in range(1, phase_number + 1):
            if phase in PHASE_CHALLENGES:
                for challenge_name in PHASE_CHALLENGES[phase]:
                    self.set_challenge_visibility(challenge_name, True)
        
        print(f"\nPhase {phase_number} activated!")
        
        # Show summary
        visible_challenges = []
        for phase in range(1, phase_number + 1):
            if phase in PHASE_CHALLENGES:
                visible_challenges.extend(PHASE_CHALLENGES[phase])
        
        print(f"Visible challenges: {', '.join(visible_challenges)}")

@click.command()
@click.option('--url', required=True, help='CTFd instance URL (e.g., http://localhost:8000)')
@click.option('--username', required=True, help='CTFd admin username')
@click.option('--password', required=True, help='CTFd admin password')
@click.option('--phase', required=True, type=click.IntRange(1, 4), help='Phase number to activate (1-4)')
def main(url, username, password, phase):
    """Manage CTFd challenge phases by controlling challenge visibility.
    
    Examples:
        # Activate phase 2 (shows challenges from phases 1 and 2)
        python3 manage_ctf_phases.py --url http://localhost:8000 --username admin --password admin --phase 2
    """
    
    try:
        manager = CTFdPhaseManager(url, username, password)
        manager.activate_phase(phase)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 