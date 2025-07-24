# CTFd Integration Setup Guide

This guide will help you integrate your Kubernetes-based CTF challenges with the CTFd web platform.

## Prerequisites

1. CTFd deployed via your `bootstrap_cluster_wide_components.sh` script
2. Python 3.7+ with pip installed
3. Access to your CTFd admin interface

## Setup Steps

### 1. Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### 2. Get Your CTFd URL

After running `bootstrap_cluster_wide_components.sh`, find your CTFd URL:

```bash
# Get the service URL (if using LoadBalancer)
kubectl -n ctfd get svc

# Or if using port-forward for testing
kubectl -n ctfd port-forward svc/platformctf-ctfd 8000:8000
# Then use http://localhost:8000
```

### 3. Configure CTFd Integration Scripts

Edit the following files and update the configuration:

**setup_ctfd_challenges.py:**
```python
CTFD_URL = "http://your-ctfd-instance-url"  # Replace with actual URL
ADMIN_USERNAME = "admin"  # Your CTFd admin username
ADMIN_PASSWORD = "your-password"  # Your CTFd admin password
```

**manage_ctf_phases.py:**
```python
CTFD_URL = "http://your-ctfd-instance-url"  # Replace with actual URL
ADMIN_USERNAME = "admin"  # Your CTFd admin username
ADMIN_PASSWORD = "your-password"  # Your CTFd admin password
```

### 4. Create Challenges in CTFd

Run the setup script to automatically create all challenges:

```bash
python3 setup_ctfd_challenges.py
```

This will:
- Connect to your CTFd instance
- Create 8 challenges based on your Kubernetes challenges
- Set up flags from your `player/values.yaml`
- Add hints for each challenge
- Organize challenges by category

### 5. Test Phase Management

Test the phase management system:

```bash
# Start with Phase 1 (shows Warmup and Leaky Secret challenges)
python3 manage_ctf_phases.py 1

# Move to Phase 2 (adds Token Theft, Network Policy Bypass, Host Path Escape)
python3 manage_ctf_phases.py 2

# Continue through phases as needed
python3 manage_ctf_phases.py 3
python3 manage_ctf_phases.py 4
```

### 6. Integrate with Your Workflow

The `start_phase.sh` script has been updated to automatically manage CTFd challenges when starting new phases:

```bash
# This now deploys K8s challenges AND updates CTFd visibility
./start_phase.sh team-a 2
```

## Challenge Structure

Your CTF now has the following challenges in CTFd:

| Challenge | Category | Points | Phase |
|-----------|----------|--------|-------|
| Warmup | Kubernetes Basics | 50 | 1 |
| Leaky Secret | RBAC & Secrets | 100 | 1 |
| Token Theft | Service Accounts | 150 | 2 |
| Network Policy Bypass | Network Security | 200 | 2 |
| Host Path Escape | Storage & Volumes | 250 | 2 |
| Controller Compromise | Custom Resources | 300 | 3 |
| Kernel Space Access | Container Escape | 400 | 3 |
| Cluster Admin | Privilege Escalation | 500 | 4 |

## Customization

### Adding New Challenges

1. Add the challenge YAML to `player/templates/challenges/`
2. Add the flag to `player/values.yaml`
3. Update `CHALLENGE_DEFINITIONS` in `setup_ctfd_challenges.py`
4. Update `PHASE_CHALLENGES` in `manage_ctf_phases.py`
5. Re-run the setup script

### Modifying Phase Structure

Edit the `PHASE_CHALLENGES` dictionary in `manage_ctf_phases.py`:

```python
PHASE_CHALLENGES = {
    1: ["Warmup", "Leaky Secret"],
    2: ["Token Theft", "Network Policy Bypass"],
    3: ["Host Path Escape", "Controller Compromise"],
    4: ["Kernel Space Access", "Cluster Admin"]
}
```

### Custom Flag Validation

For dynamic flags or custom validation logic, you can:

1. Use CTFd's plugin system to create custom challenge types
2. Set up webhook-based flag validation
3. Create a custom flag validation service

## Troubleshooting

### CTFd Connection Issues

```bash
# Test connectivity
curl -v http://your-ctfd-url/login

# Check CTFd logs
kubectl -n ctfd logs deployment/platformctf-ctfd
```

### Phase Management Issues

```bash
# Check if challenges exist in CTFd
python3 -c "
from manage_ctf_phases import CTFdPhaseManager
manager = CTFdPhaseManager('http://your-url', 'admin', 'password')
print(manager.challenges)
"
```

### Flag Sync Issues

Ensure your `player/values.yaml` flags match what's expected in CTFd:

```bash
# View current flags
helm get values team-a

# Update flags if needed
helm upgrade team-a ctf/player --set flags.warmup="CTF{NEW_FLAG}"
```
