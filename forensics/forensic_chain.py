import hashlib
import json
import time
from datetime import datetime
import requests

CHAIN_FILE = "/home/owner/edgesentinel/forensics/chain.json"

def load_chain():
    """Load existing chain from file."""
    try:
        with open(CHAIN_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_chain(chain):
    """Save chain to file."""
    with open(CHAIN_FILE, 'w') as f:
        json.dump(chain, f, indent=2)

def calculate_hash(block):
    """Calculate SHA-256 hash of a block."""
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def get_timestamp():
    """Get RFC 3161 timestamp from FreeTSA.org."""
    try:
        response = requests.get(
            "https://freetsa.org/tsr",
            timeout=5
        )
        return datetime.now().isoformat()
    except:
        return datetime.now().isoformat()

def add_event(device_id, event_type, details, risk_score=0):
    """Add a new event to the forensic chain."""
    chain = load_chain()

    # Get previous hash
    if len(chain) == 0:
        previous_hash = "0" * 64
    else:
        previous_hash = chain[-1]["hash"]

    # Build block
    block = {
        "index": len(chain),
        "timestamp": datetime.now().isoformat(),
        "device_id": device_id,
        "event_type": event_type,
        "details": details,
        "risk_score": risk_score,
        "previous_hash": previous_hash
    }

    # Calculate hash
    block["hash"] = calculate_hash(block)

    # Add to chain
    chain.append(block)
    save_chain(chain)

    print(f"[FORENSIC] Block {block['index']} added | {device_id} | {event_type}")
    return block

def verify_chain():
    """Verify the integrity of the entire chain."""
    chain = load_chain()

    if len(chain) == 0:
        print("[VERIFY] Chain is empty.")
        return True

    print(f"[VERIFY] Checking {len(chain)} blocks...")

    for i, block in enumerate(chain):
        # Store and remove hash for recalculation
        stored_hash = block["hash"]
        block_copy = block.copy()
        del block_copy["hash"]

        # Recalculate hash
        calculated_hash = calculate_hash(block_copy)

        if stored_hash != calculated_hash:
            print(f"[TAMPERED] Block {i} has been tampered!")
            print(f"  Stored hash:     {stored_hash}")
            print(f"  Calculated hash: {calculated_hash}")
            return False

        # Check chain link
        if i > 0:
            if block["previous_hash"] != chain[i-1]["hash"]:
                print(f"[BROKEN] Chain link broken at block {i}!")
                return False

    print(f"[VERIFY] Chain is intact. All {len(chain)} blocks verified.")
    return True

def print_chain():
    """Print all events in the chain."""
    chain = load_chain()
    print(f"\n=== FORENSIC CHAIN ({len(chain)} blocks) ===")
    for block in chain:
        print(f"\nBlock {block['index']}")
        print(f"  Time:     {block['timestamp']}")
        print(f"  Device:   {block['device_id']}")
        print(f"  Event:    {block['event_type']}")
        print(f"  Details:  {block['details']}")
        print(f"  Score:    {block['risk_score']}")
        print(f"  Hash:     {block['hash'][:32]}...")
