#!/usr/bin/env python3

import os
import sys
import pytest
import subprocess
import time
from unittest.mock import patch
import knockd_rotator_client

# Test fixture to reset the module between tests
@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables between tests."""
    # Save original environment
    original_env = os.environ.copy()
    
    # Set a default working environment for tests
    os.environ["KNOCKD_ROTATOR_SECRET"] = "verysecretkey1234"
    os.environ["KNOCKD_ROTATOR_LENGTH"] = "10"
    os.environ["KNOCKD_ROTATOR_PORTS"] = "2000-65536"
    os.environ["KNOCKD_ROTATOR_PERIOD_MODULO"] = "3600"
    os.environ["KNOCKD_ROTATOR_PORT_MODULO"] = "0"
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)

def test_overlapping_port_specification():
    """Test if the client crashes with overlapping port specification."""
    # Execute in a subprocess to test initialization errors
    cmd = [sys.executable, "-c", """
import os
os.environ["KNOCKD_ROTATOR_SECRET"] = "verysecretkey1234"
os.environ["KNOCKD_ROTATOR_PORTS"] = "2000-3000,2500-4000"
import knockd_rotator_client
"""]
    
    # Run command and capture exit code
    result = subprocess.run(cmd, capture_output=True)
    assert result.returncode != 0, "Client should exit with error on overlapping ports"
    assert b"Duplicate ports" in result.stderr, "Error message should mention duplicate ports"

def test_low_sequence_length():
    """Test if the client crashes with too low sequence length."""
    # Execute in a subprocess to test initialization errors
    cmd = [sys.executable, "-c", """
import os
os.environ["KNOCKD_ROTATOR_SECRET"] = "verysecretkey1234"
os.environ["KNOCKD_ROTATOR_LENGTH"] = "4"
import knockd_rotator_client
"""]
    
    # Run command and capture exit code
    result = subprocess.run(cmd, capture_output=True)
    assert result.returncode != 0, "Client should exit with error on low sequence length"
    assert b"must be at least 5" in result.stderr, "Error message should mention minimum length"

def test_short_secret():
    """Test if the client crashes with too short of a secret."""
    # Execute in a subprocess to test initialization errors
    cmd = [sys.executable, "-c", """
import os
os.environ["KNOCKD_ROTATOR_SECRET"] = "short"
import knockd_rotator_client
"""]
    
    # Run command and capture exit code
    result = subprocess.run(cmd, capture_output=True)
    assert result.returncode != 0, "Client should exit with error on short secret"
    assert b"must be at least 10 characters" in result.stderr, "Error message should mention minimum length"

def test_low_entropy():
    """Test if the client raises an error when entropy is too low."""
    # Create a temporary environment with low entropy
    with patch.dict(os.environ, {
        "KNOCKD_ROTATOR_PORTS": "2000-2010",
        "KNOCKD_ROTATOR_LENGTH": "5"
    }):
        # This should raise ValueError due to low entropy
        with pytest.raises(ValueError) as excinfo:
            knockd_rotator_client.generate_knock_sequence("test_service")
        
        # Check error message contains "Insufficient entropy"
        assert "Insufficient entropy" in str(excinfo.value), "Error should mention insufficient entropy"

def test_consistent_sequence_generation():
    """Test if 5 generated codes in a row are all the same."""
    # Using the default environment, generate 5 sequences in a row
    sequences = [knockd_rotator_client.generate_knock_sequence("test_service") for _ in range(5)]
    
    # All sequences should be identical in the same time period
    assert all(seq == sequences[0] for seq in sequences), "Generated sequences should be identical in the same time period"

def test_different_sequences_with_different_periods():
    """Test if sequences differ with different time periods."""
    # Generate sequence for current period
    seq1 = knockd_rotator_client.generate_knock_sequence("test_service", offset=0)
    
    # Generate sequence for next period
    seq2 = knockd_rotator_client.generate_knock_sequence("test_service", offset=1)
    
    # Sequences should be different
    assert seq1 != seq2, "Sequences from different time periods should be different"

def test_port_variety():
    """Test if in normal conditions, generated ports are not all identical."""
    # Using the default environment, generate a sequence
    sequence = knockd_rotator_client.generate_knock_sequence("test_service")
    
    # Extract ports from the sequence
    ports = [int(port_proto.split(":")[0]) for port_proto in sequence.split()]
    
    # Ensure not all ports are the same
    assert len(set(ports)) > 1, "Generated sequence should contain different ports"

def test_subprocess_call():
    """Test if calling from subprocess via python works."""
    # Run client with generate command
    result = subprocess.run(
        [sys.executable, 'knockd_rotator_client.py', 'generate', 'test_service'],
        capture_output=True,
        text=True,
        env=dict(os.environ)  # Use current test environment
    )
    
    # Check if it runs successfully
    assert result.returncode == 0, "Client should run successfully via subprocess"
    
    # Check if it generates a sequence (non-empty output)
    assert len(result.stdout.strip()) > 0, "Client should output a sequence"
