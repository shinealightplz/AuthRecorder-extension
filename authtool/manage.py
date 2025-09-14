#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AuthRecorder Model Manager

This script provides a simple command line interface to:
  * Check available hardware (e.g. GPU)
  * Install required dependencies
  * Launch the GUI
  * Train a model on .svb and .anom files

The training functionality is a placeholder that simply reports found files
and simulates a training loop.  It is intended to be expanded with real
model training logic in the future.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def check_hardware() -> None:
    """Print whether CUDA GPU is available."""
    try:
        import torch  # type: ignore
        cuda = torch.cuda.is_available()
    except Exception:
        cuda = False
    print(f"✅ GPU available: {cuda}")


def install_dependencies() -> None:
    """Run the existing install.py script."""
    print("🚀 Starting dependency installation...")
    result = subprocess.run(
        [sys.executable, "install.py"], capture_output=True, text=True
    )
    if result.returncode != 0:
        print("❌ Installation failed:")
        print(result.stderr)
        sys.exit(1)
    print("✅ Installation completed successfully")


def launch_gui() -> None:
    """Launch the AuthRecorder GUI."""
    print("🚀 Launching GUI...")
    subprocess.run([sys.executable, "authrecorder_gui.py"])


def list_data_files() -> list[Path]:
    """Return all .svb and .anom files in current directory."""
    return list(Path(".").glob("*.svb")) + list(Path(".").glob("*.anom"))


def train_local(model_path: str) -> None:
    """Train a local model using collected data."""
    files = list_data_files()
    if not files:
        print("⚠️  No .svb or .anom files found to train on.")
        return
    
    print(f"📚 Training local model at {model_path} on {len(files)} files...")
    
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import Dataset, DataLoader
        
        # Define a simple neural network
        class AuthModel(nn.Module):
            def __init__(self):
                super().__init__()
                self.fc1 = nn.Linear(100, 64)  # Example dimensions
                self.fc2 = nn.Linear(64, 32)
                self.fc3 = nn.Linear(32, 2)    # Binary classification
                
            def forward(self, x):
                x = torch.relu(self.fc1(x))
                x = torch.relu(self.fc2(x))
                return torch.sigmoid(self.fc3(x))
        
        # Create model and optimizer
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = AuthModel().to(device)
        optimizer = torch.optim.Adam(model.parameters())
        criterion = nn.BCELoss()
        
        # Training loop
        for epoch in range(10):  # Example epochs
            for i, f in enumerate(files, 1):
                # In a real implementation, load and preprocess the data here
                print(f"  [{i}/{len(files)}] Training on {f.name} (epoch {epoch+1}/10)")
                
                # Simulate training with random data
                inputs = torch.randn(1, 100).to(device)
                labels = torch.randint(0, 2, (1,)).float().to(device)
                
                optimizer.zero_grad()
                outputs = model(inputs)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()
                
        torch.save(model.state_dict(), model_path)
        print(f"✅ Model trained and saved to {model_path}")
        
    except ImportError:
        print("❌ PyTorch not installed. Please install with: pip install torch")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Training failed: {str(e)}")
        sys.exit(1)


def train_remote(remote_url: str) -> None:
    """Train model via remote WebUI API."""
    files = list_data_files()
    if not files:
        print("⚠️  No .svb or .anom files found to train on.")
        return
        
    print(f"🌐 Connecting to remote WebUI at {remote_url}...")
    
    try:
        import requests
        
        # Prepare data for upload
        data = {
            'model_type': 'auth_classifier',
            'files': [f.name for f in files]
        }
        
        # In a real implementation, we'd upload the actual file contents
        response = requests.post(
            f"{remote_url}/api/train",
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            print("✅ Training job started successfully")
            print(f"Job ID: {response.json().get('job_id')}")
        else:
            print(f"❌ Failed to start training: {response.text}")
            sys.exit(1)
            
    except ImportError:
        print("❌ Requests library not installed. Please install with: pip install requests")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Remote training failed: {str(e)}")
        sys.exit(1)


# ----------------------------------------------------------------------
# Command‑line interface
# ----------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="AuthRecorder Model Manager CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("hardware", help="Check available hardware")

    subparsers.add_parser("install", help="Install dependencies")

    subparsers.add_parser("gui", help="Launch the GUI")

    train_parser = subparsers.add_parser("train", help="Train a model")
    train_parser.add_argument(
        "--local-model",
        dest="local_model",
        help="Path to a local model file",
    )
    train_parser.add_argument(
        "--remote-url",
        dest="remote_url",
        help="URL of the remote WebUI training endpoint",
    )

    args = parser.parse_args()

    if args.command == "hardware":
        check_hardware()
    elif args.command == "install":
        install_dependencies()
    elif args.command == "gui":
        launch_gui()
    elif args.command == "train":
        if args.local_model:
            train_local(args.local_model)
        elif args.remote_url:
            train_remote(args.remote_url)
        else:
            print("❌ Either --local-model or --remote-url must be provided.")
            parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()
