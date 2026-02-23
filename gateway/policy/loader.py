"""Load and validate YAML policy files into PolicyConfig objects."""

import os
from pathlib import Path

import yaml

from gateway.models.policy import PolicyConfig


class PolicyLoadError(Exception):
    pass


def load_policy(path: str | Path) -> PolicyConfig:
    """
    Load a YAML policy file and validate it against the PolicyConfig schema.
    Raises PolicyLoadError if the file cannot be loaded or is invalid.
    """
    path = Path(path)
    if not path.exists():
        raise PolicyLoadError(f"Policy file not found: {path}")

    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"YAML parse error in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise PolicyLoadError(f"Policy file must be a YAML mapping, got: {type(raw)}")

    try:
        return PolicyConfig.model_validate(raw)
    except Exception as e:
        raise PolicyLoadError(f"Policy validation error in {path}: {e}") from e


def load_policy_for_environment(
    policy_dir: str | Path,
    environment: str,
    default_file: str = "default.yaml",
) -> PolicyConfig:
    """
    Load the appropriate policy for a given environment.
    Checks for {environment}.yaml first, falls back to default.yaml.
    """
    policy_dir = Path(policy_dir)
    env_file = policy_dir / f"{environment}.yaml"
    default_file_path = policy_dir / default_file

    if env_file.exists():
        return load_policy(env_file)
    elif default_file_path.exists():
        return load_policy(default_file_path)
    else:
        raise PolicyLoadError(
            f"No policy file found for environment '{environment}' "
            f"(checked: {env_file}, {default_file_path})"
        )


def load_policy_from_env(env_override: str | None = None) -> PolicyConfig:
    """Load policy using the POLICY_DIR and POLICY_FILE environment variables."""
    from gateway.config import settings

    policy_dir = os.environ.get("POLICY_DIR", settings.policy_dir)
    environment = env_override or settings.environment
    return load_policy_for_environment(policy_dir, environment)
