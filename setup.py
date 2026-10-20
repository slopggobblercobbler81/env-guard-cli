from setuptools import setup, find_packages

setup(
    name="env-guard-cli",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "env-guard=env_guard.cli:main",
            "envguard=env_guard.cli:main",
        ],
    },
)
