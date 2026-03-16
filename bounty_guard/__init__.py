"""BountyGuard: Automatic triage of security issue reports on GitHub repositories.

This package provides a GitHub App webhook server that scores incoming security
issue reports against a spam-detection rubric, applies labels to suspicious
reports, and optionally uses an LLM for a second-opinion classification.

Version history:
    0.1.0 - Initial release with rule-based scorer, LLM classifier, and
             GitHub App webhook integration.
"""

__version__ = "0.1.0"
__author__ = "BountyGuard Contributors"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
