"""Utility helper functions for the hackbot agent."""


def normalize_text(text: str) -> str:
    """Normalize text input."""
    return text.strip().lower()


def format_response(data: dict) -> str:
    """Format response data for output."""
    return str(data)
