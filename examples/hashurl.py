"""
Example: Hash URL Service
=========================

This example demonstrates how to use Advocate to safely fetch URLs
and return their SHA-256 hash. Advocate's SSRF protection prevents
attackers from using this service to access internal resources.

Usage:
    python examples/hashurl.py
    
Then visit: http://localhost:5000/?url=https://example.com
"""

import hashlib
from typing import Optional

from flask import Flask, request, Response
import requests

import advocate

app = Flask(__name__)


@app.route('/')
def get_hash() -> str:
    """Get the SHA-256 hash of a URL's content.
    
    Args:
        url: The URL to hash (from query parameter).
        
    Returns:
        The SHA-256 hex digest of the URL's content, or an error message.
    """
    url: Optional[str] = request.args.get("url")
    if not url:
        return "Please specify a url!"
    
    try:
        headers = {"User-Agent": "Hashifier 0.1"}
        resp = advocate.get(url, headers=headers)
        return hashlib.sha256(resp.content).hexdigest()
    except advocate.UnacceptableAddressException:
        return "That URL points to a forbidden resource"
    except requests.RequestException:
        return "Failed to connect to the specified URL"


if __name__ == '__main__':
    app.run(debug=True)
