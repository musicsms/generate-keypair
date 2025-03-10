import requests
from typing import Dict, Any, Optional

class VaultService:
    """
    Service for interacting with HashiCorp Vault to retrieve credentials.
    """
    
    def __init__(self, vault_url: str, token: str):
        """
        Initialize the Vault service with URL and token.
        
        Args:
            vault_url: Base URL of the Vault server
            token: Vault authentication token
        """
        self.vault_url = vault_url.rstrip('/')
        self.token = token
        self.headers = {"X-Vault-Token": token}
    
    def get_credential(self, path: str = "/kv2/cert") -> Dict[str, Any]:
        """
        Retrieve certificate credentials from Vault's KV store.
        
        Args:
            path: Path to the secrets in Vault (default: /kv2/cert)
            
        Returns:
            Dictionary containing the credential data
            
        Raises:
            Exception: If the Vault request fails
        """
        url = f"{self.vault_url}/v1/{path.lstrip('/')}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code != 200:
            raise Exception(f"Failed to retrieve credentials: {response.text}")
        
        return response.json()["data"]