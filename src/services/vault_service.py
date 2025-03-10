import hvac
from typing import Dict, Any, Optional, List, Tuple

class VaultService:
    """
    Service for interacting with HashiCorp Vault to retrieve credentials for certificate signing.
    Uses the hvac library to communicate with Vault's KV version 2 secret engine.
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
        
        # Initialize the hvac client
        self.client = hvac.Client(url=self.vault_url, token=self.token)
    
    def get_credential(self, path: str = "/kv2/cert") -> Dict[str, Any]:
        """
        Retrieve certificate credentials from Vault's KV version 2 store.
        
        Args:
            path: Path to the secrets in Vault (default: /kv2/cert)
                 Format should be: "/mount_point/path/to/secret"
            
        Returns:
            Dictionary containing the credential data
            
        Raises:
            Exception: If the Vault request fails
        """
        # Parse the path to extract mount point and secret path
        path = path.lstrip('/')
        parts = path.split('/', 1)
        
        if len(parts) < 2:
            raise ValueError(f"Invalid path format: {path}. Expected format: mount_point/path/to/secret")
        
        mount_point = parts[0]
        secret_path = parts[1]
        
        try:
            # Read the secret from the KV version 2 secret engine
            response = self.client.secrets.kv.v2.read_secret_version(
                path=secret_path,
                mount_point=mount_point
            )
            
            # The KV v2 data is nested inside 'data' -> 'data'
            if 'data' in response and 'data' in response['data']:
                return response['data']['data']
            else:
                raise Exception(f"Invalid response format from Vault: {response}")
            
        except hvac.exceptions.VaultError as e:
            raise Exception(f"Failed to retrieve credentials: {str(e)}")
    
    def is_authenticated(self) -> bool:
        """
        Check if the current token is authenticated with Vault.
        
        Returns:
            True if authenticated, False otherwise
        """
        try:
            return self.client.is_authenticated()
        except Exception:
            return False
            
    def list_secrets(self, path: str = "/kv2") -> List[str]:
        """
        List secrets at the specified path.
        
        Args:
            path: Path in Vault to list secrets (default: /kv2)
            
        Returns:
            List of secret names at the path
        """
        path = path.lstrip('/')
        parts = path.split('/', 1)
        
        mount_point = parts[0]
        list_path = parts[1] if len(parts) > 1 else ""
        
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path=list_path,
                mount_point=mount_point
            )
            
            if 'data' in response and 'keys' in response['data']:
                return response['data']['keys']
            else:
                return []
        except hvac.exceptions.VaultError:
            return []