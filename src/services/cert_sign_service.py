"""
Certificate Signing Service for Microsoft ADCS (Active Directory Certificate Services)
Based on the certsrv library: https://github.com/magnuswatn/certsrv
"""

import requests
import re
import base64
import logging
from typing import Dict, Any, Optional, Tuple, List
import os

class RequestDeniedException(Exception):
    """Signifies that the request was denied by the ADCS server."""
    def __init__(self, message, response):
        Exception.__init__(self, message)
        self.response = response

class CouldNotRetrieveCertificateException(Exception):
    """Signifies that the certificate could not be retrieved."""
    def __init__(self, message, response):
        Exception.__init__(self, message)
        self.response = response

class CertificatePendingException(Exception):
    """Signifies that the request needs to be approved by a CA admin."""
    def __init__(self, req_id):
        Exception.__init__(
            self,
            "Your certificate request has been received. "
            "However, you must wait for an administrator to issue the "
            "certificate you requested. Your Request Id is {0}.".format(req_id),
        )
        self.req_id = req_id

class CertSignService:
    """
    Service for signing Certificate Signing Requests (CSRs) using Microsoft ADCS.
    """
    
    def __init__(self, server: str, username: str, password: str, auth_method: str = "basic", timeout: int = 30):
        """
        Initialize the Certificate Signing Service.
        
        Args:
            server: The FQDN to a server running the Certification Authority Web Enrollment role
            username: The username for authentication
            password: The password for authentication
            auth_method: The authentication method ('basic', 'ntlm', or 'cert')
            timeout: Request timeout in seconds
        """
        self.server = server
        self.timeout = timeout
        self.auth_method = auth_method
        self.session = requests.Session()
        
        self._set_credentials(username, password)
        
    def _set_credentials(self, username: str, password: str):
        """Set the credentials for authentication."""
        if self.auth_method == "basic":
            self.session.auth = (username, password)
        elif self.auth_method == "ntlm":
            from requests_ntlm import HttpNtlmAuth
            self.session.auth = HttpNtlmAuth(username, password)
        elif self.auth_method == "cert":
            self.session.cert = (username, password)
        else:
            raise ValueError(f"Unknown authentication method: {self.auth_method}")
    
    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        """Make a GET request to the server."""
        response = self.session.get(url, params=params, timeout=self.timeout, verify=True)
        response.raise_for_status()
        return response
    
    def _post(self, url: str, data: Optional[Dict[str, Any]] = None) -> requests.Response:
        """Make a POST request to the server."""
        response = self.session.post(url, data=data, timeout=self.timeout, verify=True)
        response.raise_for_status()
        return response
    
    def get_cert(self, csr: str, template: str, encoding: str = "b64") -> str:
        """
        Request a certificate from the ADCS server.
        
        Args:
            csr: The CSR in PEM format
            template: The certificate template to use
            encoding: The desired encoding ('b64' for Base64/PEM or 'bin' for binary)
            
        Returns:
            The issued certificate in the specified encoding
            
        Raises:
            RequestDeniedException: If the request was denied
            CertificatePendingException: If the request needs admin approval
            CouldNotRetrieveCertificateException: If the certificate couldn't be retrieved
        """
        # Strip any header and footer from the CSR
        csr = re.sub(r"-----BEGIN.*?-----", "", csr)
        csr = re.sub(r"-----END.*?-----", "", csr)
        # Remove all whitespace, including newlines
        csr = re.sub(r"\s+", "", csr)
        
        cert_request_url = f"https://{self.server}/certsrv/certfnsh.asp"
        cert_params = {
            "Mode": "newreq",
            "CertRequest": csr,
            "CertAttrib": f"CertificateTemplate:{template}",
            "TargetStoreFlags": "0",
            "SaveCert": "yes",
        }
        
        response = self._post(cert_request_url, data=cert_params)
        
        # Check if the request was denied
        if "denied by policy module" in response.text:
            raise RequestDeniedException("Request denied by policy module", response.text)
        
        # Check if the request is pending
        if "Your certificate request has been received" in response.text:
            req_id_match = re.search(r"Your Request Id is (\d+)\.", response.text)
            if req_id_match:
                req_id = req_id_match.group(1)
                raise CertificatePendingException(req_id)
            else:
                raise CouldNotRetrieveCertificateException(
                    "Certificate request is pending but could not find the Request ID",
                    response.text
                )
        
        # Extract the RequestId from the response
        req_id_match = re.search(r"certnew.cer\?ReqID=(\d+)&", response.text)
        if not req_id_match:
            raise CouldNotRetrieveCertificateException(
                "Could not find the Request ID in the response",
                response.text
            )
        
        req_id = req_id_match.group(1)
        
        # Now get the certificate
        return self.get_existing_cert(req_id, encoding)
    
    def get_existing_cert(self, req_id: str, encoding: str = "b64") -> str:
        """
        Get an existing certificate by request ID.
        
        Args:
            req_id: The request ID of the certificate
            encoding: The desired encoding ('b64' for Base64/PEM or 'bin' for binary)
            
        Returns:
            The issued certificate in the specified encoding
            
        Raises:
            CouldNotRetrieveCertificateException: If the certificate couldn't be retrieved
        """
        cert_url = f"https://{self.server}/certsrv/certnew.cer"
        params = {"ReqID": req_id, "Enc": encoding}
        
        cert_response = self._get(cert_url, params=params)
        
        # Verify the content type
        content_type = cert_response.headers["Content-Type"]
        if content_type != "application/pkix-cert" and content_type != "application/x-x509-ca-cert":
            raise CouldNotRetrieveCertificateException(
                f"Unexpected content type: {content_type}",
                cert_response.text
            )
        
        return cert_response.content
    
    def get_ca_cert(self, encoding: str = "b64") -> str:
        """
        Get the CA certificate from the ADCS server.
        
        Args:
            encoding: The desired encoding ('b64' for Base64/PEM or 'bin' for binary)
            
        Returns:
            The CA certificate in the specified encoding
        """
        cert_url = f"https://{self.server}/certsrv/certcarc.asp"
        response = self._get(cert_url)
        
        # Extract the renewal index from the response
        renewal_idx_match = re.search(r"certnew.cer\?ReqID=CACert&Renewal=(\d+)&", response.text)
        if not renewal_idx_match:
            raise CouldNotRetrieveCertificateException(
                "Could not find the renewal index",
                response.text
            )
        
        renewal_idx = renewal_idx_match.group(1)
        
        # Get the CA certificate
        ca_cert_url = f"https://{self.server}/certsrv/certnew.cer"
        params = {"ReqID": "CACert", "Renewal": renewal_idx, "Enc": encoding}
        
        ca_cert_response = self._get(ca_cert_url, params=params)
        
        # Verify the content type
        content_type = ca_cert_response.headers["Content-Type"]
        if content_type != "application/pkix-cert" and content_type != "application/x-x509-ca-cert":
            raise CouldNotRetrieveCertificateException(
                f"Unexpected content type: {content_type}",
                ca_cert_response.text
            )
        
        return ca_cert_response.content
    
    def get_chain(self, encoding: str = "bin") -> bytes:
        """
        Get the certificate chain from the ADCS server.
        
        Args:
            encoding: The desired encoding ('b64' for Base64/PEM or 'bin' for binary)
            
        Returns:
            The certificate chain in PKCS#7 format
        """
        chain_url = f"https://{self.server}/certsrv/certnew.p7b"
        params = {"ReqID": "CACert", "Enc": encoding}
        
        chain_response = self._get(chain_url, params=params)
        
        if chain_response.headers["Content-Type"] != "application/x-pkcs7-certificates":
            raise CouldNotRetrieveCertificateException(
                "An unknown error occurred",
                chain_response.content
            )
        
        return chain_response.content
    
    def check_credentials(self) -> bool:
        """
        Checks the specified credentials against the ADCS server.
        
        Returns:
            True if authentication succeeded, False if it failed
        """
        url = f"https://{self.server}/certsrv/"
        try:
            self._get(url)
        except requests.exceptions.HTTPError as error:
            if error.response.status_code == 401:
                return False
            else:
                raise
        return True

    def list_templates(self) -> List[Dict[str, str]]:
        """
        List available certificate templates.
        
        Returns:
            List of dictionaries containing template information
        """
        # In a real implementation, this would fetch templates from the ADCS server
        # For now, we'll return a static list of common templates
        return [
            {
                "id": "WebServer",
                "name": "Web Server",
                "description": "Certificate for SSL/TLS web servers"
            },
            {
                "id": "CodeSigning",
                "name": "Code Signing",
                "description": "Certificate for signing code"
            },
            {
                "id": "ClientAuth",
                "name": "Client Authentication",
                "description": "Certificate for client authentication"
            },
            {
                "id": "SmartcardLogon",
                "name": "Smartcard Logon",
                "description": "Certificate for smartcard logon"
            }
        ]