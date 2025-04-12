#!/usr/bin/env python3

# This script connects the MCP AI agent directly to Kali Linux tools without an API server.

import logging
import os
import subprocess
import sys
import threading
import traceback
from typing import Dict, Any, Optional

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 3 minutes default timeout

class CommandExecutor:
    """Class to handle command execution with better timeout management"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


def setup_mcp_server() -> FastMCP:
    """
    Set up the MCP server with all tool functions that directly execute commands
    without a separate API server
    
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp")
    
    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali system.
        
        Args:
            command: The command to execute
            
        Returns:
            Command execution results
        """
        if not command:
            return {
                "error": "Command parameter is required",
                "success": False
            }
        
        result = CommandExecutor(command).execute()
        return result

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sCV", ports: str = "", additional_args: str = "-T4 -Pn") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results
        """
        if not target:
            return {
                "error": "Target parameter is required",
                "success": False
            }
        
        command = f"nmap {scan_type}"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.
        
        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            
        Returns:
            Scan results
        """
        if not url:
            return {
                "error": "URL parameter is required",
                "success": False
            }
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            return {
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost",
                "success": False
            }
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results
        """
        if not url:
            return {
                "error": "URL parameter is required",
                "success": False
            }
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        if not target:
            return {
                "error": "Target parameter is required",
                "success": False
            }
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        if not url:
            return {
                "error": "URL parameter is required",
                "success": False
            }
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        if not module:
            return {
                "error": "Module parameter is required",
                "success": False
            }
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        try:
            with open(resource_file, "w") as f:
                f.write(resource_content)
        except Exception as e:
            return {
                "error": f"Error creating resource file: {str(e)}",
                "success": False
            }
        
        command = f"msfconsole -q -r {resource_file}"
        result = CommandExecutor(command).execute()
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return result

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        if not target or not service:
            return {
                "error": "Target and service parameters are required",
                "success": False
            }
        
        if not (username or username_file) or not (password or password_file):
            return {
                "error": "Username/username_file and password/password_file are required",
                "success": False
            }
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        if not hash_file:
            return {
                "error": "Hash file parameter is required",
                "success": False
            }
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results
        """
        if not url:
            return {
                "error": "URL parameter is required",
                "success": False
            }
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results
        """
        if not target:
            return {
                "error": "Target parameter is required",
                "success": False
            }
        
        command = f"enum4linux {additional_args} {target}"
        
        return CommandExecutor(command).execute()

    @mcp.tool()
    def check_health() -> Dict[str, Any]:
        """
        Check the health status of the system and available tools.
        
        Returns:
            Server health information
        """
        # Check if essential tools are installed
        essential_tools = ["nmap", "gobuster", "dirb", "nikto", "sqlmap", "hydra", "john", "wpscan", "enum4linux"]
        tools_status = {}
        
        for tool in essential_tools:
            try:
                result = CommandExecutor(f"which {tool}").execute()
                tools_status[tool] = result["success"]
            except:
                tools_status[tool] = False
        
        all_essential_tools_available = all(tools_status.values())
        
        return {
            "status": "healthy",
            "message": "Kali Linux Tools direct access is running",
            "tools_status": tools_status,
            "all_essential_tools_available": all_essential_tools_available
        }

    return mcp

def main():
    """Main entry point for the MCP server."""
    # Configure logging based on debug flag
    if DEBUG_MODE:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server()
    logger.info("Starting Kali MCP server with direct tool access")
    mcp.run()

if __name__ == "__main__":
    main()