# NeuroPwn

NeuroPwn is a proof-of-concept tool that demonstrates an agent-based approach to automatically discover security vulnerabilities. The system leverages Claude as the MCP (Model Context Protocol) client while operating with a Kali Linux MCP server backend.

This architecture allows NeuroPwn to combine the reasoning capabilities of advanced AI models with the specialized security tools available in Kali Linux, creating a powerful automated security assessment system.

# Setup

The project uses a Kali MCP server modified with AI from [MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server). An unofficial Linux Client is used as the Claude MCP client: [claude-desktop-debian](https://github.com/aaddrick/claude-desktop-debian).

### Quickstart (Docker)

1. Build the Docker image:
   ```bash
   docker build -t kali-web-vnc .
   ```

2. Run the container:
   ```bash
   docker run -p 6080:6080 --name kali-container kali-web-vnc
   ```

3. Access the web VNC interface at `http://127.0.0.1:6080/` with password `password`

4. Open a terminal in the VNC session

5. Launch Claude Desktop:
   ```bash
   claude-desktop
   ```

6. Login with your Claude account

### Installation on Kali Linux

1. Install Claude MCP client:
   ```bash
   # Follow instructions at https://github.com/aaddrick/claude-desktop-debian
   ```

2. Copy MCP-Server files to your directory:
   ```bash
   mkdir -p /home/kali/neuropwn
   cp python/kali-mcp-server.py script/setup-mcp-server.sh script/start-mcp-server.sh /home/kali/neuropwn/
   ```

3. Set up the MCP server:
   ```bash
   cd /home/kali/neuropwn
   chmod +x setup-mcp-server.sh
   ./setup-mcp-server.sh
   ```

4. Launch Claude Desktop:
   ```bash
   claude-desktop
   ```

5. Create the MCP configuration file:
   ```bash
   mkdir -p /home/kali/.config/Claude
   cat > /home/kali/.config/Claude/claude_desktop_config.json << 'EOF'
   {
       "mcpServers": {
           "kali_mcp": {
               "command": "/bin/bash",
               "args": [
                   "-c",
                   "/home/kali/neuropwn/start-mcp-server.sh"
               ]
           }
       }
   }
   EOF
   ```

6. Restart Claude Desktop:
   - Close Claude Desktop using the GUI (File->Close)
   - Reopen the application:
     ```bash
     claude-desktop
     ```

## Usage

1. After setting up and launching Claude Desktop with the MCP configuration, create a new chat.

## Security Considerations

- **Important**: This tool should only be used on systems you own or have explicit permission to test.
- Using this tool against unauthorized targets may be illegal and unethical.
- Always follow responsible disclosure practices for any vulnerabilities discovered.

## Contributing

Contributions to NeuroPwn are welcome! Please feel free to submit pull requests or open issues to improve the tool.

## License

[MIT License](LICENSE)

## Disclaimer

NeuroPwn is provided for educational and legitimate security testing purposes only. The creators are not responsible for any misuse of this tool or for any damage that may result from its use.
