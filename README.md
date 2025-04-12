# NeuroPwn

NeuroPwn is a proof-of-concept tool that demonstrates an agent-based approach to automatically discover security vulnerabilities. The system leverages Claude as the MCP (Model Context Protocol) client while operating with a Kali Linux MCP server backend.
This architecture allows NeuroPwn to combine the reasoning capabilities of advanced AI models with the specialized security tools available in Kali Linux, creating a powerful automated security assessment system.

# Quickstart

1. `docker build -t kali-vnc .`
2. `docker run -p 6080:6080 --name kali-container kali-web-vnc`
3. Open `http://127.0.0.1:6080/` with Password `password`
4. Open a terminal (Right mouse click on Dektop)
5. Open `claude-dektop` in the terminal
6. Create the file /home/kaliuser/.config/Claude/claude_desktop_config.json with the content:
```
{
    "mcpServers": {
        "kali_mcp": {
            "command": "/bin/bash",
            "args": [
                "-c",
                "/home/kaliuser/start-mcp-server.sh"
            ]
        }
    }
}
```
7. Close claude-desktop using the GUI (File->Close)
8. Open  `claude-dektop` in the terminal again

# Installation on Kali Linux

TODO