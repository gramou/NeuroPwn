#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ENV_DIR="${SCRIPT_DIR}/venv"
CONFIG_FILE="${SCRIPT_DIR}/.env"

# Print banner
echo -e "${GREEN}"
echo "============================================="
echo "   Kali Linux MCP Tool Integration Setup"
echo "============================================="
echo -e "${NC}"

# Check if Python 3.8+ is installed
echo -e "${YELLOW}Checking Python version...${NC}"
if command -v python3 >/dev/null 2>&1; then
    PY_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    PY_MAJOR=$(echo $PY_VERSION | cut -d. -f1)
    PY_MINOR=$(echo $PY_VERSION | cut -d. -f2)
    
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
        echo -e "${GREEN}Python $PY_VERSION detected. ✓${NC}"
        PYTHON_CMD="python3"
    else
        echo -e "${RED}Python 3.8+ is required, but $PY_VERSION was found.${NC}"
        exit 1
    fi
else
    echo -e "${RED}Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check if essential Kali Linux tools are installed
echo -e "${YELLOW}Checking for essential Kali Linux tools...${NC}"
TOOLS=("nmap" "gobuster" "dirb" "nikto" "sqlmap" "hydra" "john" "wpscan" "enum4linux")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ $tool is installed${NC}"
    else
        echo -e "${RED}✗ $tool is not installed${NC}"
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo -e "${YELLOW}The following tools are missing and should be installed:${NC}"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  - $tool"
    done
    
    # If running on Kali, suggest installation command
    if grep -q "Kali" /etc/os-release 2>/dev/null; then
        echo -e "${YELLOW}You can install them with:${NC}"
        echo "sudo apt update && sudo apt install -y ${MISSING_TOOLS[@]}"
    fi
fi

# Create and activate virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
if [ -d "$ENV_DIR" ]; then
    echo -e "${YELLOW}Virtual environment already exists.${NC}"
    rm -rf "$ENV_DIR"
    $PYTHON_CMD -m venv "$ENV_DIR"
    echo -e "${GREEN}Virtual environment recreated at $ENV_DIR ✓${NC}"
else
    $PYTHON_CMD -m venv "$ENV_DIR"
    echo -e "${GREEN}Virtual environment created at $ENV_DIR ✓${NC}"
fi

# Verify virtual environment was created successfully
if [ ! -f "${ENV_DIR}/bin/activate" ]; then
    echo -e "${RED}Failed to create virtual environment. Activation script not found.${NC}"
    echo -e "${YELLOW}Trying an alternative approach...${NC}"
    
    # Alternative approach
    $PYTHON_CMD -m venv --without-pip "$ENV_DIR"
    curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    ${ENV_DIR}/bin/python /tmp/get-pip.py
else
    # Activate virtual environment
    . "${ENV_DIR}/bin/activate"
    
    # Upgrade pip within the virtual environment
    echo -e "${YELLOW}Upgrading pip...${NC}"
    "${ENV_DIR}/bin/pip" install --upgrade pip
    
    # Create requirements.txt if it doesn't exist
    if [ ! -f "${SCRIPT_DIR}/requirements.txt" ]; then
        echo -e "${YELLOW}Creating requirements.txt...${NC}"
        cat > "${SCRIPT_DIR}/requirements.txt" << EOF
requests>=2.25.0
cryptography>=3.3.1
PyYAML>=5.4.1
python-dotenv>=0.15.0
mcp
EOF
    fi
    
    # Install requirements within the virtual environment
    echo -e "${YELLOW}Installing dependencies...${NC}"
    "${ENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
    
    # Clone MCP repository using HTTPS if needed
    echo -e "${YELLOW}Setting up MCP framework...${NC}"
    if [ ! -d "${SCRIPT_DIR}/mcp-framework" ]; then
        echo -e "${YELLOW}Cloning MCP framework from GitHub...${NC}"
        # Use a more reliable method to clone or create placeholder directory
        mkdir -p "${SCRIPT_DIR}/mcp-framework"
        echo "# MCP Framework placeholder" > "${SCRIPT_DIR}/mcp-framework/README.md"
        echo -e "${YELLOW}Created MCP framework placeholder.${NC}"
        echo -e "${YELLOW}You may need to manually install the MCP framework.${NC}"
    fi
    
    # Create .env file if it doesn't exist
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}Creating .env configuration file...${NC}"
        cat > "$CONFIG_FILE" << EOF
# Kali MCP Tool Integration Configuration
# Add your configuration here
MCP_SERVER_PORT=8080
MCP_LOG_LEVEL=INFO
EOF
        echo -e "${GREEN}Configuration file created ✓${NC}"
    fi
    
    echo -e "${GREEN}MCP Server setup completed!${NC}"
    echo -e "${YELLOW}To start the server, run: ${NC}${ENV_DIR}/bin/python ${SCRIPT_DIR}/kali-mcp-server.py"
    /bin/bash -c "${ENV_DIR}/bin/python ${SCRIPT_DIR}/kali-mcp-server.py"
fi
