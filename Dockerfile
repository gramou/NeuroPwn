FROM kalilinux/kali-rolling

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm
ENV DISPLAY=:1
ENV LANG=en_US.UTF-8
ENV LC_ALL=C.UTF-8

# Update and install essential packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    kali-desktop-xfce \
    xfce4 \
    xfce4-terminal \
    tightvncserver \
    xfonts-base \
    xfonts-100dpi \
    xfonts-75dpi \
    xfonts-cyrillic \
    dbus-x11 \
    nikto \
    nmap \
    dirb \
    net-tools \
    gobuster \
    sqlmap \
    hydra \
    john \
    wpscan \
    enum4linux \
    procps \
    wget \
    curl \
    git \
    python3 \
    python3-pip \
    python3-numpy \
    python3-websockify \
    ca-certificates \
    supervisor \
    locales \
    sudo \
    p7zip-full \
    icoutils \
    imagemagick \
    nodejs \
    npm \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Generate UTF-8 locale
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales

# Create a non-root user
RUN useradd -m kaliuser -s /bin/bash && \
    echo "kaliuser:kalipassword" | chpasswd && \
    usermod -aG sudo kaliuser && \
    echo "kaliuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Setup VNC for the non-root user
ENV USER=kaliuser
ENV HOME=/home/kaliuser

# Setup directories owned by kaliuser
RUN mkdir -p /home/kaliuser/.vnc && \
    mkdir -p /var/log/supervisor

# Setup VNC password and configuration for kaliuser
RUN echo "password" | vncpasswd -f > /home/kaliuser/.vnc/passwd && \
    chmod 600 /home/kaliuser/.vnc/passwd && \
    touch /home/kaliuser/.Xauthority && \
    echo '#!/bin/bash\nxrdb $HOME/.Xresources\nstartxfce4 &' > /home/kaliuser/.vnc/xstartup && \
    chmod +x /home/kaliuser/.vnc/xstartup && \
    chown -R kaliuser:kaliuser /home/kaliuser

# Install noVNC (web-based VNC client)
RUN mkdir -p /usr/local/novnc && \
    git clone --depth 1 https://github.com/novnc/noVNC.git /usr/local/novnc && \
    git clone --depth 1 https://github.com/novnc/websockify /usr/local/novnc/utils/websockify && \
    ln -s /usr/local/novnc/vnc.html /usr/local/novnc/index.html

# Create supervisord.conf
RUN echo '[supervisord]\nnodaemon=true\n\n[program:vncserver]\ncommand=su - kaliuser -c "/usr/bin/vncserver :1 -geometry 1280x800 -depth 24"\nautorestart=true\n\n[program:novnc]\ncommand=/usr/local/novnc/utils/novnc_proxy --vnc localhost:5901\nautorestart=true' > /etc/supervisor/conf.d/supervisord.conf

# Add these lines to your Dockerfile before the Claude Desktop installation

# Install additional X11 and graphics libraries
RUN apt-get update && apt-get install -y \
    libx11-xcb1 \
    libxcb-dri3-0 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxi6 \
    libxtst6 \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libgtk-3-0 \
    libdrm2 \
    libgbm1 \
    libasound2 \
    xdg-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for Electron
ENV ELECTRON_DISABLE_SANDBOX=1
ENV ELECTRON_NO_SANDBOX=1
ENV ELECTRON_DISABLE_GPU=1
ENV ELECTRON_DISABLE_SECCOMP_FILTER_SANDBOX=1

# Install Claude Desktop dependencies and prepare build
RUN apt-get update && \
    apt-get install -y \
    p7zip-full \
    icoutils \
    imagemagick \
    nodejs \
    npm \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/aaddrick/claude-desktop-debian.git /tmp/claude-desktop-debian \
    && cd /tmp/claude-desktop-debian \
    && sed -i 's/check_dependencies/#check_dependencies/g' build.sh \
    && sed -i 's/check_root_privilege/#check_root_privilege/g' build.sh \
    && sed -i 's/prompt_sudo/#prompt_sudo/g' build.sh \
    && chown -R kaliuser:kaliuser /tmp/claude-desktop-debian

# Build and install Claude Desktop as kaliuser
RUN su - kaliuser -c "cd /tmp/claude-desktop-debian && ./build.sh" && \
    dpkg -i /tmp/claude-desktop-debian/claude-desktop_*.deb

# Modify the claude-desktop launch script after installation
RUN if [ -f /usr/bin/claude-desktop ]; then \
    sed -i 's/ELECTRON_ARGS=(/ELECTRON_ARGS=(--no-sandbox --disable-gpu --disable-software-rasterizer /' /usr/bin/claude-desktop; \
    fi

# Entry point script
RUN echo '#!/bin/bash\nset -e\n\n# Kill any existing VNC sessions\nsu - kaliuser -c "vncserver -kill :1" >/dev/null 2>&1 || true\n\n# Start supervisord\nexec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf' > /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

RUN apt-get update && apt-get install -y python3-venv vim

COPY python/kali-mcp-server.py /home/kaliuser
COPY script/start-mcp-server.sh /home/kaliuser

RUN chown kaliuser:kaliuser /home/kaliuser/kali-mcp-server.py
RUN chmod +x /home/kaliuser/start-mcp-server.sh && chown kaliuser:kaliuser /home/kaliuser/start-mcp-server.sh

COPY script/setup-mcp-server.sh /home/kaliuser
RUN chmod +x /home/kaliuser/setup-mcp-server.sh && chown kaliuser:kaliuser /home/kaliuser/setup-mcp-server.sh

COPY python/test-client.py /home/kaliuser
RUN chmod +x /home/kaliuser/test-client.py && chown kaliuser:kaliuser home/kaliuser/test-client.py

# Set the working directory
WORKDIR /home/kaliuser
USER kaliuser
RUN mkdir -p /home/kaliuser/.config/Claude
COPY config/claude_desktop_config.json /home/kaliuser/.config/Claude
RUN /home/kaliuser/setup-mcp-server.sh
USER root

# Expose noVNC port
EXPOSE 6080

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]