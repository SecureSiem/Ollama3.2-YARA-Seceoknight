A. Install Ollama (System Service)
1. Install Ollama
        
                curl -fsSL https://ollama.com/install.sh | sh

2. Verify Installation
        
                systemctl status ollama
                which ollama
                ollama --version


Expected binary location:

/usr/local/bin/ollama

B. Create Models Directory and Set Permissions

This step ensures the Ollama system service (running as the ollama user) can read and write model files.

1. Create the models directory
    
                sudo mkdir -p /var/lib/ollama/models

2. Confirm the Ollama service user exists

                id ollama

3. Set ownership and permissions

                sudo chown -R ollama:ollama /var/lib/ollama

                sudo chmod 750 /var/lib/ollama

                sudo chmod 750 /var/lib/ollama/models

C. Configure Ollama Using systemd Override
1. Edit the systemd override file
    sudo systemctl edit ollama


Add the following configuration:

    [Service]
    Environment="OLLAMA_HOST=0.0.0.0:11434"
    Environment="OLLAMA_MODELS=/var/lib/ollama/models"


Save and exit.

2. Apply configuration changes

        sudo systemctl daemon-reload
        sudo systemctl restart ollama

3. Verify effective configuration
    systemctl cat ollama

D. Install Ollama Models

Since Ollama runs as a system service, use sudo to avoid permission issues.

Option 1: Pull the model explicitly
    sudo ollama pull llama3.2

Option 2: Run the model (auto-pull if not installed)
    sudo ollama run llama3.2

Verify installed models
    sudo ollama list
    sudo ollama show llama3.2

E. Verify Model Files on Disk
    sudo ls -la /var/lib/ollama/models
    sudo du -sh /var/lib/ollama/models


Expected directories:

blobs/
manifests/

F. Verify Ollama API Access (For Wazuh Integration)
1. List available models via API
    curl http://127.0.0.1:11434/api/tags

2. Generate a test response
    curl http://127.0.0.1:11434/api/generate \
      -d '{"model":"llama3.2","prompt":"hello"}'

3. Confirm port is listening
    ss -tulnp | grep 11434

Security Note

If Wazuh runs on the same host, bind Ollama to localhost:

    Environment="OLLAMA_HOST=127.0.0.1:11434"


If Wazuh is on a remote host, keep 0.0.0.0 but restrict access using firewall rules.

Summary

Ollama is installed as a system service

Models are stored in /var/lib/ollama/models

Configuration is managed via systemd overrides

The Ollama API is available on port 11434

This setup is suitable for Wazuh and SOC automation use cases
