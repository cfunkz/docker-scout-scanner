## How do (LINUX ONLY)
Testend on AlmaLinux only.

![image](https://github.com/user-attachments/assets/74dca4ca-6a6a-414f-b92d-8a9aee3fcaf1)
![image](https://github.com/user-attachments/assets/aeb36668-25d1-4b85-a5ad-a34f39359775)

### What to have prior
Before using the `docker-scout-scanner` script, you need the following installed:

1. **Docker** - Make sure Docker is installed and running on your system.
   - [Install Docker](https://docs.docker.com/get-docker/)

2. **Docker Scout** - Install Docker Scout CLI.
   - Get link to latest [Docker Scout](https://github.com/docker/scout-cli/releases)
   - Download ```curl -fsSL <link to the latest .TAR file> -o docker-scout.tar.gz```
   - Extract ```tar -xvzf docker-scout.tar.gz```
   - Make plugins dir if not there ```mkdir -p ~/.docker/cli-plugins```
   - Move the script to the plugins folder ```mv docker-scout ~/.docker/cli-plugins/```
   - Check if working by ```docker scout --version```

### What do

1. **Clone the Repository**:
   First, clone the repository to your local machine or download file:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/cfunkz/docker-scout-scanner/main/dockerscout_scan.sh -o dockerscout_scan.sh
   
2. Make the script runnable:
   - ```chmod +x dockerscout_scan.sh```
   - Run the script ```./dockerscout_scan.sh```
