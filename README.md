## How to Use (LINUX ONLY)

### Prerequisites
Before using the `docker-scout-scanner` script, you need the following installed:

1. **Docker** - Make sure Docker is installed and running on your system.
   - [Install Docker](https://docs.docker.com/get-docker/)

2. **Docker Scout** - Install Docker Scout CLI.
   - Download latest release [Docker Scout](https://github.com/docker/scout-cli/releases)
   - Download ```curl -fsSL ,link to TAR file) -o docker-scout.tar.gz```
   - Extract ```tar -xvzf docker-scout.tar.gz```
   - Make plugins dir if not there ```mkdir -p ~/.docker/cli-plugins```
   - Move the script to the plugins folder ```mv docker-scout ~/.docker/cli-plugins/```
   - Check if working by ```docker scout --version```

### Steps to Use the Script

1. **Clone the Repository**:
   First, clone the repository to your local machine:

   ```bash
   git clone https://github.com/<your-username>/docker-scout-scanner.git
   cd docker-scout-scanner
