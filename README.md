# WolfSSH Mapper

## Overview

This project provides two variants of the SSH mapper binary, each using a different optimization strategy:

- `original-ssh-mapper-binaries/` — optimized with **EOF + known replies**
- `oob-ssh-mapper-binaries/` — optimized with **EOF + OOB**

## Getting Started

### 1. Build the WolfSSH Docker Image

Navigate to the project directory and build the Docker image:

```bash
cd wolfssh-mapper
chmod +x build.sh
./build.sh
```

### 2. Start the WolfSSH Container

The `wolfssh-mapper` directory will be automatically mounted to `/project` inside the container.

```bash
docker-compose up -d
```

**Note:** The SSH server is exposed on port `2222` (host) → port `22` (container)

### 3. Access the Container and Build the Project

```bash
docker exec -it wolfssh-server bash
cd /project
make all
```

### 4. Run with OOB Handler

Use the preloaded OOB handler library to run the SSH server:

```bash
LD_PRELOAD=./build/oob-handler.so ./run.sh
```

## Testing

### Using ssh-run

Test the SSH server using the `ssh-run` 

```bash
RUST_LOG=DEBUG ./ssh-run \
  -t 10 \
  -e localhost:2222 \
  -s client \
  -i KexInit KexECDHInit NewKeys ServiceRequestUserAuth AuthRequestPassword
```

## Project Structure

```text
wolfssh-mapper/
├── build.sh              # Docker image build script
├── Dockerfile            # Docker image definition
├── docker-compose.yml    # Container configuration
├── build/               # Compiled binaries and libraries
│   └── oob-handler.so  # OOB handler shared library
└── run.sh              # Server startup script
```
