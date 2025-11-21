#!/bin/bash
set -e

IMAGE="wolfssh:latest"
docker build -t $IMAGE .
echo "Build $IMAGE successful!"
