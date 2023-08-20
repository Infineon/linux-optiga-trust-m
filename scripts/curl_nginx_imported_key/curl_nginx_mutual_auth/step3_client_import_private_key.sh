#!/bin/bash
source config.sh


set -e
echo "Import Key using Optiga Trust M Explorer"

cd $PROJECT_DIR
cd ../
lxterminal -e ./start_gui.sh
