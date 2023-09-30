# Tested with python 3.10 and PyInstaller 5.4.1
# Run with ./release/generate_linux_binary.sh

pip3 install -r requirements.txt
pyinstaller  --onefile --clean --target-arch universal2 cloudgrep.py
