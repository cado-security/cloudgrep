# Run with ./release/generate_linux_binary.sh
pwd
ls
pip3 install -r requirements.txt
pyinstaller  --onefile --name cloudgrep --clean ./cloudgrep/__main__.py
