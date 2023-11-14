dir
python3 -m pip install -r ../requirements.txt
python3 -m PyInstaller --name cloudgrep --onefile ../cloudgrep/__main__.py
