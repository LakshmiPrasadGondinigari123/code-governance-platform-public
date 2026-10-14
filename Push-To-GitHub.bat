@echo off
rem Pushes this project to GitHub. A browser window opens once to sign in to GitHub (Git Credential Manager).
set "PATH=%USERPROFILE%\portablegit\cmd;%PATH%"
cd /d "%~dp0"
git fetch origin
git merge origin/main --allow-unrelated-histories -s ours -m "Merge previous remote history (keep rebuilt platform)"
git push -u origin main
echo.
echo Done. Repo: https://github.com/LakshmiPrasadGondinigari123/code-governance-platform
pause
