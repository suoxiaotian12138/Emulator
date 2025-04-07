@echo off

set PROJECT_PATH=D:\project\Oniverse

set COMMIT_MESSAGE=Auto-sync: %date% %time%

cd /d %PROJECT_PATH%

git diff-index --quiet HEAD --
if errorlevel 1 (
    echo updating...
    git add .
    git commit -m "%COMMIT_MESSAGE%"
    git push -u origin main
    echo update successfully
) else (
    echo no change
)
