@echo off
set LOG_DIR=D:\project\Oniverse\logs
if not exist %LOG_DIR% mkdir %LOG_DIR%

echo Running Client1.tac...
start cmd /k twistd -n  -y D:\project\Oniverse\Client_client1.tac
timeout /t 1 /nobreak >nul

echo Running Client2.tac...
start cmd /k twistd -n  -y D:\project\Oniverse\Client_client2.tac
timeout /t 1 /nobreak >nul

echo Running Provider1.tac...
start cmd /k twistd -n  -y D:\project\Oniverse\Provider_provider1.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode1.tac...
start cmd /k twistd -n  -y D:\project\Oniverse\Mixnode_mix1.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode2.tac...
start cmd /k twistd -n  -y D:\project\Oniverse\Mixnode_mix2.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode3.tac...
start cmd /k twistd -n  -y D:\project\Oniverse\Mixnode_mix3.tac
timeout /t 1 /nobreak >nul



echo All processes have been started.
pause
