@echo off
set LOG_DIR=D:\Oniverse\Emulator\logs
if not exist %LOG_DIR% mkdir %LOG_DIR%



echo Running Provider1.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\Provider_provider1_cc.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode1.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\Mixnode_mix1.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode2.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\Mixnode_mix2.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode3.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\Mixnode_mix3.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode4.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\Mixnode_mix4.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode5.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\Mixnode_mix5.tac
timeout /t 1 /nobreak >nul

echo Running Mixnode6.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\Mixnode_mix6.tac
timeout /t 1 /nobreak >nul

echo Running Client1-cc.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\Client_client1_cc.tac
timeout /t 1 /nobreak >nul

echo Running Client2.tac...
start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\WCClient_client2.tac
timeout /t 1 /nobreak >nul


@REM echo Running Client1.tac...
@REM start cmd /k twistd -n  -y D:\Oniverse\Emulator\Examples\total\WCClient_client1.tac
@REM timeout /t 1 /nobreak >nul

@REM echo Running Client1.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Client_client1_cc.tac
@REM timeout /t 1 /nobreak >nul


echo All processes have been started.
pause
