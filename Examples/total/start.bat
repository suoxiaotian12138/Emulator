@echo off
set LOG_DIR=D:\Emulator\logs
if not exist %LOG_DIR% mkdir %LOG_DIR%



@REM echo Running Provider1.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Provider_provider1.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Mixnode1.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Mixnode_mix1.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Mixnode2.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Mixnode_mix2.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Mixnode3.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Mixnode_mix3.tac
@REM timeout /t 1 /nobreak >nul
@REM echo Running Mixnode4.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Mixnode_mix4.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Mixnode5.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Mixnode_mix5.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Mixnode6.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Mixnode_mix6.tac
@REM timeout /t 1 /nobreak >nul



echo Running Client2.tac...
start cmd /k twistd -n  -y D:\Emulator\Examples\total\WCClient_client2.tac
timeout /t 1 /nobreak >nul


echo Running Client1.tac...
start cmd /k twistd -n  -y D:\Emulator\Examples\total\WCClient_client1.tac
timeout /t 1 /nobreak >nul

@REM echo Running Client1.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\total\Client_client1_cc.tac
@REM timeout /t 1 /nobreak >nul


echo All processes have been started.
pause
