@echo off
set LOG_DIR=D:\Emulator\logs
if not exist %LOG_DIR% mkdir %LOG_DIR%

echo Running Client1.tac...
start cmd /k twistd -n  -y D:\Emulator\Examples\WC\Topology\Client_client1.tac
timeout /t 1 /nobreak >nul

@REM echo Running Client2.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\WC\Topology\Client_client2.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Provider1.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\WC\Topology\Provider_provider1.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Mixnode1.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\WC\Topology\Mixnode_mix1.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Mixnode2.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\WC\Topology\Mixnode_mix2.tac
@REM timeout /t 1 /nobreak >nul
@REM
@REM echo Running Mixnode3.tac...
@REM start cmd /k twistd -n  -y D:\Emulator\Examples\WC\Topology\Mixnode_mix3.tac
@REM timeout /t 1 /nobreak >nul

echo All processes have been started.
pause
