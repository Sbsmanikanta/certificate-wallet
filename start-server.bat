@echo off
cd /d "%~dp0"
if not exist DocumentVaultServer.class (
  javac DocumentVaultServer.java
)
if errorlevel 1 exit /b 1
java DocumentVaultServer
