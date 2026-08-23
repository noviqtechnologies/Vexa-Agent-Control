# Windows Command Prompt (CMD) Guide

This guide covers installing and running Vexa Agent Control using the traditional Windows Command Prompt (`cmd.exe`).

---

## Installation via CMD

Because Windows Command Prompt does not have native cryptographic hash and JSON parsing primitives, the CMD installer uses PowerShell under the hood in a single command:

1. Open `cmd.exe`.
2. Run the bootstrap command:
   ```cmd
   curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 -o "%TEMP%\install.ps1" && powershell.exe -ExecutionPolicy Bypass -File "%TEMP%\install.ps1" && del "%TEMP%\install.ps1"
   ```
3. Add the binary directory to your current CMD session:
   ```cmd
   set PATH=%USERPROFILE%\.local\bin;%PATH%
   ```
4. Verify:
   ```cmd
   agentcontrol.exe --version
   ```

---

## Starting Protection in CMD

```cmd
:: Start in active protection mode:
agentcontrol.exe protect

:: Or start in shadow/observation mode:
agentcontrol.exe protect --shadow
```

---

## Running Verification

In a second CMD prompt window:

```cmd
agentcontrol.exe verify
```

---

## Clean Uninstallation from CMD

```cmd
powershell.exe -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.ps1 | iex"
```
