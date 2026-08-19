Stop-Process -Name "agentcontrol" -Force -ErrorAction SilentlyContinue
# Set your OpenAI API key via environment variable before running this script.
# Export it in your shell: $env:OPENAI_API_KEY = "sk-proj-..."
# Or set it in your system environment variables.
if (-not $env:OPENAI_API_KEY) {
    Write-Error "OPENAI_API_KEY environment variable is not set. Aborting."
    exit 1
}
target\debug\agentcontrol.exe start --listen 127.0.0.1:8080 --policy test-llm-policy.yaml
