Write-Host "Building and starting AgentWall Demo..." -ForegroundColor Cyan
docker compose -f docker-compose.demo.yml up --build
