# ─── ECS Task Definition (Full Control Plane Stack) ───────────────────────────

resource "aws_ecs_task_definition" "agentwall" {
  family                   = "${local.name_prefix}-gateway"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "postgres"
      image     = var.control_plane_db_image
      essential = true
      portMappings = [
        {
          containerPort = 5432
          hostPort      = 5432
        }
      ]
      environment = [
        { name = "POSTGRES_USER", value = var.postgres_user },
        { name = "POSTGRES_PASSWORD", value = local.postgres_password },
        { name = "POSTGRES_DB", value = var.postgres_db }
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "pg_isready -U ${var.postgres_user} -d ${var.postgres_db}"]
        interval    = 5
        timeout     = 5
        retries     = 5
        startPeriod = 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "postgres"
        }
      }
    },
    {
      name      = "valkey"
      image     = "valkey/valkey:7.2-alpine"
      essential = true
      portMappings = [
        {
          containerPort = 6379
          hostPort      = 6379
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "valkey"
        }
      }
    },
    {
      name      = "dashboard-api"
      image     = var.control_plane_api_image
      essential = true
      portMappings = [
        {
          containerPort = 8400
          hostPort      = 8400
        }
      ]
      environment = [
        { name = "DATABASE_URL", value = "postgres://${var.postgres_user}:${local.postgres_password}@127.0.0.1:5432/${var.postgres_db}?sslmode=disable" },
        { name = "VALKEY_URL", value = "127.0.0.1:6379" },
        { name = "DASHBOARD_PORT", value = "8400" },
        { name = "ENVIRONMENT", value = var.environment },
        { name = "DEV_MODE", value = var.environment == "dev" ? "true" : "false" },
        { name = "ALLOW_DEV_MODE", value = var.environment == "dev" ? "true" : "false" },
        { name = "GATEWAY_SECRET", value = local.gateway_secret },
        { name = "POLICY_READ_SECRET", value = local.policy_read_secret },
        { name = "GATEWAY_URL", value = "http://127.0.0.1:8080" },
        { name = "PROVIDER_KEY_ENCRYPTION_SECRET", value = local.encryption_secret },
        { name = "AGENTWALL_SESSION_SECRET", value = local.session_secret },
        { name = "AGENTCONTROL_SESSION_SECRET", value = local.session_secret },
        { name = "DIRECT_TLS_ENABLED", value = "true" },
        { name = "INGRESS_AUTH_SECRET", value = local.gateway_secret }
      ]
      dependsOn = [
        {
          containerName = "postgres"
          condition     = "HEALTHY"
        },
        {
          containerName = "valkey"
          condition     = "START"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "dashboard-api"
        }
      }
    },
    {
      name      = "control-plane-ui"
      image     = var.control_plane_ui_image
      essential = true
      portMappings = [
        {
          containerPort = 8081
          hostPort      = 8081
        }
      ]
      environment = [
        { name = "DASHBOARD_API_URL", value = "http://127.0.0.1:8400" },
        { name = "AGENTCONTROL_API_URL", value = "http://127.0.0.1:8400" }
      ]
      dependsOn = [
        {
          containerName = "dashboard-api"
          condition     = "START"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "control-plane-ui"
        }
      }
    },
    {
      name      = "gateway"
      image     = var.container_image
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ]
      environment = [
        { name = "AGENTCONTROL_LISTEN", value = "0.0.0.0:8080" },
        { name = "AGENTWALL_LISTEN", value = "0.0.0.0:8080" },
        { name = "AGENTCONTROL_CENTRALIZED", value = "true" },
        { name = "AGENTCONTROL_ADMIN_TOKEN", value = local.gateway_secret },
        { name = "AGENTCONTROL_POLICY_PATH", value = "/app/policy.example.yaml" },
        { name = "AGENTCONTROL_HUB_URL", value = "http://127.0.0.1:8400" },
        { name = "DASHBOARD_API_URL", value = "http://127.0.0.1:8400" },
        { name = "POLICY_READ_SECRET", value = local.policy_read_secret },
        { name = "GATEWAY_SECRET", value = local.gateway_secret },
        { name = "POLICY_POLL_INTERVAL_SECS", value = "30" },
        { name = "AGENTCONTROL_LOG_PATH", value = "/var/log/agentcontrol/audit.log" },
        { name = "AGENTWALL_LOG_PATH", value = "/var/log/agentcontrol/audit.log" }
      ]
      dependsOn = [
        {
          containerName = "dashboard-api"
          condition     = "START"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "gateway"
        }
      }
    }
  ])
}

# ─── ECS Service ──────────────────────────────────────────────────────────────

resource "aws_ecs_service" "agentwall" {
  name            = "${local.name_prefix}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.agentwall.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.public_1.id, aws_subnet.public_2.id]
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.alb_tg.arn
    container_name   = "gateway"
    container_port   = 8080
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.control_plane_tg.arn
    container_name   = "control-plane-ui"
    container_port   = 8081
  }

  depends_on = [aws_lb_listener.http, aws_lb_listener.control_plane]
}
