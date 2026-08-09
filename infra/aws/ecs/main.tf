terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "agentwall"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "eu-west-1"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "container_image" {
  description = "Universal public image reference (Docker Hub, GHCR, or AWS ECR Public) consumable across AWS, Azure, GCP, and On-Prem"
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentwall:latest"
}

# ─── VPC & Public Subnets ─────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "agentwall-ecs-vpc" }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "agentwall-ecs-igw" }
}

resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "b" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public.id
}

# ─── Security Group ───────────────────────────────────────────────────────────

resource "aws_security_group" "ecs" {
  name        = "agentwall-ecs-sg"
  description = "Allow HTTP inbound to AgentWall Gateway (8080) and Control Plane (8081)"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ─── Application Load Balancer (ALB) ──────────────────────────────────────────

resource "aws_lb" "alb" {
  name               = "agentwall-ecs-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ecs.id]
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  tags = { Name = "agentwall-ecs-alb" }
}

# Target Group for Gateway (8080)
resource "aws_lb_target_group" "alb_tg" {
  name        = "agentwall-ecs-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/healthz"
    port                = "8080"
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# Target Group for Control Plane UI (8081)
resource "aws_lb_target_group" "control_plane_tg" {
  name        = "agentwall-cp-tg"
  port        = 8081
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/"
    port                = "8081"
    protocol            = "HTTP"
    matcher             = "200-399"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "8080"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_tg.arn
  }
}

resource "aws_lb_listener" "control_plane" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "8081"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.control_plane_tg.arn
  }
}

# ─── ECS Cluster ($0 control plane cost) ──────────────────────────────────────

resource "aws_ecs_cluster" "main" {
  name = "agentwall-cluster"
}

# ─── IAM Execution & Task Roles ───────────────────────────────────────────────

resource "aws_iam_role" "ecs_execution_role" {
  name = "agentwall-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ─── CloudWatch Log Group ─────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/agentwall"
  retention_in_days = 7
}

# ─── ECS Task Definition (Full Control Plane Stack) ───────────────────────────

variable "control_plane_ui_image" {
  description = "Enterprise Control Plane UI container image"
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentwall-dashboard-frontend:latest"
}

variable "control_plane_api_image" {
  description = "Enterprise Control Plane API container image"
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentwall-dashboard-api:latest"
}

variable "control_plane_db_image" {
  description = "Control Plane PostgreSQL Database container image with migrations"
  type        = string
  default     = "ghcr.io/noviqtechnologies/agentwall-db:latest"
}

resource "aws_ecs_task_definition" "agentwall" {
  family                   = "agentwall-gateway"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024" # 1.0 vCPU
  memory                   = "2048" # 2048 MiB
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
        { name = "POSTGRES_USER", value = "agentwall" },
        { name = "POSTGRES_PASSWORD", value = "devpassword" },
        { name = "POSTGRES_DB", value = "agentwall" }
      ]
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
        { name = "DATABASE_URL", value = "postgres://agentwall:devpassword@127.0.0.1:5432/agentwall?sslmode=disable" },
        { name = "DASHBOARD_PORT", value = "8400" },
        { name = "DEV_MODE", value = "true" },
        { name = "ALLOW_DEV_MODE", value = "true" },
        { name = "GATEWAY_SECRET", value = "local-dev-shared-secret-change-me" },
        { name = "POLICY_READ_SECRET", value = "local-dev-policy-read-secret" },
        { name = "GATEWAY_URL", value = "http://127.0.0.1:8080" },
        { name = "PROVIDER_KEY_ENCRYPTION_SECRET", value = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
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
        { name = "AGENTWALL_LISTEN", value = "0.0.0.0:8080" },
        { name = "DASHBOARD_API_URL", value = "http://127.0.0.1:8400" },
        { name = "POLICY_READ_SECRET", value = "local-dev-policy-read-secret" },
        { name = "GATEWAY_SECRET", value = "local-dev-shared-secret-change-me" }
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

# ─── ECS Service (Runs in Public Subnets with ALB) ───────────────────────────

resource "aws_ecs_service" "agentwall" {
  name            = "agentwall-service"
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

output "dashboard_url" {
  description = "AgentWall Local Observability Proxy Endpoint (Port 8080)"
  value       = "http://${aws_lb.alb.dns_name}:8080"
}

output "control_plane_url" {
  description = "AgentWall Enterprise Control Plane & SOC Dashboard (Port 8081)"
  value       = "http://${aws_lb.alb.dns_name}:8081"
}

output "health_url" {
  description = "Health check endpoint URL"
  value       = "http://${aws_lb.alb.dns_name}:8080/healthz"
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  value = aws_ecs_service.agentwall.name
}

output "container_image_in_use" {
  value = var.container_image
}


