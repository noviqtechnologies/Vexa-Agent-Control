# ─── Amazon RDS PostgreSQL Database (Optional Managed Persistence) ────────────
# When enable_rds = true, provisions an Amazon RDS PostgreSQL instance to ensure
# durability for provider API keys, virtual keys, audit events, and spend analytics.
# By default (enable_rds = false), an in-task PostgreSQL container is used to minimize costs ($0 extra).

resource "random_password" "rds_password" {
  count   = var.enable_rds ? 1 : 0
  length  = 24
  special = false
}

resource "aws_db_subnet_group" "rds" {
  count      = var.enable_rds ? 1 : 0
  name       = "${local.name_prefix}-rds-subnet-group"
  subnet_ids = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  tags = {
    Name = "${local.name_prefix}-rds-subnet-group"
  }
}

resource "aws_security_group" "rds" {
  count       = var.enable_rds ? 1 : 0
  name        = "${local.name_prefix}-rds-sg"
  description = "Allow inbound PostgreSQL traffic from ECS tasks"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-rds-sg"
  }
}

resource "aws_db_instance" "postgres" {
  count                  = var.enable_rds ? 1 : 0
  identifier             = "${local.name_prefix}-pg"
  engine                 = "postgres"
  engine_version         = "16"
  instance_class         = var.rds_instance_class
  allocated_storage      = var.rds_allocated_storage
  storage_type           = "gp3"
  db_name                = var.postgres_db
  username               = var.postgres_user
  password               = random_password.rds_password[0].result
  db_subnet_group_name   = aws_db_subnet_group.rds[0].name
  vpc_security_group_ids = [aws_security_group.rds[0].id]
  skip_final_snapshot    = var.environment != "prod"
  publicly_accessible    = false

  tags = {
    Name = "${local.name_prefix}-postgres"
  }
}
