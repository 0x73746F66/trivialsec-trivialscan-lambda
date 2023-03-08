resource "aws_dynamodb_table" "login_sessions" {
  name           = "${lower(var.app_env)}_login_sessions"
  billing_mode   = "PAY_PER_REQUEST"
  table_class    = "STANDARD"

  server_side_encryption {
    enabled = true
  }

  attribute {
    name = "session_token"
    type = "S"
  }

  attribute {
    name = "member_email"
    type = "S"
  }

  global_secondary_index {
    name               = "member_email-index"
    hash_key           = "member_email"
    projection_type    = "KEYS_ONLY"
  }

  hash_key = "session_token"
  tags = local.tags
}

resource "aws_dynamodb_table" "report_history" {
  name           = "${lower(var.app_env)}_report_history"
  billing_mode   = "PAY_PER_REQUEST"
  table_class    = "STANDARD"

  server_side_encryption {
    enabled = true
  }

  attribute {
    name = "report_id"
    type = "S"
  }

  attribute {
    name = "account_name"
    type = "S"
  }

  global_secondary_index {
    name               = "account_name-index"
    hash_key           = "account_name"
    projection_type    = "KEYS_ONLY"
  }

  hash_key = "report_id"
  tags = local.tags
}

resource "aws_dynamodb_table" "observed_identifiers" {
  name           = "${lower(var.app_env)}_observed_identifiers"
  billing_mode   = "PAY_PER_REQUEST"
  table_class    = "STANDARD"

  server_side_encryption {
    enabled = true
  }

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "account_name"
    type = "S"
  }

  attribute {
    name = "address"
    type = "S"
  }

  global_secondary_index {
    name               = "account_name-index"
    hash_key           = "account_name"
    projection_type    = "KEYS_ONLY"
  }

  global_secondary_index {
    name               = "address-index"
    hash_key           = "address"
    projection_type    = "KEYS_ONLY"
  }

  hash_key = "id"
  tags = local.tags
}

resource "aws_dynamodb_table" "early_warning_service" {
  name           = "${lower(var.app_env)}_early_warning_service"
  billing_mode   = "PAY_PER_REQUEST"
  table_class    = "STANDARD"

  server_side_encryption {
    enabled = true
  }

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "account_name"
    type = "S"
  }

  attribute {
    name = "feed_identifier"
    type = "S"
  }

  global_secondary_index {
    name               = "account_name-index"
    hash_key           = "account_name"
    projection_type    = "KEYS_ONLY"
  }

  global_secondary_index {
    name               = "feed_identifier-index"
    hash_key           = "feed_identifier"
    projection_type    = "KEYS_ONLY"
  }

  hash_key = "id"
  tags = local.tags
}

resource "aws_dynamodb_table" "member_fido" {
  name           = "${lower(var.app_env)}_member_fido"
  billing_mode   = "PAY_PER_REQUEST"
  table_class    = "STANDARD"

  server_side_encryption {
    enabled = true
  }

  attribute {
    name = "record_id"
    type = "S"
  }

  attribute {
    name = "member_email"
    type = "S"
  }

  global_secondary_index {
    name               = "member_email-index"
    hash_key           = "member_email"
    projection_type    = "KEYS_ONLY"
  }

  hash_key = "record_id"
  tags = local.tags
}

resource "aws_dynamodb_table" "findings" {
  name           = "${lower(var.app_env)}_findings"
  billing_mode   = "PAY_PER_REQUEST"
  table_class    = "STANDARD"

  server_side_encryption {
    enabled = true
  }

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "account_name"
    type = "S"
  }

  global_secondary_index {
    name               = "account_name-index"
    hash_key           = "account_name"
    projection_type    = "KEYS_ONLY"
  }

  hash_key = "finding_id"
  tags = local.tags
}
