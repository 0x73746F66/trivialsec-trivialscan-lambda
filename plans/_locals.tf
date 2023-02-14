locals {
    aws_master_account_id = 984310022655
    aws_default_region    = "ap-southeast-2"
    python_version        = "python3.9"
    source_file           = "${lower(var.app_env)}-${var.app_name}.zip"
    function_name         = "${lower(var.app_env)}-trivialscan-api"
    tags                  = {
        ProjectName = "trivialscan"
        ProjectLeadEmail = "chris@trivialsec.com"
        CostCenter = var.app_env != "Prod" ? "randd" : "opex"
        SecurityTags = "credentials customer-data public-data"
        AutomationTool = "Terraform"
    }
    hosted_zone           = "Z04169281YCJD2GS4F5ER"
    domain_name           = "${lower(var.app_env)}-api.trivialsec.com"
    timeout               = 900
    memory_size           = 1024
    retention_in_days     = var.app_env == "Prod" ? 30 : 7
}
