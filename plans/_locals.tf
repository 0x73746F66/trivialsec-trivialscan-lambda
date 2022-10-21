locals {
    aws_master_account_id = 984310022655
    aws_default_region    = "ap-southeast-2"
    python_version        = "python3.9"
    source_file           = "${lower(var.app_env)}-${var.app_name}.zip"
    function_name         = "${lower(var.app_env)}-trivialscan-api"
    hosted_zone           = "Z04169281YCJD2GS4F5ER"
    domain_name           = "${lower(var.app_env)}-api.trivialsec.com"
    acm_arn               = "arn:aws:acm:us-east-1:${local.aws_master_account_id}:certificate/8ba67bad-47e9-4936-a860-d47ae4bafba6" #this needs to be us-east-1, do not change
    tags                  = {
        ProjectName = "trivialscan"
        ProjectLeadEmail = "chris@trivialsec.com"
        CostCenter = var.app_env != "Prod" ? "randd" : "opex"
        SecurityTags = "credentials customer-data public-data"
        AutomationTool = "Terraform"
    }
}
