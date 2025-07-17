variable "create_role" {
  description = "Whether to create a role"
  type        = bool
  default     = true
}

variable "role_name" {
  description = "Name of IAM role"
  type        = string
  default     = null
}

variable "role_permissions_boundary_arn" {
  description = "Permissions boundary ARN to use for IAM role"
  type        = string
  default     = null
}

variable "role_description" {
  description = "IAM Role description"
  type        = string
  default     = null
}

variable "role_name_prefix" {
  description = "IAM role name prefix"
  type        = string
  default     = null
}

variable "policy_name_prefix" {
  description = "IAM policy name prefix"
  type        = string
  default     = "AmazonEKS_"
}

variable "role_policy_arns" {
  description = "ARNs of any policies to attach to the IAM role"
  type        = map(string)
  default     = {}
}

variable "oidc_providers" {
  description = "Map of OIDC providers where each provider map should contain the `provider`, `provider_arn`, and `namespace_service_accounts`"
  type        = any
  default     = {}
}

variable "force_detach_policies" {
  description = "Whether policies should be detached from this role when destroying"
  type        = bool
  default     = true
}

variable "max_session_duration" {
  description = "Maximum CLI/API session duration in seconds between 3600 and 43200"
  type        = number
  default     = null
}

variable "assume_role_condition_test" {
  description = "Name of the [IAM condition operator](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) to evaluate when assuming the role"
  type        = string
  default     = "StringEquals"
}

################################################################################
# Policies
################################################################################

# Cert Manager
variable "attach_cert_manager_policy" {
  description = "Determines whether to attach the Cert Manager IAM policy to the role"
  type        = bool
  default     = false
}

variable "cert_manager_hosted_zone_arns" {
  description = "Route53 hosted zone ARNs to allow Cert manager to manage records"
  type        = list(string)
  default     = ["arn:aws:route53:::hostedzone/*"]
}

# Cluster autoscaler
variable "attach_cluster_autoscaler_policy" {
  description = "Determines whether to attach the Cluster Autoscaler IAM policy to the role"
  type        = bool
  default     = false
}

#Karpenter
variable "attach_karpenter_policy" {
  description = "Determines whether to attach the Karpenter Controller IAM policy to the role"
  type        = bool
  default     = false
}


#OpenSearch
variable "attach_opensearch_policy" {
  description = "Determines whether to attach the OpenSearch IAM policy to the role"
  type        = bool
  default     = false
}
variable "arn_opensearch" {
  description = "ARN of OpenSearch Domain"
  type        = string
  default     = null
}

#CSI Driver EBS
variable "attach_csi_driver_ebs_policy" {
  description = "Determines whether to attach the CSI Driver EBS IAM policy to the role"
  type        = bool
  default     = false
}

variable "eks_cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "eks-cluster"
}

variable "cluster_autoscaler_cluster_ids" {
  description = "List of cluster IDs to appropriately scope permissions within the Cluster Autoscaler IAM policy"
  type        = list(string)
  default     = []
}


# External Secrets
variable "attach_external_secrets_policy" {
  description = "Determines whether to attach the External Secrets policy to the role"
  type        = bool
  default     = false
}

variable "external_secrets_ssm_parameter_arns" {
  description = "List of Systems Manager Parameter ARNs that contain secrets to mount using External Secrets"
  type        = list(string)
  default     = ["arn:aws:ssm:*:*:parameter/*"]
}

variable "external_secrets_secrets_manager_arns" {
  description = "List of Secrets Manager ARNs that contain secrets to mount using External Secrets"
  type        = list(string)
  default     = ["arn:aws:secretsmanager:*:*:secret:*"]
}

# AWS Load Balancer Controller
variable "attach_load_balancer_controller_policy" {
  description = "Determines whether to attach the Load Balancer Controller policy to the role"
  type        = bool
  default     = false
}

# https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/guide/targetgroupbinding/targetgroupbinding/#reference
# https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/deploy/installation/#setup-iam-manually
variable "attach_load_balancer_controller_targetgroup_binding_only_policy" {
  description = "Determines whether to attach the Load Balancer Controller policy for the TargetGroupBinding only"
  type        = bool
  default     = false
}

# VPC CNI
variable "attach_vpc_cni_policy" {
  description = "Determines whether to attach the VPC CNI IAM policy to the role"
  type        = bool
  default     = false
}

variable "vpc_cni_enable_ipv4" {
  description = "Determines whether to enable IPv4 permissions for VPC CNI policy"
  type        = bool
  default     = false
}

variable "vpc_cni_enable_ipv6" {
  description = "Determines whether to enable IPv6 permissions for VPC CNI policy"
  type        = bool
  default     = false
}

# Node termination handler
variable "attach_node_termination_handler_policy" {
  description = "Determines whether to attach the Node Termination Handler policy to the role"
  type        = bool
  default     = false
}

variable "node_termination_handler_sqs_queue_arns" {
  description = "List of SQS ARNs that contain node termination events"
  type        = list(string)
  default     = ["*"]
}

variable "owner" {
  description = "Owner of the resource in mail format (used for tagging)"
  type        = string
}

variable "team" {
  description = "Resource owner team name"
  type        = string
}

variable "environment" {
  description = "A name that identifies the environment, used as prefix and for tagging."
  type        = string
}
variable "url_repo" {
  description = "Url of the terraform repository (ex: https://github.com//example-project)"
  type        = string
}

variable "karpenter_discovery_key_tag" {
  description = "Tag key for discovery subnets & Security groups for this cluster"
  type        = string
  default     = ""
}
variable "karpenter_discovery_value_tag" {
  description = "Tag value for discovery subnets & Security groups for this cluster"
  type        = string
  default     = ""
}

variable "attach_cloudwatch_observability_policy" {
  description = "Determines whether to attach the Cloudwatch Observability policy to the role"
  type        = bool
  default     = false
}

# S3
variable "attach_s3_policy" {
  description = "Determines whether to attach the s3 IAM policy to the role"
  type        = bool
  default     = false
}

variable "s3_buckets_arns" {
  description = "List of S3 buckets ARNs"
  type        = list(string)
  default     = ["arn:aws:s3:::noexist"]
}

# S3
variable "attach_sqs_policy" {
  description = "Determines whether to attach the sqs IAM policy to the role"
  type        = bool
  default     = false
}

variable "sqs_arns" {
  description = "List of SQS ARNs"
  type        = list(string)
  default     = ["arn:aws:sqs:::noexist"]
}

# Dynamodb
variable "attach_dynamodb_policy" {
  description = "Determines whether to attach the dynamodb IAM policy to the role"
  type        = bool
  default     = false
}

variable "dynamodb_arns" {
  description = "List of DynamoDB ARNs"
  type        = list(string)
  default     = ["arn:aws:dynamodb:::noexist"]
}

# App mesh
variable "attach_appmesh_policy" {
  description = "Determines whether to attach the app mesh IAM policy to the role"
  type        = bool
  default     = false
}
