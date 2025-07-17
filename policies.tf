data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  dns_suffix = data.aws_partition.current.dns_suffix
}

################################################################################
# EBS CSI Driver Policy
################################################################################

# https://github.com/kubernetes-sigs/aws-ebs-csi-driver/blob/master/docs/example-iam-policy.json

data "aws_iam_policy_document" "csi_driver_ebs" {
  count = var.create_role && var.attach_csi_driver_ebs_policy ? 1 : 0
  statement {
    actions = [
      "ec2:CreateSnapshot",
      "ec2:AttachVolume",
      "ec2:DetachVolume",
      "ec2:ModifyVolume",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInstances",
      "ec2:DescribeSnapshots",
      "ec2:DescribeTags",
      "ec2:DescribeVolumes",
      "ec2:DescribeVolumesModifications"
    ]
    resources = ["*"]
    effect    = "Allow"
  }

  statement {
    actions = [
      "ec2:CreateTags"
    ]
    resources = [
      "arn:aws:ec2:*:*:volume/*",
      "arn:aws:ec2:*:*:snapshot/*"
    ]
    effect = "Allow"
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values = [
        "CreateVolume",
        "CreateSnapshot"
      ]
    }
  }

  statement {
    actions = [
      "ec2:DeleteTags"
    ]
    resources = [
      "arn:aws:ec2:*:*:volume/*",
      "arn:aws:ec2:*:*:snapshot/*"
    ]
    effect = "Allow"
  }

  statement {
    actions = [
      "ec2:CreateVolume"
    ]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/ebs.csi.aws.com/cluster"
      values = [
        "true"
      ]
    }
  }

  statement {
    actions = [
      "ec2:CreateVolume"
    ]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/CSIVolumeName"
      values = [
        "*"
      ]
    }
  }

  statement {
    actions = [
      "ec2:DeleteVolume"
    ]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/ebs.csi.aws.com/cluster"
      values = [
        "true"
      ]
    }
  }

  statement {
    actions = [
      "ec2:DeleteVolume"
    ]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/CSIVolumeName"
      values = [
        "*"
      ]
    }
  }

  statement {
    actions = [
      "ec2:DeleteVolume"
    ]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/kubernetes.io/created-for/pvc/name"
      values = [
        "*"
      ]
    }
  }

  statement {
    actions = [
      "ec2:DeleteSnapshot"
    ]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/CSIVolumeSnapshotName"
      values = [
        "*"
      ]
    }
  }

  statement {
    actions = [
      "ec2:DeleteSnapshot"
    ]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/ebs.csi.aws.com/cluster"
      values = [
        "true"
      ]
    }
  }
}

resource "aws_iam_policy" "csi_driver_ebs" {
  count = var.create_role && var.attach_csi_driver_ebs_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}CSI_Driver_EBS_Policy-"
  path        = "/${local.team}/"
  description = "CSI Driver EBS policy to allow examination and modification of Elastic Block Store"
  policy      = data.aws_iam_policy_document.csi_driver_ebs[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "csi_driver_ebs" {
  count = var.create_role && var.attach_csi_driver_ebs_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.csi_driver_ebs[0].arn
}

################################################################################
# Karpenter Policy
################################################################################

# https://karpenter.sh
data "aws_iam_policy_document" "karpenter" {
  count = var.create_role && var.attach_karpenter_policy ? 1 : 0
  statement {
    actions = [
      "ssm:GetParameter",
      "ec2:DescribeImages",
      "ec2:RunInstances",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeLaunchTemplates",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeInstanceTypeOfferings",
      "ec2:DescribeAvailabilityZones",
      "ec2:DeleteLaunchTemplate",
      "ec2:CreateTags",
      "ec2:CreateLaunchTemplate",
      "ec2:CreateFleet",
      "ec2:DescribeSpotPriceHistory",
      "pricing:GetProducts"
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "ec2:TerminateInstances"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/${var.karpenter_discovery_key_tag}"
      values   = ["${var.karpenter_discovery_value_tag}"]
    }
  }
  statement {
    actions = ["ec2:RunInstances"]
    resources = [
      "arn:aws:ec2:*::image/*",
      "arn:aws:ec2:*:${local.account_id}:volume/*",
      "arn:aws:ec2:*:${local.account_id}:subnet/*",
      "arn:aws:ec2:*:${local.account_id}:spot-instances-request/*",
      "arn:aws:ec2:*:${local.account_id}:security-group/*",
      "arn:aws:ec2:*:${local.account_id}:network-interface/*",
      "arn:aws:ec2:*:${local.account_id}:instance/*",
      "arn:aws:ec2:*:${local.account_id}:launch-template/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/${var.karpenter_discovery_key_tag}"
      values   = ["${var.karpenter_discovery_value_tag}"]
    }
  }
  statement {
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:*:*:parameter/aws/service/*"]
  }
  statement {
    actions   = ["eks:DescribeCluster"]
    resources = ["arn:aws:eks:*:${local.account_id}:cluster/${var.eks_cluster_name}"]
  }

  statement {
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/${local.team}/*"]
  }
  #For spot interruption queue:
  statement {
    actions = [
      "sqs:ReceiveMessage",
      "sqs:GetQueueUrl",
      "sqs:GetQueueAttributes",
      "sqs:DeleteMessage"
    ]
    resources = ["arn:aws:sqs:us-east-1:${local.account_id}:Karpenter-${var.eks_cluster_name}"]
  }

}
resource "aws_iam_policy" "karpenter" {
  count = var.create_role && var.attach_karpenter_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}Karpenter_Policy-"
  path        = "/${local.team}/"
  description = "Karpenter policy to allow examination and modification of EC2 Auto Scaling Groups"
  policy      = data.aws_iam_policy_document.karpenter[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "karpenter" {
  count = var.create_role && var.attach_karpenter_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.karpenter[0].arn
}

################################################################################
# Cluster Autoscaler Policy
################################################################################

# https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/cloudprovider/aws/README.md
data "aws_iam_policy_document" "cluster_autoscaler" {
  count = var.create_role && var.attach_cluster_autoscaler_policy ? 1 : 0

  statement {
    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeScalingActivities",
      "autoscaling:DescribeTags",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:DescribeInstanceTypes",
      "eks:DescribeNodegroup",
    ]

    resources = ["*"]
  }

  dynamic "statement" {
    for_each = toset(var.cluster_autoscaler_cluster_ids)
    content {
      actions = [
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup",
        "autoscaling:UpdateAutoScalingGroup",
      ]

      resources = ["*"]

      condition {
        test     = "StringEquals"
        variable = "autoscaling:ResourceTag/kubernetes.io/cluster/${statement.value}"
        values   = ["owned"]
      }
    }
  }
}

resource "aws_iam_policy" "cluster_autoscaler" {
  count = var.create_role && var.attach_cluster_autoscaler_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}Cluster_Autoscaler_Policy-"
  path        = "/${local.team}/"
  description = "Cluster autoscaler policy to allow examination and modification of EC2 Auto Scaling Groups"
  policy      = data.aws_iam_policy_document.cluster_autoscaler[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "cluster_autoscaler" {
  count = var.create_role && var.attach_cluster_autoscaler_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.cluster_autoscaler[0].arn
}

################################################################################
# External Secrets Policy
################################################################################

# https://github.com/external-secrets/kubernetes-external-secrets#add-a-secret
data "aws_iam_policy_document" "external_secrets" {
  count = var.create_role && var.attach_external_secrets_policy ? 1 : 0

  statement {
    actions   = ["ssm:GetParameter"]
    resources = var.external_secrets_ssm_parameter_arns
  }

  statement {
    actions = [
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds",
    ]
    resources = var.external_secrets_secrets_manager_arns
  }
}

resource "aws_iam_policy" "external_secrets" {
  count = var.create_role && var.attach_external_secrets_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}External_Secrets_Policy-"
  path        = "/${local.team}/"
  description = "Provides permissions to for External Secrets to retrieve secrets from AWS SSM and AWS Secrets Manager"
  policy      = data.aws_iam_policy_document.external_secrets[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "external_secrets" {
  count = var.create_role && var.attach_external_secrets_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.external_secrets[0].arn
}

################################################################################
# AWS Load Balancer Controller Policy
################################################################################

# https://github.com/kubernetes-sigs/aws-load-balancer-controller/blob/main/docs/install/iam_policy.json
data "aws_iam_policy_document" "load_balancer_controller" {
  count = var.create_role && var.attach_load_balancer_controller_policy ? 1 : 0

  statement {
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["elasticloadbalancing.${local.dns_suffix}"]
    }
  }

  statement {
    actions = [
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeAddresses",
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeInternetGateways",
      "ec2:DescribeVpcs",
      "ec2:DescribeVpcPeeringConnections",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeTags",
      "ec2:GetCoipPoolUsage",
      "ec2:DescribeCoipPools",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeListenerCertificates",
      "elasticloadbalancing:DescribeSSLPolicies",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetGroupAttributes",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeTags",
      "elasticloadbalancing:DescribeListenerAttributes"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "cognito-idp:DescribeUserPoolClient",
      "acm:ListCertificates",
      "acm:DescribeCertificate",
      "iam:ListServerCertificates",
      "iam:GetServerCertificate",
      "waf-regional:GetWebACL",
      "waf-regional:GetWebACLForResource",
      "waf-regional:AssociateWebACL",
      "waf-regional:DisassociateWebACL",
      "wafv2:GetWebACL",
      "wafv2:GetWebACLForResource",
      "wafv2:AssociateWebACL",
      "wafv2:DisassociateWebACL",
      "shield:GetSubscriptionState",
      "shield:DescribeProtection",
      "shield:CreateProtection",
      "shield:DeleteProtection",
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:CreateSecurityGroup",
    ]
    resources = ["*"]
  }

  statement {
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${local.partition}:ec2:*:*:security-group/*"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSecurityGroup"]
    }

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    actions = [
      "ec2:CreateTags",
      "ec2:DeleteTags",
    ]
    resources = ["arn:${local.partition}:ec2:*:*:security-group/*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["true"]
    }

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    actions = [
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DeleteSecurityGroup",
    ]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    actions = [
      "elasticloadbalancing:CreateLoadBalancer",
      "elasticloadbalancing:CreateTargetGroup",
    ]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    actions = [
      "elasticloadbalancing:CreateListener",
      "elasticloadbalancing:DeleteListener",
      "elasticloadbalancing:CreateRule",
      "elasticloadbalancing:DeleteRule",
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags",
    ]
    resources = [
      "arn:${local.partition}:elasticloadbalancing:*:*:targetgroup/*/*",
      "arn:${local.partition}:elasticloadbalancing:*:*:loadbalancer/net/*/*",
      "arn:${local.partition}:elasticloadbalancing:*:*:loadbalancer/app/*/*",
    ]

    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["true"]
    }

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    actions = [
      "elasticloadbalancing:AddTags",
      "elasticloadbalancing:RemoveTags",
    ]
    resources = [
      "arn:${local.partition}:elasticloadbalancing:*:*:listener/net/*/*/*",
      "arn:${local.partition}:elasticloadbalancing:*:*:listener/app/*/*/*",
      "arn:${local.partition}:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
      "arn:${local.partition}:elasticloadbalancing:*:*:listener-rule/app/*/*/*",
    ]
  }

  statement {
    actions = [
      "elasticloadbalancing:ModifyLoadBalancerAttributes",
      "elasticloadbalancing:SetIpAddressType",
      "elasticloadbalancing:SetSecurityGroups",
      "elasticloadbalancing:SetSubnets",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:DeleteTargetGroup",
    ]
    resources = ["*"]

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }

  statement {
    actions = [
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets",
    ]
    resources = ["arn:${local.partition}:elasticloadbalancing:*:*:targetgroup/*/*"]
  }

  statement {
    actions = [
      "elasticloadbalancing:SetWebAcl",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:AddListenerCertificates",
      "elasticloadbalancing:RemoveListenerCertificates",
      "elasticloadbalancing:ModifyRule",
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "elasticloadbalancing:AddTags"
    ]
    resources = [
      "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
      "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
      "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "elasticloadbalancing:CreateAction"
      values   = ["CreateTargetGroup", "CreateLoadBalancer"]
    }
    condition {
      test     = "Null"
      variable = "aws:RequestTag/elbv2.k8s.aws/cluster"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "load_balancer_controller" {
  count = var.create_role && var.attach_load_balancer_controller_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}AWS_Load_Balancer_Controller-"
  path        = "/${local.team}/"
  description = "Provides permissions for AWS Load Balancer Controller addon"
  policy      = data.aws_iam_policy_document.load_balancer_controller[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "load_balancer_controller" {
  count = var.create_role && var.attach_load_balancer_controller_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.load_balancer_controller[0].arn
}

################################################################################
# AWS Load Balancer Controller TargetGroup Binding Only Policy
################################################################################

# https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/guide/targetgroupbinding/targetgroupbinding/#reference
# https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/deploy/installation/#setup-iam-manually
data "aws_iam_policy_document" "load_balancer_controller_targetgroup_only" {
  count = var.create_role && var.attach_load_balancer_controller_targetgroup_binding_only_policy ? 1 : 0

  statement {
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeVpcs",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:ModifyTargetGroup",
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "load_balancer_controller_targetgroup_only" {
  count = var.create_role && var.attach_load_balancer_controller_targetgroup_binding_only_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}AWS_Load_Balancer_Controller_TargetGroup_Only-"
  path        = "/${local.team}/"
  description = "Provides permissions for AWS Load Balancer Controller addon in TargetGroup binding only scenario"
  policy      = data.aws_iam_policy_document.load_balancer_controller_targetgroup_only[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "load_balancer_controller_targetgroup_only" {
  count = var.create_role && var.attach_load_balancer_controller_targetgroup_binding_only_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.load_balancer_controller_targetgroup_only[0].arn
}

################################################################################
# Node Termination Handler Policy
################################################################################

# https://github.com/aws/aws-node-termination-handler#5-create-an-iam-role-for-the-pods
data "aws_iam_policy_document" "node_termination_handler" {
  count = var.create_role && var.attach_node_termination_handler_policy ? 1 : 0

  statement {
    actions = [
      "autoscaling:CompleteLifecycleAction",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeTags",
      "ec2:DescribeInstances",
    ]

    resources = ["*"]
  }

  statement {
    actions = [
      "sqs:DeleteMessage",
      "sqs:ReceiveMessage",
    ]

    resources = var.node_termination_handler_sqs_queue_arns
  }
}

resource "aws_iam_policy" "node_termination_handler" {
  count = var.create_role && var.attach_node_termination_handler_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}Node_Termination_Handler_Policy-"
  path        = "/${local.team}/"
  description = "Provides permissions to handle node termination events via the Node Termination Handler"
  policy      = data.aws_iam_policy_document.node_termination_handler[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "node_termination_handler" {
  count = var.create_role && var.attach_node_termination_handler_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.node_termination_handler[0].arn
}

################################################################################
# VPC CNI Policy
################################################################################

data "aws_iam_policy_document" "vpc_cni" {
  count = var.create_role && var.attach_vpc_cni_policy ? 1 : 0

  # arn:${local.partition}:iam::aws:policy/AmazonEKS_CNI_Policy
  dynamic "statement" {
    for_each = var.vpc_cni_enable_ipv4 ? [1] : []
    content {
      sid = "IPV4"
      actions = [
        "ec2:AssignPrivateIpAddresses",
        "ec2:AttachNetworkInterface",
        "ec2:CreateNetworkInterface",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeInstances",
        "ec2:DescribeTags",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInstanceTypes",
        "ec2:DetachNetworkInterface",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:UnassignPrivateIpAddresses",
      ]
      resources = ["*"]
    }
  }

  # https://docs.aws.amazon.com/eks/latest/userguide/cni-iam-role.html#cni-iam-role-create-ipv6-policy
  dynamic "statement" {
    for_each = var.vpc_cni_enable_ipv6 ? [1] : []
    content {
      sid = "IPV6"
      actions = [
        "ec2:AssignIpv6Addresses",
        "ec2:DescribeInstances",
        "ec2:DescribeTags",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInstanceTypes",
      ]
      resources = ["*"]
    }
  }

  statement {
    sid       = "CreateTags"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${local.partition}:ec2:*:*:network-interface/*"]
  }
}

resource "aws_iam_policy" "vpc_cni" {
  count = var.create_role && var.attach_vpc_cni_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}CNI_Policy-"
  path        = "/${local.team}/"
  description = "Provides the Amazon VPC CNI Plugin (amazon-vpc-cni-k8s) the permissions it requires to modify the IPv4/IPv6 address configuration on your EKS worker nodes"
  policy      = data.aws_iam_policy_document.vpc_cni[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "vpc_cni" {
  count = var.create_role && var.attach_vpc_cni_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.vpc_cni[0].arn
}


################################################################################
# OpenSearch Policy
################################################################################

# Conectividad from pod to opensearch
data "aws_iam_policy_document" "opensearch" {
  count = var.create_role && var.attach_opensearch_policy ? 1 : 0
  statement {
    actions = [
      "es:*"
    ]
    resources = [var.arn_opensearch]
  }

}
resource "aws_iam_policy" "opensearch" {
  count = var.create_role && var.attach_opensearch_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}Opensearch_Policy-"
  path        = "/${local.team}/"
  description = "OpenSearch policy to allow connecto to remote OS Domain"
  policy      = data.aws_iam_policy_document.opensearch[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "opensearch" {
  count = var.create_role && var.attach_opensearch_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.opensearch[0].arn
}

################################################################################
# Amazon CloudWatch Observability Policy
################################################################################
resource "aws_iam_role_policy_attachment" "amazon_cloudwatch_observability" {
  for_each = { for k, v in {
    CloudWatchAgentServerPolicy = "arn:${local.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
    AWSXrayWriteOnlyAccess      = "arn:${local.partition}:iam::aws:policy/AWSXrayWriteOnlyAccess"
  } : k => v if var.create_role && var.attach_cloudwatch_observability_policy }

  role       = aws_iam_role.this[0].name
  policy_arn = each.value
}

################################################################################
# S3 policy
################################################################################

# Conectividad from pod to s3
data "aws_iam_policy_document" "s3" {
  count = var.create_role && var.attach_s3_policy ? 1 : 0
  statement {
    actions = [
      "s3:*"
    ]
    resources = var.s3_buckets_arns
  }

}
resource "aws_iam_policy" "s3" {
  count = var.create_role && var.attach_s3_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}S3_Policy-"
  path        = "/${local.team}/"
  description = "S3 policy to allow connecto to buckets from pod"
  policy      = data.aws_iam_policy_document.s3[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "s3" {
  count = var.create_role && var.attach_s3_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.s3[0].arn
}

################################################################################
# SQS policy
################################################################################

# Conectividad from pod to SQS
data "aws_iam_policy_document" "sqs" {
  count = var.create_role && var.attach_sqs_policy ? 1 : 0
  statement {
    actions = [
      "sqs:*"
    ]
    resources = var.sqs_arns
  }

}
resource "aws_iam_policy" "sqs" {
  count = var.create_role && var.attach_sqs_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}SQS_Policy-"
  path        = "/${local.team}/"
  description = "SQS policy to allow connect to SQS from pod"
  policy      = data.aws_iam_policy_document.sqs[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "sqs" {
  count = var.create_role && var.attach_sqs_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.sqs[0].arn
}

################################################################################
# APPMESH Policy
################################################################################

# Conectividad from pod to AppMesh
resource "aws_iam_role_policy_attachment" "appmesh" {
  count = var.create_role && var.attach_appmesh_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/AWSAppMeshFullAccess"
}
# Conectividad from pod to AppMesh xray
resource "aws_iam_role_policy_attachment" "appmesh2" {
  count = var.create_role && var.attach_appmesh_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/AWSXrayFullAccess"
}

################################################################################
# Dynamo policy
################################################################################

# Conectividad from pod to DynamoDB
data "aws_iam_policy_document" "dynamodb" {
  count = var.create_role && var.attach_dynamodb_policy ? 1 : 0
  statement {
    actions = [
      "dynamodb:*"
    ]
    resources = var.dynamodb_arns
  }

}
resource "aws_iam_policy" "dynamodb" {
  count = var.create_role && var.attach_dynamodb_policy ? 1 : 0

  name_prefix = "${var.policy_name_prefix}DynamoDB_Policy-"
  path        = "/${local.team}/"
  description = "DynamoDB policy to allow connect to table from pod"
  policy      = data.aws_iam_policy_document.dynamodb[0].json

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "dynamodb" {
  count = var.create_role && var.attach_dynamodb_policy ? 1 : 0

  role       = aws_iam_role.this[0].name
  policy_arn = aws_iam_policy.dynamodb[0].arn
}