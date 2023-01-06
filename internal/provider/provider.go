package provider

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/experimental/intf"
	"github.com/hashicorp/terraform-provider-aws/internal/experimental/nullable"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	"github.com/hashicorp/terraform-provider-aws/internal/service/s3"
	"github.com/hashicorp/terraform-provider-aws/internal/service/s3control"
	"github.com/hashicorp/terraform-provider-aws/internal/service/s3outposts"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// New returns a new, initialized Terraform Plugin SDK v2-style provider instance.
// The provider instance is fully configured once the `ConfigureContextFunc` has been called.
func New(_ context.Context) (*schema.Provider, error) {
	provider := &schema.Provider{
		// This schema must match exactly the Terraform Protocol v6 (Terraform Plugin Framework) provider's schema.
		// Notably the attributes can have no Default values.
		Schema: map[string]*schema.Schema{
			"access_key": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The access key for API operations. You can retrieve this\n" +
					"from the 'Security & Credentials' section of the AWS console.",
			},
			"allowed_account_ids": {
				Type:          schema.TypeSet,
				Elem:          &schema.Schema{Type: schema.TypeString},
				Optional:      true,
				ConflictsWith: []string{"forbidden_account_ids"},
				Set:           schema.HashString,
			},
			"assume_role":                   assumeRoleSchema(),
			"assume_role_with_web_identity": assumeRoleWithWebIdentitySchema(),
			"custom_ca_bundle": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "File containing custom root and intermediate certificates. " +
					"Can also be configured using the `AWS_CA_BUNDLE` environment variable. " +
					"(Setting `ca_bundle` in the shared config file is not supported.)",
			},
			"default_tags": {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Description: "Configuration block with settings to default resource tags across all resources.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"tags": {
							Type:        schema.TypeMap,
							Optional:    true,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Description: "Resource tags to default across all resources",
						},
					},
				},
			},
			"ec2_metadata_service_endpoint": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Address of the EC2 metadata service endpoint to use. " +
					"Can also be configured using the `AWS_EC2_METADATA_SERVICE_ENDPOINT` environment variable.",
			},
			"ec2_metadata_service_endpoint_mode": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Protocol to use with EC2 metadata service endpoint." +
					"Valid values are `IPv4` and `IPv6`. Can also be configured using the `AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE` environment variable.",
			},
			"endpoints": endpointsSchema(),
			"forbidden_account_ids": {
				Type:          schema.TypeSet,
				Elem:          &schema.Schema{Type: schema.TypeString},
				Optional:      true,
				ConflictsWith: []string{"allowed_account_ids"},
				Set:           schema.HashString,
			},
			"http_proxy": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The address of an HTTP proxy to use when accessing the AWS API. " +
					"Can also be configured using the `HTTP_PROXY` or `HTTPS_PROXY` environment variables.",
			},
			"ignore_tags": {
				Type:        schema.TypeList,
				Optional:    true,
				MaxItems:    1,
				Description: "Configuration block with settings to ignore resource tags across all resources.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"keys": {
							Type:        schema.TypeSet,
							Optional:    true,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Set:         schema.HashString,
							Description: "Resource tag keys to ignore across all resources.",
						},
						"key_prefixes": {
							Type:        schema.TypeSet,
							Optional:    true,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Set:         schema.HashString,
							Description: "Resource tag key prefixes to ignore across all resources.",
						},
					},
				},
			},
			"insecure": {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Explicitly allow the provider to perform \"insecure\" SSL requests. If omitted, " +
					"default value is `false`",
			},
			"max_retries": {
				Type:     schema.TypeInt,
				Optional: true,
				Description: "The maximum number of times an AWS API request is\n" +
					"being executed. If the API request still fails, an error is\n" +
					"thrown.",
			},
			"profile": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The profile for API operations. If not set, the default profile\n" +
					"created with `aws configure` will be used.",
			},
			"region": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The region where AWS operations will take place. Examples\n" +
					"are us-east-1, us-west-2, etc.", // lintignore:AWSAT003,
			},
			"s3_force_path_style": {
				Type:       schema.TypeBool,
				Optional:   true,
				Deprecated: "Use s3_use_path_style instead.",
				Description: "Set this to true to enable the request to use path-style addressing,\n" +
					"i.e., https://s3.amazonaws.com/BUCKET/KEY. By default, the S3 client will\n" +
					"use virtual hosted bucket addressing when possible\n" +
					"(https://BUCKET.s3.amazonaws.com/KEY). Specific to the Amazon S3 service.",
			},
			"s3_use_path_style": {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Set this to true to enable the request to use path-style addressing,\n" +
					"i.e., https://s3.amazonaws.com/BUCKET/KEY. By default, the S3 client will\n" +
					"use virtual hosted bucket addressing when possible\n" +
					"(https://BUCKET.s3.amazonaws.com/KEY). Specific to the Amazon S3 service.",
			},
			"secret_key": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The secret key for API operations. You can retrieve this\n" +
					"from the 'Security & Credentials' section of the AWS console.",
			},
			"shared_config_files": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "List of paths to shared config files. If not set, defaults to [~/.aws/config].",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"shared_credentials_file": {
				Type:          schema.TypeString,
				Optional:      true,
				Deprecated:    "Use shared_credentials_files instead.",
				ConflictsWith: []string{"shared_credentials_files"},
				Description:   "The path to the shared credentials file. If not set, defaults to ~/.aws/credentials.",
			},
			"shared_credentials_files": {
				Type:          schema.TypeList,
				Optional:      true,
				ConflictsWith: []string{"shared_credentials_file"},
				Description:   "List of paths to shared credentials files. If not set, defaults to [~/.aws/credentials].",
				Elem:          &schema.Schema{Type: schema.TypeString},
			},
			"skip_credentials_validation": {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Skip the credentials validation via STS API. " +
					"Used for AWS API implementations that do not have STS available/implemented.",
			},
			"skip_get_ec2_platforms": {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Skip getting the supported EC2 platforms. " +
					"Used by users that don't have ec2:DescribeAccountAttributes permissions.",
				Deprecated: `With the retirement of EC2-Classic the skip_get_ec2_platforms attribute has been deprecated and will be removed in a future version.`,
			},
			"skip_metadata_api_check": {
				Type:         nullable.TypeNullableBool,
				Optional:     true,
				ValidateFunc: nullable.ValidateTypeStringNullableBool,
				Description: "Skip the AWS Metadata API check. " +
					"Used for AWS API implementations that do not have a metadata api endpoint.",
			},
			"skip_region_validation": {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Skip static validation of region name. " +
					"Used by users of alternative AWS-like APIs or users w/ access to regions that are not public (yet).",
			},
			"skip_requesting_account_id": {
				Type:     schema.TypeBool,
				Optional: true,
				Description: "Skip requesting the account ID. " +
					"Used for AWS API implementations that do not have IAM/STS API and/or metadata API.",
			},
			"sts_region": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The region where AWS STS operations will take place. Examples\n" +
					"are us-east-1 and us-west-2.", // lintignore:AWSAT003,
			},
			"token": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "session token. A session token is only required if you are\n" +
					"using temporary security credentials.",
			},
			"use_dualstack_endpoint": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Resolve an endpoint with DualStack capability",
			},
			"use_fips_endpoint": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Resolve an endpoint with FIPS capability",
			},
		},

		DataSourcesMap: map[string]*schema.Resource{
			"aws_canonical_user_id": s3.DataSourceCanonicalUserID(),
			"aws_s3_bucket":         s3.DataSourceBucket(),
			"aws_s3_object":         s3.DataSourceObject(),
			"aws_s3_objects":        s3.DataSourceObjects(),
			"aws_s3_bucket_object":  s3.DataSourceBucketObject(),  // DEPRECATED: use aws_s3_object instead
			"aws_s3_bucket_objects": s3.DataSourceBucketObjects(), // DEPRECATED: use aws_s3_objects instead
			"aws_s3_bucket_policy":  s3.DataSourceBucketPolicy(),

			"aws_s3_account_public_access_block": s3control.DataSourceAccountPublicAccessBlock(),
		},

		ResourcesMap: map[string]*schema.Resource{

			"aws_s3_bucket":                                      s3.ResourceBucket(),
			"aws_s3_bucket_accelerate_configuration":             s3.ResourceBucketAccelerateConfiguration(),
			"aws_s3_bucket_acl":                                  s3.ResourceBucketACL(),
			"aws_s3_bucket_analytics_configuration":              s3.ResourceBucketAnalyticsConfiguration(),
			"aws_s3_bucket_cors_configuration":                   s3.ResourceBucketCorsConfiguration(),
			"aws_s3_bucket_intelligent_tiering_configuration":    s3.ResourceBucketIntelligentTieringConfiguration(),
			"aws_s3_bucket_inventory":                            s3.ResourceBucketInventory(),
			"aws_s3_bucket_lifecycle_configuration":              s3.ResourceBucketLifecycleConfiguration(),
			"aws_s3_bucket_logging":                              s3.ResourceBucketLogging(),
			"aws_s3_bucket_metric":                               s3.ResourceBucketMetric(),
			"aws_s3_bucket_notification":                         s3.ResourceBucketNotification(),
			"aws_s3_bucket_object_lock_configuration":            s3.ResourceBucketObjectLockConfiguration(),
			"aws_s3_bucket_ownership_controls":                   s3.ResourceBucketOwnershipControls(),
			"aws_s3_bucket_policy":                               s3.ResourceBucketPolicy(),
			"aws_s3_bucket_public_access_block":                  s3.ResourceBucketPublicAccessBlock(),
			"aws_s3_bucket_replication_configuration":            s3.ResourceBucketReplicationConfiguration(),
			"aws_s3_bucket_request_payment_configuration":        s3.ResourceBucketRequestPaymentConfiguration(),
			"aws_s3_bucket_server_side_encryption_configuration": s3.ResourceBucketServerSideEncryptionConfiguration(),
			"aws_s3_bucket_versioning":                           s3.ResourceBucketVersioning(),
			"aws_s3_bucket_website_configuration":                s3.ResourceBucketWebsiteConfiguration(),
			"aws_s3_object":                                      s3.ResourceObject(),
			"aws_s3_object_copy":                                 s3.ResourceObjectCopy(),
			"aws_s3_bucket_object":                               s3.ResourceBucketObject(), // DEPRECATED: use aws_s3_object instead

			"aws_s3_access_point":                             s3control.ResourceAccessPoint(),
			"aws_s3control_access_point_policy":               s3control.ResourceAccessPointPolicy(),
			"aws_s3_account_public_access_block":              s3control.ResourceAccountPublicAccessBlock(),
			"aws_s3control_bucket":                            s3control.ResourceBucket(),
			"aws_s3control_bucket_lifecycle_configuration":    s3control.ResourceBucketLifecycleConfiguration(),
			"aws_s3control_bucket_policy":                     s3control.ResourceBucketPolicy(),
			"aws_s3control_multi_region_access_point":         s3control.ResourceMultiRegionAccessPoint(),
			"aws_s3control_multi_region_access_point_policy":  s3control.ResourceMultiRegionAccessPointPolicy(),
			"aws_s3control_object_lambda_access_point":        s3control.ResourceObjectLambdaAccessPoint(),
			"aws_s3control_object_lambda_access_point_policy": s3control.ResourceObjectLambdaAccessPointPolicy(),
			"aws_s3control_storage_lens_configuration":        s3control.ResourceStorageLensConfiguration(),

			"aws_s3outposts_endpoint": s3outposts.ResourceEndpoint(),
		},
	}

	provider.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		return configure(ctx, provider, d)
	}

	providerData := &conns.AWSClient{
		// TODO: This should be generated.

		// ServicePackageData is used before configuration to determine the provider's exported resources and data sources.
		ServicePackages: []intf.ServicePackageData{},
	}

	// Set the provider Meta (instance data) here.
	// It will be overwritten by the result of the call to ConfigureContextFunc.
	provider.SetMeta(providerData)

	return provider, nil
}

// configure ensures that the provider is fully configured.
func configure(ctx context.Context, provider *schema.Provider, d *schema.ResourceData) (*conns.AWSClient, diag.Diagnostics) {
	terraformVersion := provider.TerraformVersion
	if terraformVersion == "" {
		// Terraform 0.12 introduced this field to the protocol
		// We can therefore assume that if it's missing it's 0.10 or 0.11
		terraformVersion = "0.11+compatible"
	}

	config := conns.Config{
		AccessKey:                      d.Get("access_key").(string),
		CustomCABundle:                 d.Get("custom_ca_bundle").(string),
		EC2MetadataServiceEndpoint:     d.Get("ec2_metadata_service_endpoint").(string),
		EC2MetadataServiceEndpointMode: d.Get("ec2_metadata_service_endpoint_mode").(string),
		Endpoints:                      make(map[string]string),
		HTTPProxy:                      d.Get("http_proxy").(string),
		Insecure:                       d.Get("insecure").(bool),
		MaxRetries:                     25, // Set default here, not in schema (muxing with v6 provider).
		Profile:                        d.Get("profile").(string),
		Region:                         d.Get("region").(string),
		S3UsePathStyle:                 d.Get("s3_use_path_style").(bool) || d.Get("s3_force_path_style").(bool),
		SecretKey:                      d.Get("secret_key").(string),
		SkipCredsValidation:            d.Get("skip_credentials_validation").(bool),
		SkipGetEC2Platforms:            d.Get("skip_get_ec2_platforms").(bool),
		SkipRegionValidation:           d.Get("skip_region_validation").(bool),
		SkipRequestingAccountId:        d.Get("skip_requesting_account_id").(bool),
		STSRegion:                      d.Get("sts_region").(string),
		TerraformVersion:               terraformVersion,
		Token:                          d.Get("token").(string),
		UseDualStackEndpoint:           d.Get("use_dualstack_endpoint").(bool),
		UseFIPSEndpoint:                d.Get("use_fips_endpoint").(bool),
	}

	if v, ok := d.GetOk("allowed_account_ids"); ok && v.(*schema.Set).Len() > 0 {
		config.AllowedAccountIds = flex.ExpandStringValueSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("assume_role"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		config.AssumeRole = expandAssumeRole(v.([]interface{})[0].(map[string]interface{}))
		log.Printf("[INFO] assume_role configuration set: (ARN: %q, SessionID: %q, ExternalID: %q, SourceIdentity: %q)", config.AssumeRole.RoleARN, config.AssumeRole.SessionName, config.AssumeRole.ExternalID, config.AssumeRole.SourceIdentity)
	}

	if v, ok := d.GetOk("assume_role_with_web_identity"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		config.AssumeRoleWithWebIdentity = expandAssumeRoleWithWebIdentity(v.([]interface{})[0].(map[string]interface{}))
		log.Printf("[INFO] assume_role_with_web_identity configuration set: (ARN: %q, SessionID: %q)", config.AssumeRoleWithWebIdentity.RoleARN, config.AssumeRoleWithWebIdentity.SessionName)
	}

	if v, ok := d.GetOk("default_tags"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		config.DefaultTagsConfig = expandDefaultTags(v.([]interface{})[0].(map[string]interface{}))
	}

	if v, ok := d.GetOk("endpoints"); ok && v.(*schema.Set).Len() > 0 {
		endpoints, err := expandEndpoints(v.(*schema.Set).List())

		if err != nil {
			return nil, diag.FromErr(err)
		}

		config.Endpoints = endpoints
	}

	if v, ok := d.GetOk("forbidden_account_ids"); ok && v.(*schema.Set).Len() > 0 {
		config.ForbiddenAccountIds = flex.ExpandStringValueSet(v.(*schema.Set))
	}

	if v, ok := d.GetOk("ignore_tags"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		config.IgnoreTagsConfig = expandIgnoreTags(v.([]interface{})[0].(map[string]interface{}))
	}

	if v, ok := d.GetOk("max_retries"); ok {
		config.MaxRetries = v.(int)
	}

	if v, ok := d.GetOk("shared_credentials_file"); ok {
		config.SharedCredentialsFiles = []string{v.(string)}
	} else if v, ok := d.GetOk("shared_credentials_files"); ok && len(v.([]interface{})) > 0 {
		config.SharedCredentialsFiles = flex.ExpandStringValueList(v.([]interface{}))
	}

	if v, ok := d.GetOk("shared_config_files"); ok && len(v.([]interface{})) > 0 {
		config.SharedConfigFiles = flex.ExpandStringValueList(v.([]interface{}))
	}

	providerData, diags := config.ConfigureProvider(ctx, provider.Meta().(*conns.AWSClient))

	if diags.HasError() {
		return nil, diags
	}

	// Configure each service.
	for _, v := range providerData.ServicePackages {
		if err := v.Configure(ctx, providerData); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}

	if diags.HasError() {
		return nil, diags
	}

	return providerData, diags
}

func assumeRoleSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"duration": {
					Type:          schema.TypeString,
					Optional:      true,
					Description:   "The duration, between 15 minutes and 12 hours, of the role session. Valid time units are ns, us (or µs), ms, s, h, or m.",
					ValidateFunc:  validAssumeRoleDuration,
					ConflictsWith: []string{"assume_role.0.duration_seconds"},
				},
				"duration_seconds": {
					Type:          schema.TypeInt,
					Optional:      true,
					Deprecated:    "Use assume_role.duration instead",
					Description:   "The duration, in seconds, of the role session.",
					ValidateFunc:  validation.IntBetween(900, 43200),
					ConflictsWith: []string{"assume_role.0.duration"},
				},
				"external_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "A unique identifier that might be required when you assume a role in another account.",
					ValidateFunc: validation.All(
						validation.StringLenBetween(2, 1224),
						validation.StringMatch(regexp.MustCompile(`[\w+=,.@:\/\-]*`), ""),
					),
				},
				"policy": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "IAM Policy JSON describing further restricting permissions for the IAM Role being assumed.",
					ValidateFunc: validation.StringIsJSON,
				},
				"policy_arns": {
					Type:        schema.TypeSet,
					Optional:    true,
					Description: "Amazon Resource Names (ARNs) of IAM Policies describing further restricting permissions for the IAM Role being assumed.",
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: verify.ValidARN,
					},
				},
				"role_arn": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Amazon Resource Name (ARN) of an IAM Role to assume prior to making API calls.",
					ValidateFunc: verify.ValidARN,
				},
				"session_name": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "An identifier for the assumed role session.",
					ValidateFunc: validAssumeRoleSessionName,
				},
				"source_identity": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Source identity specified by the principal assuming the role.",
					ValidateFunc: validAssumeRoleSourceIdentity,
				},
				"tags": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: "Assume role session tags.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"transitive_tag_keys": {
					Type:        schema.TypeSet,
					Optional:    true,
					Description: "Assume role session tag keys to pass to any subsequent sessions.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
			},
		},
	}
}

func assumeRoleWithWebIdentitySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"duration": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "The duration, between 15 minutes and 12 hours, of the role session. Valid time units are ns, us (or µs), ms, s, h, or m.",
					ValidateFunc: validAssumeRoleDuration,
				},
				"policy": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "IAM Policy JSON describing further restricting permissions for the IAM Role being assumed.",
					ValidateFunc: validation.StringIsJSON,
				},
				"policy_arns": {
					Type:        schema.TypeSet,
					Optional:    true,
					Description: "Amazon Resource Names (ARNs) of IAM Policies describing further restricting permissions for the IAM Role being assumed.",
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: verify.ValidARN,
					},
				},
				"role_arn": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Amazon Resource Name (ARN) of an IAM Role to assume prior to making API calls.",
					ValidateFunc: verify.ValidARN,
				},
				"session_name": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "An identifier for the assumed role session.",
					ValidateFunc: validAssumeRoleSessionName,
				},
				"web_identity_token": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringLenBetween(4, 20000),
					ExactlyOneOf: []string{"assume_role_with_web_identity.0.web_identity_token", "assume_role_with_web_identity.0.web_identity_token_file"},
				},
				"web_identity_token_file": {
					Type:         schema.TypeString,
					Optional:     true,
					ExactlyOneOf: []string{"assume_role_with_web_identity.0.web_identity_token", "assume_role_with_web_identity.0.web_identity_token_file"},
				},
			},
		},
	}
}

func endpointsSchema() *schema.Schema {
	endpointsAttributes := make(map[string]*schema.Schema)

	for _, serviceKey := range names.Aliases() {
		endpointsAttributes[serviceKey] = &schema.Schema{
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Use this to override the default service endpoint URL",
		}
	}

	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Resource{
			Schema: endpointsAttributes,
		},
	}
}

func expandAssumeRole(tfMap map[string]interface{}) *awsbase.AssumeRole {
	if tfMap == nil {
		return nil
	}

	assumeRole := awsbase.AssumeRole{}

	if v, ok := tfMap["duration"].(string); ok && v != "" {
		duration, _ := time.ParseDuration(v)
		assumeRole.Duration = duration
	} else if v, ok := tfMap["duration_seconds"].(int); ok && v != 0 {
		assumeRole.Duration = time.Duration(v) * time.Second
	}

	if v, ok := tfMap["external_id"].(string); ok && v != "" {
		assumeRole.ExternalID = v
	}

	if v, ok := tfMap["policy"].(string); ok && v != "" {
		assumeRole.Policy = v
	}

	if v, ok := tfMap["policy_arns"].(*schema.Set); ok && v.Len() > 0 {
		assumeRole.PolicyARNs = flex.ExpandStringValueSet(v)
	}

	if v, ok := tfMap["role_arn"].(string); ok && v != "" {
		assumeRole.RoleARN = v
	}

	if v, ok := tfMap["session_name"].(string); ok && v != "" {
		assumeRole.SessionName = v
	}

	if v, ok := tfMap["source_identity"].(string); ok && v != "" {
		assumeRole.SourceIdentity = v
	}

	if v, ok := tfMap["tags"].(map[string]interface{}); ok && len(v) > 0 {
		assumeRole.Tags = flex.ExpandStringValueMap(v)
	}

	if v, ok := tfMap["transitive_tag_keys"].(*schema.Set); ok && v.Len() > 0 {
		assumeRole.TransitiveTagKeys = flex.ExpandStringValueSet(v)
	}

	return &assumeRole
}

func expandAssumeRoleWithWebIdentity(tfMap map[string]interface{}) *awsbase.AssumeRoleWithWebIdentity {
	if tfMap == nil {
		return nil
	}

	assumeRole := awsbase.AssumeRoleWithWebIdentity{}

	if v, ok := tfMap["duration"].(string); ok && v != "" {
		duration, _ := time.ParseDuration(v)
		assumeRole.Duration = duration
	} else if v, ok := tfMap["duration_seconds"].(int); ok && v != 0 {
		assumeRole.Duration = time.Duration(v) * time.Second
	}

	if v, ok := tfMap["policy"].(string); ok && v != "" {
		assumeRole.Policy = v
	}

	if v, ok := tfMap["policy_arns"].(*schema.Set); ok && v.Len() > 0 {
		assumeRole.PolicyARNs = flex.ExpandStringValueSet(v)
	}

	if v, ok := tfMap["role_arn"].(string); ok && v != "" {
		assumeRole.RoleARN = v
	}

	if v, ok := tfMap["session_name"].(string); ok && v != "" {
		assumeRole.SessionName = v
	}

	if v, ok := tfMap["web_identity_token"].(string); ok && v != "" {
		assumeRole.WebIdentityToken = v
	}

	if v, ok := tfMap["web_identity_token_file"].(string); ok && v != "" {
		assumeRole.WebIdentityTokenFile = v
	}

	return &assumeRole
}

func expandDefaultTags(tfMap map[string]interface{}) *tftags.DefaultConfig {
	if tfMap == nil {
		return nil
	}

	defaultConfig := &tftags.DefaultConfig{}

	if v, ok := tfMap["tags"].(map[string]interface{}); ok {
		defaultConfig.Tags = tftags.New(v)
	}

	return defaultConfig
}

func expandIgnoreTags(tfMap map[string]interface{}) *tftags.IgnoreConfig {
	if tfMap == nil {
		return nil
	}

	ignoreConfig := &tftags.IgnoreConfig{}

	if v, ok := tfMap["keys"].(*schema.Set); ok {
		ignoreConfig.Keys = tftags.New(v.List())
	}

	if v, ok := tfMap["key_prefixes"].(*schema.Set); ok {
		ignoreConfig.KeyPrefixes = tftags.New(v.List())
	}

	return ignoreConfig
}

func expandEndpoints(tfList []interface{}) (map[string]string, error) {
	if len(tfList) == 0 {
		return nil, nil
	}

	endpoints := make(map[string]string)

	for _, tfMapRaw := range tfList {
		tfMap, ok := tfMapRaw.(map[string]interface{})

		if !ok {
			continue
		}

		for _, alias := range names.Aliases() {
			pkg, err := names.ProviderPackageForAlias(alias)

			if err != nil {
				return nil, fmt.Errorf("failed to assign endpoint (%s): %w", alias, err)
			}

			if endpoints[pkg] == "" {
				if v := tfMap[alias].(string); v != "" {
					endpoints[pkg] = v
				}
			}
		}
	}

	for _, pkg := range names.ProviderPackages() {
		if endpoints[pkg] != "" {
			continue
		}

		envVar := names.EnvVar(pkg)
		if envVar != "" {
			if v := os.Getenv(envVar); v != "" {
				endpoints[pkg] = v
				continue
			}
		}

		if deprecatedEnvVar := names.DeprecatedEnvVar(pkg); deprecatedEnvVar != "" {
			if v := os.Getenv(deprecatedEnvVar); v != "" {
				log.Printf("[WARN] The environment variable %q is deprecated. Use %q instead.", deprecatedEnvVar, envVar)
				endpoints[pkg] = v
			}
		}
	}

	return endpoints, nil
}
