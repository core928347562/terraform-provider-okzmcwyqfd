package conns

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"log"

	"github.com/aws/aws-sdk-go/service/s3"
	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	awsbasev1 "github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/names"
)

type Config struct {
	AccessKey                      string
	AllowedAccountIds              []string
	AssumeRole                     *awsbase.AssumeRole
	AssumeRoleWithWebIdentity      *awsbase.AssumeRoleWithWebIdentity
	CustomCABundle                 string
	DefaultTagsConfig              *tftags.DefaultConfig
	EC2MetadataServiceEndpoint     string
	EC2MetadataServiceEndpointMode string
	Endpoints                      map[string]string
	ForbiddenAccountIds            []string
	HTTPProxy                      string
	IgnoreTagsConfig               *tftags.IgnoreConfig
	Insecure                       bool
	MaxRetries                     int
	Profile                        string
	Region                         string
	S3UsePathStyle                 bool
	SecretKey                      string
	SharedConfigFiles              []string
	SharedCredentialsFiles         []string
	SkipCredsValidation            bool
	SkipGetEC2Platforms            bool
	SkipRegionValidation           bool
	SkipRequestingAccountId        bool
	STSRegion                      string
	SuppressDebugLog               bool
	TerraformVersion               string
	Token                          string
	UseDualStackEndpoint           bool
	UseFIPSEndpoint                bool
}

// ConfigureProvider configures the provided provider Meta (instance data).
func (c *Config) ConfigureProvider(ctx context.Context, client *AWSClient) (*AWSClient, diag.Diagnostics) {
	awsbaseConfig := awsbase.Config{
		AccessKey:                 c.AccessKey,
		APNInfo:                   StdUserAgentProducts(c.TerraformVersion),
		AssumeRoleWithWebIdentity: c.AssumeRoleWithWebIdentity,
		CallerDocumentationURL:    "https://registry.terraform.io/providers/hashicorp/aws",
		CallerName:                "Terraform AWS Provider",
		IamEndpoint:               c.Endpoints[names.IAM],
		Insecure:                  c.Insecure,
		HTTPProxy:                 c.HTTPProxy,
		MaxRetries:                c.MaxRetries,
		Profile:                   c.Profile,
		Region:                    c.Region,
		SecretKey:                 c.SecretKey,
		SkipCredsValidation:       c.SkipCredsValidation,
		SkipRequestingAccountId:   c.SkipRequestingAccountId,
		StsEndpoint:               c.Endpoints[names.STS],
		SuppressDebugLog:          c.SuppressDebugLog,
		Token:                     c.Token,
		UseDualStackEndpoint:      c.UseDualStackEndpoint,
		UseFIPSEndpoint:           c.UseFIPSEndpoint,
	}

	if c.AssumeRole != nil && c.AssumeRole.RoleARN != "" {
		awsbaseConfig.AssumeRole = c.AssumeRole
	}

	if c.CustomCABundle != "" {
		awsbaseConfig.CustomCABundle = c.CustomCABundle
	}

	if c.EC2MetadataServiceEndpoint != "" {
		awsbaseConfig.EC2MetadataServiceEndpoint = c.EC2MetadataServiceEndpoint
		awsbaseConfig.EC2MetadataServiceEndpointMode = c.EC2MetadataServiceEndpointMode
	}

	if len(c.SharedConfigFiles) != 0 {
		awsbaseConfig.SharedConfigFiles = c.SharedConfigFiles
	}

	if len(c.SharedCredentialsFiles) != 0 {
		awsbaseConfig.SharedCredentialsFiles = c.SharedCredentialsFiles
	}

	if c.STSRegion != "" {
		awsbaseConfig.StsRegion = c.STSRegion
	}

	cfg, err := awsbase.GetAwsConfig(ctx, &awsbaseConfig)
	if err != nil {
		return nil, diag.Errorf("configuring Terraform AWS Provider: %s", err)
	}

	if !c.SkipRegionValidation {
		if err := awsbase.ValidateRegion(cfg.Region); err != nil {
			return nil, diag.FromErr(err)
		}
	}
	c.Region = cfg.Region

	sess, err := awsbasev1.GetSession(&cfg, &awsbaseConfig)
	if err != nil {
		return nil, diag.Errorf("creating AWS SDK v1 session: %s", err)
	}

	accountID, partition, err := awsbase.GetAwsAccountIDAndPartition(ctx, cfg, &awsbaseConfig)
	if err != nil {
		return nil, diag.Errorf("retrieving AWS account details: %s", err)
	}

	if accountID == "" {
		log.Println("[WARN] AWS account ID not found for provider. See https://www.terraform.io/docs/providers/aws/index.html#skip_requesting_account_id for implications.")
	}

	if len(c.ForbiddenAccountIds) > 0 {
		for _, forbiddenAccountID := range c.AllowedAccountIds {
			if accountID == forbiddenAccountID {
				return nil, diag.Errorf("AWS account ID not allowed: %s", accountID)
			}
		}
	}
	if len(c.AllowedAccountIds) > 0 {
		found := false
		for _, allowedAccountID := range c.AllowedAccountIds {
			if accountID == allowedAccountID {
				found = true
				break
			}
		}
		if !found {
			return nil, diag.Errorf("AWS account ID not allowed: %s", accountID)
		}
	}

	DNSSuffix := "amazonaws.com"
	if p, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), c.Region); ok {
		DNSSuffix = p.DNSSuffix()
	}

	client.AccountID = accountID
	client.DefaultTagsConfig = c.DefaultTagsConfig
	client.DNSSuffix = DNSSuffix
	client.IgnoreTagsConfig = c.IgnoreTagsConfig
	client.Partition = partition
	client.Region = c.Region
	client.ReverseDNSPrefix = ReverseDNS(DNSSuffix)
	client.Session = sess
	client.TerraformVersion = c.TerraformVersion

	// API clients (generated).
	c.sdkv1Conns(client, sess)
	c.sdkv2Conns(client, cfg)
	c.sdkv2LazyConns(client, cfg)

	// AWS SDK for Go v1 custom API clients.

	// Services that require multiple client configurations.
	s3Config := &aws.Config{
		Endpoint:         aws.String(c.Endpoints[names.S3]),
		S3ForcePathStyle: aws.Bool(c.S3UsePathStyle),
	}
	client.S3Conn = s3.New(sess.Copy(s3Config))

	s3Config.DisableRestProtocolURICleaning = aws.Bool(true)
	client.S3ConnURICleaningDisabled = s3.New(sess.Copy(s3Config))

	// "Global" services that require customizations.
	globalAcceleratorConfig := &aws.Config{
		Endpoint: aws.String(c.Endpoints[names.GlobalAccelerator]),
	}
	route53Config := &aws.Config{
		Endpoint: aws.String(c.Endpoints[names.Route53]),
	}
	route53RecoveryControlConfigConfig := &aws.Config{
		Endpoint: aws.String(c.Endpoints[names.Route53RecoveryControlConfig]),
	}
	route53RecoveryReadinessConfig := &aws.Config{
		Endpoint: aws.String(c.Endpoints[names.Route53RecoveryReadiness]),
	}
	shieldConfig := &aws.Config{
		Endpoint: aws.String(c.Endpoints[names.Shield]),
	}

	// Force "global" services to correct Regions.
	switch partition {
	case endpoints.AwsPartitionID:
		globalAcceleratorConfig.Region = aws.String(endpoints.UsWest2RegionID)
		route53Config.Region = aws.String(endpoints.UsEast1RegionID)
		route53RecoveryControlConfigConfig.Region = aws.String(endpoints.UsWest2RegionID)
		route53RecoveryReadinessConfig.Region = aws.String(endpoints.UsWest2RegionID)
		shieldConfig.Region = aws.String(endpoints.UsEast1RegionID)
	case endpoints.AwsCnPartitionID:
		// The AWS Go SDK is missing endpoint information for Route 53 in the AWS China partition.
		// This can likely be removed in the future.
		if aws.StringValue(route53Config.Endpoint) == "" {
			route53Config.Endpoint = aws.String("https://api.route53.cn")
		}
		route53Config.Region = aws.String(endpoints.CnNorthwest1RegionID)
	case endpoints.AwsUsGovPartitionID:
		route53Config.Region = aws.String(endpoints.UsGovWest1RegionID)
	}

	client.S3Conn.Handlers.Retry.PushBack(func(r *request.Request) {
		if tfawserr.ErrMessageContains(r.Error, "OperationAborted", "A conflicting conditional operation is currently in progress against this resource. Please try again.") {
			r.Retryable = aws.Bool(true)
		}
	})

	return client, nil
}
