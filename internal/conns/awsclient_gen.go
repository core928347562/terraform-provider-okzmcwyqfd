// Code generated by internal/generate/awsclient/main.go; DO NOT EDIT.
package conns

import (
	s3control_sdkv2 "github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/mediaconvert"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3control"
	"github.com/aws/aws-sdk-go/service/s3outposts"
	"github.com/hashicorp/terraform-provider-aws/internal/experimental/intf"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
)

type AWSClient struct {
	AccountID                 string
	DefaultTagsConfig         *tftags.DefaultConfig
	DNSSuffix                 string
	IgnoreTagsConfig          *tftags.IgnoreConfig
	MediaConvertAccountConn   *mediaconvert.MediaConvert
	Partition                 string
	Region                    string
	ReverseDNSPrefix          string
	S3ConnURICleaningDisabled *s3.S3
	ServicePackages           []intf.ServicePackageData
	Session                   *session.Session
	TerraformVersion          string

	s3controlClient lazyClient[*s3control_sdkv2.Client]

	S3Conn         *s3.S3
	S3ControlConn  *s3control.S3Control
	S3OutpostsConn *s3outposts.S3Outposts
}

func (client *AWSClient) S3ControlClient() *s3control_sdkv2.Client {
	return client.s3controlClient.Client()
}
