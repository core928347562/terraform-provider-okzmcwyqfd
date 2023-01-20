package s3

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/mitchellh/go-homedir"
)

const objectCreationTimeout = 2 * time.Minute

func ResourceObject() *schema.Resource {
	return &schema.Resource{
		Create: resourceObjectCreate,
		Read:   resourceObjectRead,
		Update: resourceObjectUpdate,
		Delete: resourceObjectDelete,

		Importer: &schema.ResourceImporter{
			State: resourceObjectImport,
		},

		CustomizeDiff: customdiff.Sequence(
			resourceObjectCustomizeDiff,
		),

		Schema: map[string]*schema.Schema{
			"acl": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     false,
				ValidateFunc: validation.StringInSlice(s3.ObjectCannedACL_Values(), false),
			},
			"bucket": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},
			"cache_control": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"content": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"source", "content_base64"},
			},
			"content_base64": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"source", "content"},
			},
			"content_disposition": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"content_encoding": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"content_language": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"content_type": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"key": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.NoZeroValues,
			},
			"metadata": {
				Type:         schema.TypeMap,
				ValidateFunc: validateMetadataIsLowerCase,
				Optional:     true,
				Elem:         &schema.Schema{Type: schema.TypeString},
			},
			"object_lock_legal_hold_status": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice(s3.ObjectLockLegalHoldStatus_Values(), false),
			},
			"object_lock_mode": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice(s3.ObjectLockMode_Values(), false),
			},
			"object_lock_retain_until_date": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.IsRFC3339Time,
			},
			"source": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"content", "content_base64"},
			},
			"source_hash": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"tags": tftags.TagsSchema(),
		},
	}
}

func resourceObjectCreate(d *schema.ResourceData, meta interface{}) error {
	return resourceObjectUpload(d, meta)
}

func resourceObjectRead(d *schema.ResourceData, meta interface{}) error {
	return nil
	conn := meta.(*conns.AWSClient).S3Conn

	bucket := d.Get("bucket").(string)
	key := d.Get("key").(string)

	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	var resp *s3.HeadObjectOutput

	err := resource.Retry(objectCreationTimeout, func() *resource.RetryError {
		var err error

		resp, err = conn.HeadObject(input)

		if d.IsNewResource() && tfawserr.ErrStatusCodeEquals(err, http.StatusNotFound) {
			return resource.RetryableError(err)
		}

		if err != nil {
			return resource.NonRetryableError(err)
		}

		return nil
	})

	if tfresource.TimedOut(err) {
		resp, err = conn.HeadObject(input)
	}

	if !d.IsNewResource() && tfawserr.ErrStatusCodeEquals(err, http.StatusNotFound) {
		log.Printf("[WARN] S3 Object (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return fmt.Errorf("reading S3 Object (%s): %w", d.Id(), err)
	}

	log.Printf("[DEBUG] Reading S3 Object meta: %s", resp)

	d.Set("cache_control", resp.CacheControl)
	d.Set("content_disposition", resp.ContentDisposition)
	d.Set("content_encoding", resp.ContentEncoding)
	d.Set("content_language", resp.ContentLanguage)
	d.Set("content_type", resp.ContentType)
	metadata := flex.PointersMapToStringList(resp.Metadata)

	// AWS Go SDK capitalizes metadata, this is a workaround. https://github.com/aws/aws-sdk-go/issues/445
	for k, v := range metadata {
		delete(metadata, k)
		metadata[strings.ToLower(k)] = v
	}

	if err := d.Set("metadata", metadata); err != nil {
		return fmt.Errorf("setting metadata: %s", err)
	}

	d.Set("object_lock_legal_hold_status", resp.ObjectLockLegalHoldStatus)
	d.Set("object_lock_mode", resp.ObjectLockMode)
	d.Set("object_lock_retain_until_date", flattenObjectDate(resp.ObjectLockRetainUntilDate))

	return nil
}

func resourceObjectUpdate(d *schema.ResourceData, meta interface{}) error {
	if hasObjectContentChanges(d) {
		return resourceObjectUpload(d, meta)
	}

	conn := meta.(*conns.AWSClient).S3Conn

	bucket := d.Get("bucket").(string)
	key := d.Get("key").(string)

	if d.HasChange("object_lock_legal_hold_status") {
		_, err := conn.PutObjectLegalHold(&s3.PutObjectLegalHoldInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			LegalHold: &s3.ObjectLockLegalHold{
				Status: aws.String(d.Get("object_lock_legal_hold_status").(string)),
			},
		})
		if err != nil {
			return fmt.Errorf("putting S3 object lock legal hold: %s", err)
		}
	}

	if d.HasChanges("object_lock_mode", "object_lock_retain_until_date") {
		req := &s3.PutObjectRetentionInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Retention: &s3.ObjectLockRetention{
				Mode:            aws.String(d.Get("object_lock_mode").(string)),
				RetainUntilDate: expandObjectDate(d.Get("object_lock_retain_until_date").(string)),
			},
		}

		// Bypass required to lower or clear retain-until date.
		if d.HasChange("object_lock_retain_until_date") {
			oraw, nraw := d.GetChange("object_lock_retain_until_date")
			o := expandObjectDate(oraw.(string))
			n := expandObjectDate(nraw.(string))
			if n == nil || (o != nil && n.Before(*o)) {
				req.BypassGovernanceRetention = aws.Bool(true)
			}
		}

		_, err := conn.PutObjectRetention(req)
		if err != nil {
			return fmt.Errorf("putting S3 object lock retention: %s", err)
		}
	}

	return resourceObjectRead(d, meta)
}

func resourceObjectDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*conns.AWSClient).S3Conn

	bucket := d.Get("bucket").(string)
	key := d.Get("key").(string)
	// We are effectively ignoring all leading '/'s in the key name and
	// treating multiple '/'s as a single '/' as aws.Config.DisableRestProtocolURICleaning is false
	key = strings.TrimLeft(key, "/")
	key = regexp.MustCompile(`/+`).ReplaceAllString(key, "/")

	var err error
	if _, ok := d.GetOk("version_id"); ok {
		_, err = DeleteAllObjectVersions(conn, bucket, key, false) //zzzforce_destroy
	} else {
		err = deleteObjectVersion(conn, bucket, key, "") //zzzforce_destroy
	}

	if err != nil {
		return fmt.Errorf("deleting S3 Bucket (%s) Object (%s): %s", bucket, key, err)
	}

	return nil
}

func resourceObjectImport(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	id = strings.TrimPrefix(id, "s3://")
	parts := strings.Split(id, "/")

	if len(parts) < 2 {
		return []*schema.ResourceData{d}, fmt.Errorf("id %s should be in format <bucket>/<key> or s3://<bucket>/<key>", id)
	}

	bucket := parts[0]
	key := strings.Join(parts[1:], "/")

	d.SetId(key)
	d.Set("bucket", bucket)
	d.Set("key", key)

	return []*schema.ResourceData{d}, nil
}

func resourceObjectUpload(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*conns.AWSClient).S3Conn
	uploader := s3manager.NewUploaderWithClient(conn)
	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	tags := defaultTagsConfig.MergeTags(tftags.New(d.Get("tags").(map[string]interface{})))

	var body io.ReadSeeker

	if v, ok := d.GetOk("source"); ok {
		source := v.(string)
		path, err := homedir.Expand(source)
		if err != nil {
			return fmt.Errorf("expanding homedir in source (%s): %s", source, err)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening S3 object source (%s): %s", path, err)
		}

		body = file
		defer func() {
			err := file.Close()
			if err != nil {
				log.Printf("[WARN] Error closing S3 object source (%s): %s", path, err)
			}
		}()
	} else if v, ok := d.GetOk("content"); ok {
		content := v.(string)
		body = bytes.NewReader([]byte(content))
	} else if v, ok := d.GetOk("content_base64"); ok {
		content := v.(string)
		// We can't do streaming decoding here (with base64.NewDecoder) because
		// the AWS SDK requires an io.ReadSeeker but a base64 decoder can't seek.
		contentRaw, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return fmt.Errorf("decoding content_base64: %s", err)
		}
		body = bytes.NewReader(contentRaw)
	} else {
		body = bytes.NewReader([]byte{})
	}

	bucket := d.Get("bucket").(string)
	key := d.Get("key").(string)

	input := &s3manager.UploadInput{
		//ACL:    aws.String(d.Get("acl").(string)),
		Body:   body,
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	//if v, ok := d.GetOk("storage_class"); ok {
	//	input.StorageClass = aws.String(v.(string))
	//}

	if v, ok := d.GetOk("cache_control"); ok {
		input.CacheControl = aws.String(v.(string))
	}

	if v, ok := d.GetOk("content_type"); ok {
		input.ContentType = aws.String(v.(string))
	}

	if v, ok := d.GetOk("metadata"); ok {
		input.Metadata = flex.ExpandStringMap(v.(map[string]interface{}))
	}

	if v, ok := d.GetOk("content_encoding"); ok {
		input.ContentEncoding = aws.String(v.(string))
	}

	if v, ok := d.GetOk("content_language"); ok {
		input.ContentLanguage = aws.String(v.(string))
	}

	if v, ok := d.GetOk("content_disposition"); ok {
		input.ContentDisposition = aws.String(v.(string))
	}

	//if v, ok := d.GetOk("bucket_key_enabled"); ok {
	//	input.BucketKeyEnabled = aws.Bool(v.(bool))
	//}

	//if v, ok := d.GetOk("server_side_encryption"); ok {
	//	input.ServerSideEncryption = aws.String(v.(string))
	//}
	//
	//if v, ok := d.GetOk("kms_key_id"); ok {
	//	input.SSEKMSKeyId = aws.String(v.(string))
	//	input.ServerSideEncryption = aws.String(s3.ServerSideEncryptionAwsKms)
	//}

	if len(tags) > 0 {
		// The tag-set must be encoded as URL Query parameters.
		input.Tagging = aws.String(tags.IgnoreAWS().URLEncode())
	}

	if v, ok := d.GetOk("website_redirect"); ok {
		input.WebsiteRedirectLocation = aws.String(v.(string))
	}

	if v, ok := d.GetOk("object_lock_legal_hold_status"); ok {
		input.ObjectLockLegalHoldStatus = aws.String(v.(string))
	}

	if v, ok := d.GetOk("object_lock_mode"); ok {
		input.ObjectLockMode = aws.String(v.(string))
	}

	if v, ok := d.GetOk("object_lock_retain_until_date"); ok {
		input.ObjectLockRetainUntilDate = expandObjectDate(v.(string))
	}

	if _, err := uploader.Upload(input); err != nil {
		return fmt.Errorf("uploading object to S3 bucket (%s): %s", bucket, err)
	}

	d.SetId(key)

	return resourceObjectRead(d, meta)
}

func resourceObjectSetKMS(d *schema.ResourceData, meta interface{}, sseKMSKeyId *string) error {

	return nil
}

func validateMetadataIsLowerCase(v interface{}, k string) (ws []string, errors []error) {
	value := v.(map[string]interface{})

	for k := range value {
		if k != strings.ToLower(k) {
			errors = append(errors, fmt.Errorf(
				"Metadata must be lowercase only. Offending key: %q", k))
		}
	}
	return
}

func resourceObjectCustomizeDiff(_ context.Context, d *schema.ResourceDiff, meta interface{}) error {
	if hasObjectContentChanges(d) {
	}

	if d.HasChange("source_hash") {

	}

	return nil
}

func hasObjectContentChanges(d verify.ResourceDiffer) bool {
	for _, key := range []string{
		//"bucket_key_enabled",
		"cache_control",
		"content_base64",
		"content_disposition",
		"content_encoding",
		"content_language",
		"content_type",
		"content",
		"metadata",
		"source",
		"source_hash",
	} {
		if d.HasChange(key) {
			return true
		}
	}
	return false
}

// DeleteAllObjectVersions deletes all versions of a specified key from an S3 bucket.
// If key is empty then all versions of all objects are deleted.
// Set force to true to override any S3 object lock protections on object lock enabled buckets.
// Returns the number of objects deleted.
func DeleteAllObjectVersions(conn *s3.S3, bucketName, key string, ignoreObjectErrors bool) (int64, error) { //zzzforce_destroy
	var nObjects int64

	input := &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucketName),
	}
	if key != "" {
		input.Prefix = aws.String(key)
	}

	var lastErr error
	err := conn.ListObjectVersionsPages(input, func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
		if page == nil {
			return !lastPage
		}

		for _, objectVersion := range page.Versions {
			objectKey := aws.StringValue(objectVersion.Key)
			objectVersionID := aws.StringValue(objectVersion.VersionId)

			if key != "" && key != objectKey {
				continue
			}

			err := deleteObjectVersion(conn, bucketName, objectKey, objectVersionID) //zzzforce_destroy

			if err == nil {
				nObjects++
			}

			if tfawserr.ErrCodeEquals(err, "AccessDenied") { //zzzforce_destroy
				// Remove any legal hold.
				resp, err := conn.HeadObject(&s3.HeadObjectInput{
					Bucket:    aws.String(bucketName),
					Key:       objectVersion.Key,
					VersionId: objectVersion.VersionId,
				})

				if err != nil {
					log.Printf("[ERROR] Error getting S3 Bucket (%s) Object (%s) Version (%s) metadata: %s", bucketName, objectKey, objectVersionID, err)
					lastErr = err
					continue
				}

				if aws.StringValue(resp.ObjectLockLegalHoldStatus) == s3.ObjectLockLegalHoldStatusOn {
					_, err := conn.PutObjectLegalHold(&s3.PutObjectLegalHoldInput{
						Bucket:    aws.String(bucketName),
						Key:       objectVersion.Key,
						VersionId: objectVersion.VersionId,
						LegalHold: &s3.ObjectLockLegalHold{
							Status: aws.String(s3.ObjectLockLegalHoldStatusOff),
						},
					})

					if err != nil {
						log.Printf("[ERROR] Error putting S3 Bucket (%s) Object (%s) Version(%s) legal hold: %s", bucketName, objectKey, objectVersionID, err)
						lastErr = err
						continue
					}

					// Attempt to delete again.
					err = deleteObjectVersion(conn, bucketName, objectKey, objectVersionID) //zzzforce_destroy

					if err != nil {
						lastErr = err
					} else {
						nObjects++
					}

					continue
				}

				// AccessDenied for another reason.
				lastErr = fmt.Errorf("AccessDenied deleting S3 Bucket (%s) Object (%s) Version: %s", bucketName, objectKey, objectVersionID)
				continue
			}

			if err != nil {
				lastErr = err
			}
		}

		return !lastPage
	})

	if tfawserr.ErrCodeEquals(err, s3.ErrCodeNoSuchBucket) {
		err = nil
	}

	if err != nil {
		return nObjects, err
	}

	if lastErr != nil {
		if !ignoreObjectErrors {
			return nObjects, fmt.Errorf("deleting at least one object version, last error: %s", lastErr)
		}

		lastErr = nil
	}

	err = conn.ListObjectVersionsPages(input, func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
		if page == nil {
			return !lastPage
		}

		for _, deleteMarker := range page.DeleteMarkers {
			deleteMarkerKey := aws.StringValue(deleteMarker.Key)
			deleteMarkerVersionID := aws.StringValue(deleteMarker.VersionId)

			if key != "" && key != deleteMarkerKey {
				continue
			}

			// Delete markers have no object lock protections.
			err := deleteObjectVersion(conn, bucketName, deleteMarkerKey, deleteMarkerVersionID) //zzzforce_destroy

			if err != nil {
				lastErr = err
			} else {
				nObjects++
			}
		}

		return !lastPage
	})

	if tfawserr.ErrCodeEquals(err, s3.ErrCodeNoSuchBucket) {
		err = nil
	}

	if err != nil {
		return nObjects, err
	}

	if lastErr != nil {
		if !ignoreObjectErrors {
			return nObjects, fmt.Errorf("deleting at least one object delete marker, last error: %s", lastErr)
		}

		lastErr = nil
	}

	return nObjects, nil
}

// deleteObjectVersion deletes a specific object version.
// Set force to true to override any S3 object lock protections.
func deleteObjectVersion(conn *s3.S3, b, k, v string) error { //zzzforce_destroy
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(b),
		Key:    aws.String(k),
	}

	if v != "" {
		input.VersionId = aws.String(v)
	}

	log.Printf("[INFO] Deleting S3 Bucket (%s) Object (%s) Version: %s", b, k, v)
	_, err := conn.DeleteObject(input)

	if err != nil {
		log.Printf("[WARN] Error deleting S3 Bucket (%s) Object (%s) Version (%s): %s", b, k, v, err)
	}

	if tfawserr.ErrCodeEquals(err, s3.ErrCodeNoSuchBucket) || tfawserr.ErrCodeEquals(err, s3.ErrCodeNoSuchKey) {
		return nil
	}

	return err
}

func expandObjectDate(v string) *time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil
	}

	return aws.Time(t)
}

func flattenObjectDate(t *time.Time) string {
	if t == nil {
		return ""
	}

	return t.Format(time.RFC3339)
}
