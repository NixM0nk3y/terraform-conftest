package openenterprise

import data.s3.s3_buckets_non_private.s3_buckets_non_private
import data.s3.s3_buckets_without_aes256.s3_buckets_without_aes256
import data.s3.s3_buckets_without_versioning.s3_buckets_without_versioning

deny[msg] {
	count(s3_buckets_without_aes256) > 0
	msg := sprintf("bucket %s has an invalid encryption algorithm", [s3_buckets_without_aes256[_]])
}

deny[msg] {
	count(s3_buckets_non_private) > 0
	msg := sprintf("bucket %s is not set to private", [s3_buckets_non_private[_]])
}

deny[msg] {
	count(s3_buckets_without_versioning) > 0
	msg := sprintf("bucket %s has not got versioning enabling", [s3_buckets_without_versioning[_]])
}

allow {
	count(deny) == 0
}
