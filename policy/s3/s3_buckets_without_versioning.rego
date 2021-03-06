package s3.s3_buckets_without_versioning
import data.s3

# # Negation example (probably more useful since it catches invalid buckets)
s3_buckets_without_versioning[name] {
	# Any resource that has a type "aws_s3_bucket"
    resource := s3.s3_bucket_changes[_]
    
    # After the plan applies..
    new_resource := resource.change.after
    
    # Does *not* use version
    true != new_resource.versioning[0].enabled
    
      # Add it to the list of buckets missing the encryption
    name := resource.name
}

