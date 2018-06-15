use strict;
use warnings;

use Test::More;
use WebService::S3::Tiny;

{
    no warnings 'redefine';

    *WebService::S3::Tiny::request    = sub { \@_ };
    *WebService::S3::Tiny::signed_url = sub { \@_ };
}

my $s3 = WebService::S3::Tiny->new(qw(access_key 1 host 1 secret_key 1));

is_deeply +$s3->delete_bucket('bucket', 'headers'),
    [ $s3, 'DELETE', 'bucket', undef, undef, 'headers' ],
    'delete_bucket';

is_deeply +$s3->get_bucket('bucket', 'headers', 'parameters'),
    [ $s3, 'GET', 'bucket', undef, undef, 'headers', 'parameters' ],
    'get_bucket';

is_deeply +$s3->head_bucket('bucket', 'headers'),
    [ $s3, 'HEAD', 'bucket', undef, undef, 'headers' ],
    'head_bucket';

is_deeply +$s3->put_bucket('bucket', 'headers'),
    [ $s3, 'PUT', 'bucket', undef, undef, 'headers' ],
    'put_bucket';

is_deeply +$s3->delete_object('bucket', 'object', 'headers'),
    [ $s3, 'DELETE', 'bucket', 'object', undef, 'headers' ],
    'delete_object';

is_deeply +$s3->get_object('bucket', 'object', 'headers', 'parameters'),
    [ $s3, 'GET', 'bucket', 'object', undef, 'headers', 'parameters' ],
    'get_object';

is_deeply +$s3->head_object('bucket', 'object', 'headers'),
    [ $s3, 'HEAD', 'bucket', 'object', undef, 'headers' ],
    'head_object';

is_deeply +$s3->put_object('bucket', 'object', 'content', 'headers'),
    [ $s3, 'PUT', 'bucket', 'object', 'content', 'headers' ],
    'put_object';

# Signed URL methods

is_deeply +$s3->delete_bucket_url('bucket', 'headers', 'expires'),
    [ $s3, 'DELETE', 'bucket', undef, 'headers', undef, 'expires' ],
    'delete_bucket_url';

is_deeply +$s3->get_bucket_url('bucket', 'headers', 'parameters', 'expires'),
    [ $s3, 'GET', 'bucket', undef, 'headers', 'parameters', 'expires' ],
    'get_bucket_url';

is_deeply +$s3->head_bucket_url('bucket', 'headers', 'expires'),
    [ $s3, 'HEAD', 'bucket', undef, 'headers', undef, 'expires' ],
    'head_bucket_url';

is_deeply +$s3->put_bucket_url('bucket', 'headers', 'expires'),
    [ $s3, 'PUT', 'bucket', undef, 'headers', undef, 'expires' ],
    'put_bucket_url';

is_deeply +$s3->delete_object_url('bucket', 'object', 'headers', 'expires'),
    [ $s3, 'DELETE', 'bucket', 'object', 'headers', undef, 'expires' ],
    'delete_object_url';

is_deeply +$s3->get_object_url('bucket', 'object', 'headers', 'parameters', 'expires'),
    [ $s3, 'GET', 'bucket', 'object', 'headers', 'parameters', 'expires' ],
    'get_object_url';

is_deeply +$s3->head_object_url('bucket', 'object', 'headers', 'expires'),
    [ $s3, 'HEAD', 'bucket', 'object', 'headers', undef, 'expires' ],
    'head_object_url';

is_deeply +$s3->put_object_url('bucket', 'object', 'headers', 'expires'),
    [ $s3, 'PUT', 'bucket', 'object', 'headers', undef, 'expires' ],
    'put_object_url';

done_testing;
