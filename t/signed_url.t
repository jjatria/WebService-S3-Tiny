use strict;
use warnings;

use Test::More;
use WebService::S3::Tiny;

my $s3 = WebService::S3::Tiny->new(
    access_key => 'foo',
    host       => 'http://s3.baz.com',
    secret_key => 'bar',
);

is +$s3->signed_url( 'maibucket', 'path/to/my+image.jpg', 1406712744 ),
    'http://maibucket.s3.baz.com/path/to/my%2Bimage.jpg?AWSAccessKeyId=foo&Expires=1406712744&Signature=%2BEfymm%2BhjUfRLdQ3bS%2FJWrg9dc0',
    'signed_uri';

done_testing;
