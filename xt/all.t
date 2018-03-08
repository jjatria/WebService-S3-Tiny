use Socket;
use Test::More;
use WebService::S3::Tiny;

# Block until minio is up.
BEGIN {
    socket my $sock, PF_INET, SOCK_STREAM, 0 or die $!;

    my $addr = sockaddr_in 9000, inet_aton 'minio';

    my $i;
    until ( connect $sock, $addr ) {
        select undef, undef, undef, .1;
        die 'Minio never came up' if ++$i > 50;
    }
}

my $s3 = WebService::S3::Tiny->new(
    access_key => 'access_key',
    host       => 'http://minio:9000',
    secret_key => 'secret_key',
);

is $s3->add_bucket('bucket')->{status}, 200, 'add_bucket("bucket")';
is $s3->add_bucket('bucket')->{status}, 409, 'add_bucket("bucket")';

is $s3->del_bucket('bucket')->{status}, 204, 'del_bucket("bucket")';

done_testing;
