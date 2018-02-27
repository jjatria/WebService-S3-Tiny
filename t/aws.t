BEGIN { *CORE::GLOBAL::gmtime = sub(;$) { CORE::gmtime(1440938160) } }

use Data::Dumper;
use HTTP::Request;
use Test2::V0;
use WebService::S3::Tiny;

sub slurp($) { local ( @ARGV, $/ ) = @_; scalar <> }

my $s3 = WebService::S3::Tiny->new(
    access_key => 'AKIDEXAMPLE',
    host       => 'example.amazonaws.com',
    region     => 'us-east-1',
    secret_key => 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    service    => 'service',
);

chdir 't/aws';

for (<{get,post}-*>) {
    # TODO
    next if /utf8/;

    my $foo = slurp "$_/$_.req";

    my ( $method, $path, $headers ) =
        $foo =~ m(^(GET|POST) (.+) HTTP/1.1\n(.+))s;

    ( $path, my $query ) = split /\?/, $path;

    my %query;

    for ( split /&/, $query // '' ) {
        my ( $k, $v ) = split /=/;

        push @{ $query{$k} }, $v;
    }

    ( $headers, my $content ) = split /\n\n/, $headers;

    my $req = HTTP::Request->parse( slurp "$_/$_.req" );

    my %headers = %{ $req->headers };

    delete $headers{'::std_case'};

    is $s3->sign_request(
        $req->method,
        $path,
        \%query,
        \%headers,
        $req->content,
    ) => slurp "$_/$_.authz", $_;
}

done_testing;
