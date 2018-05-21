## Synopsis

This module extends LWP::UserAgent such that you can authenticate to a CAS/Duo 2-factor protected service and access resources protected by that service.

## Code Example

```
# instantiate
my $ua = LWP::UserAgent::AuthenCASDuo->new(
    cas_url      => 'https://some.server.net/cas/login'
    cas_username => 'AzureDiamond',
    cas_password => 'hunter2',
    duo_status_allow_callback => sub {
        print "Request accepted, logging in...\n";
    },
    duo_status_pushed_callback => sub {
        print "Pushed a request to device, waiting for approval...\n";
    }
);

# authenticate
$ua->cas_duo_login() || die "Issue authenticating...";

> Request accepted, logging in...
> Pushed a request to device, waiting for approval...

# access protected resources
my $ret = $ua->submit_request(
    method => 'GET',
    url    => 'https://that.thing.you.wanted/to/access'
);
```

## License

This module is free software; you can redistribute it or modify it under the same terms as Perl itself.
