package LWP::UserAgent::AuthenCASDuo;
use base( "LWP::UserAgent" );

use strict;
use warnings;

use JSON;
use Data::Dumper;
use HTTP::Cookies;
use LWP::UserAgent;
use Tiny::Mojo::Dom;
use IO::Socket::SSL;
use HTTP::Request::Common;

=head1 NAME

LWP::UserAgent::AuthenCASDuo - A LWP::UserAgent extension for Authenticating to a resource under 2-factor CAS/Duo protection 

=head1 VERSION

Version 1.0.0

=cut

our $VERSION = '1.0.0';


=head1 SYNOPSIS

This Object extends L<LWP::UserAgent> class providing two new methods 'cas_duo_login' ( the method that handles the authentication )
and 'submit_request' ( a conveniece method that handles the particulars of submitting a user agent request ).

=head1 CONSTRUCTOR

=head2 new()

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

    # access protected resources
    my $ret = $ua->submit_request(
        method => 'GET',
        url    => 'https://that.thing.you.wanted/to/access'
    );

=cut

=head1 AUTHOR

Ben Geels 

=head1 COPYRIGHT

Copyright (C) 2018, Ben Geels 

This module is free software; you can redistribute it or modify it under the same terms as Perl itself.

=cut

sub new {
    my ($class, %args) = @_;
    
    # Create the SUPER object with the remaining arguments or use the one passed in
    my $ua = LWP::UserAgent->new(
        ssl_opts => {
          verify_hostname => 0,
          SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE,
        }
    );
    $ua->requests_redirectable(['GET', 'HEAD', 'POST', 'OPTIONS']);
   
    # bless our object 
    my $self = bless $ua, $class;

    # let's set the passed in arguments
    $self->{_cas_url}      = $args{cas_url};
    $self->{_cas_username} = $args{cas_username};
    $self->{_cas_password} = $args{cas_password};
    $self->{_duo_status_allow_callback} = $args{duo_status_allow_callback};
    $self->{_duo_status_pushed_callback} = $args{duo_status_pushed_callback};
    $self->{_duo_status_retries} = defined($args{duo_status_retries}) ? $args{duo_status_retries} : 10;

    # create an in memory cookie jar
    my $cookie_jar = new HTTP::Cookies(
        autosave       => 0,
        ignore_discard => 1,
    );
    if(!$cookie_jar) {
        die "Unable to create cookie jar";
    }
    $self->cookie_jar($cookie_jar);
    
    return $self;
}

# method that authenticates to a 2-factor CAS / Duo authentication system
sub cas_duo_login {
    my ($self, %args) = @_;

    # authenticate to CAS
    my $cas_resp = $self->_cas_login() || return 0;

    # authenticate to Duo
    my $duo_resp = $self->_duo_login(
        cas_resp => $cas_resp 
    ) || return 0;

    return 1;
}

# helper method to login to CAS service
sub _cas_login {
    my ($self, %args) = @_;

    # retrieve the CAS login form to get some required form elements 
    my $cas_form = $self->_parse_form( 
        form_selector => '#fm1 .row input',
        dom => $self->submit_request(
            method => 'GET',
            decode_html => 1,
            url => $self->{_cas_url},
        )
    );

    # now submit credentials along with form elements
    my $cas_duo_page = $self->submit_request(
        url => $self->{_cas_url}, 
        content_type => 'application/x-www-form-urlencoded',
        params => {
            'username' => $self->{_cas_username},
            'password' => $self->{_cas_password},
            'lt' => $cas_form->{lt}, 
            'execution' => $cas_form->{execution}, 
            '_eventId_submit' => $cas_form->{_eventId_submit} 
        }
    );

    # grab the variables used to instantiate the Duo widget and convert them
    # to a hash reference
    my $duo_widget_params_json = ($cas_duo_page =~ /Duo.init\(({.*})\)/s)[0];
    $duo_widget_params_json =~ s/'/"/g;
    my $duo_widget_params = decode_json( $duo_widget_params_json );

            
    # parse the duo form 
    my $duo_form = $self->_parse_form( 
        form_selector => '#duo_form .row input',
        dom => Tiny::Mojo::DOM->new( $cas_duo_page ) 
    );

    # split the duo signature from the application signature
    my @sig_request_parts = split(':', $duo_widget_params->{sig_request});
    my $duo_sig = $sig_request_parts[0];
    my $app_sig = $sig_request_parts[1];

    return {
        'duo_host' => $duo_widget_params->{host},
        'duo_sig'  => $duo_sig,
        'app_sig'  => $app_sig,
        '_eventId' => $duo_form->{'_eventId'},
        'lt' => $duo_form->{'lt'},
        'execution' => $duo_form->{'execution'},
        'post_argument' => $duo_widget_params->{post_argument} 
    };
}

# helper method to login to DUO service
sub _duo_login {
    my ($self, %args) = @_;

    # pull out the parameters we need to use
    my $cas_resp = $args{cas_resp};
    my $duo_sig  = $cas_resp->{duo_sig};
    my $app_sig  = $cas_resp->{app_sig};
    my $duo_host = $cas_resp->{duo_host};

    # now submit credentials along with form elements
    my $duo_auth_url  = "https://$duo_host/frame/web/v1/auth";
    my $duo_form = $self->_parse_form(
        form_selector => '#login-form input',
        dom => $self->submit_request(
            url => $duo_auth_url, 
            decode_html => 1,
            content_type => 'application/x-www-form-urlencoded',
            params => {
                tx            => $duo_sig,
                parent        => $self->{_cas_url},
                v             => '2.6'
            }
        )
    );

    # now submit remote authentication request to the user's 
    # preferred device / factor
    my $duo_prompt_url = "https://$duo_host/frame/prompt";
    my $duo_tx = $self->submit_request(
        decode_json => 1,
        url => $duo_prompt_url, 
        content_type => 'application/x-www-form-urlencoded',
        params => {
            sid => $duo_form->{sid},
            factor => $duo_form->{preferred_factor},
            device => $duo_form->{preferred_device},
            out_of_date => undef,
            days_out_of_date => undef,
            days_to_block => 'None'
        }
    );

    # make sure the remote 2 factor request was sucessful
    if($duo_tx->{stat} ne 'OK'){
        warn "There was a problem issuing remote 2 factor verification";
        return 0;
    }
    
    # now pull the status service until we get a successful response
    my $tx_status;
    my $duo_logged_in = 0;
    my $txid = $duo_tx->{response}{txid};
    my $duo_status_url = "https://$duo_host/frame/status";
    my $duo_status_retries = $self->{_duo_status_retries};
    for( my $i = 0; $i < $duo_status_retries; $i++){

        # check if the user has approved the duo request
        $tx_status = $self->submit_request(
            decode_json => 1,
            url => $duo_status_url, 
            content_type => 'application/x-www-form-urlencoded',
            params => {
                sid  => $duo_form->{sid},
                txid => $txid
            }
        );
        my $tx_status_code = $tx_status->{response}{status_code};

        # if the user accepted the duo request stop checking
        if($tx_status_code eq 'allow'){
            $duo_logged_in = 1;

            # excute the sudcess callback if one was passed in
            if(defined($self->{_duo_status_allow_callback})){
                $self->{_duo_status_allow_callback}( tx_status => $tx_status );
            }
            last;
        }
        # if the request is still pushed execute the pushed callback if set or check again
        elsif($tx_status_code eq 'pushed'){
            if(defined($self->{_duo_status_pushed_callback})){
                $self->{_duo_status_pushed_callback}( tx_status => $tx_status );
            }
        }

        # sleep 3 seconds between status polls
        sleep(3);
    }

    # if we didn't get an allow response after _duo_status_retries give up and return failure
    if(!$duo_logged_in){
        warn "Did not receive authentication confirmation from duo after $duo_status_retries tries, giving up";
        return 0;
    }

    # now submit final request to CAS 
    my $cas_login_page = $self->submit_request(
        url => $self->{_cas_url}, 
        content_type => 'application/x-www-form-urlencoded',
        params => {
            'lt' => $cas_resp->{lt},
            'execution' => $cas_resp->{execution},
            '_eventId' => $cas_resp->{_eventId},
            'signedDuoResponse' => join( ':', (
                $tx_status->{response}{cookie},
                $app_sig
            ))
        }
    );

    return 1;
}

# helper method that wraps the particulars of creating and submitting a user agent request
sub submit_request {
    my ($self, %args) = @_;

    # default to post method if none is set
    $args{method} = $args{method} || 'POST';
   
    # handle querystring parameters if GET method 
    my $request;
    if( $args{method} eq 'GET' ){ 
        if($args{params}){
            my @params;
            foreach my $name ( keys(%{$args{params}}) ){
                my $value = $args{params}->{$name};
                push(@params, "$name=$value");
            }
            $args{url} .= "?".join('&', @params);
        }

        # instatiate the request object
        $request = HTTP::Request->new($args{method} => $args{url});
    }
    # handle post request 
    elsif($args{method} eq 'POST'){
        my %post_params = (
           Content_Type => defined($args{content_type}) ? $args{content_type} : 'form-data',
        );
        $post_params{Content} = [%{$args{params}}] if(defined($args{params}));

        $request = HTTP::Request::Common::POST( $args{url}, %post_params );
    }
   
    # submit the request 
    my $resp = $self->request( $request );

    # retrieve the content
    my $content = $resp->content();

    # decode json if requested
    $content = decode_json( $content ) if($args{decode_json});
    $content = Tiny::Mojo::DOM->new( $content ) if($args{decode_html});

    return $content;
}

# helper method to parse a form out of an html page and return it's values as a hash ref
sub _parse_form {
    my ($self, %args) = @_;

    my $dom = $args{dom}; 
    my $elements = $dom->find($args{form_selector});

    my $form = {};
    foreach my $element ( @$elements ){
        my $name  = $element->attr( 'name' );
        my $value = $element->attr( 'value' );
        $form->{$name} = $value;
    }

    return $form;
}

1;
