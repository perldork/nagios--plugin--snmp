package Nagios::Plugin::SNMP;

=pod

=head1 NAME

Nagios::Plugin::SNMP - Helper module to make writing SNMP-based plugins for Nagios easier.

=head1 SYNOPSIS

 This module extends Nagios::Plugin and includes routines 
 to do the following:

=head2 Parse and process common SNMP arguments:

 * --warning|-w: Warning threshold [optional]
 * --critical|-c: Warning threshold  [optional]
 * --hostname|-H: SNMP device to query
 * --port|-p: Port on remote device to connect to [default 161]
 * --snmp-local-ip: Local IP to bind to for outgoing requests
 * --snmp-version: SNMP version (1, 2c, 3)
 * --snmp-timeout: Connect timeout in seconds [default 15]
 * --snmp-debug: Turn on Net::SNMP debugging
 * --snmp-max-msg-size N: Set maximum SNMP message size in bytes
 * --rocommunity: Read-only community string for SNMP 1/v2c
 * --auth-username: Auth username for SNMP v3
 * --auth-password: Auth password for SNMP v3
 * --auth-protocol: Auth protocol for SNMP v3 (defaults to md5)
 * Connect to an SNMP device
 * Perform a get() or walk() request, each method does 'the right
   thing' based on the version of SNMP selected by the user.

 This module requires Net::SNMP for its' SNMP functionality; it 
 subclasses Nagios::Plugin.

=cut

use strict;

require Exporter;
use base qw(Exporter Nagios::Plugin);

use Net::SNMP;

#  Have to copy, inheritence doesn't work for these
use constant OK         => 0;
use constant WARNING    => 1;
use constant CRITICAL   => 2;
use constant UNKNOWN    => 3;
use constant DEPENDENT  => 4;

our @EXPORT = qw(OK WARNING CRITICAL UNKNOWN DEPENDENT);

our $VERSION = '1.0';

our $SNMP_USAGE = <<EOF;
       --hostname|-H HOST --port|-p INT --snmp-version 1|2c|3 \\
       [--snmp-timeout INT] \\
       [--snmp-local-ip IP] \\
       [--warning|-w STRING] [--critical|-c STRING] \
       [--snmp-debug] \\
       [--snmp-max-msg-size N] \\
       { 
           [--rocommunity S] | \\
           [--auth-username S --auth-password S [--auth-protocol S]] 
       }
EOF

our %OS_TYPES = qw(
   .1.3.6.1.4.1.8072.3.2.1   hpux
   .1.3.6.1.4.1.8072.3.2.2   sunos4
   .1.3.6.1.4.1.8072.3.2.3   solaris
   .1.3.6.1.4.1.8072.3.2.4   osf
   .1.3.6.1.4.1.8072.3.2.5   ultrix
   .1.3.6.1.4.1.8072.3.2.6   hpux10
   .1.3.6.1.4.1.8072.3.2.7   netbsd1
   .1.3.6.1.4.1.8072.3.2.8   freebsd
   .1.3.6.1.4.1.8072.3.2.9   irix
   .1.3.6.1.4.1.8072.3.2.10  linux
   .1.3.6.1.4.1.8072.3.2.11  bsdi
   .1.3.6.1.4.1.8072.3.2.12  openbsd
   .1.3.6.1.4.1.8072.3.2.13  win32
   .1.3.6.1.4.1.8072.3.2.14  hpux11
   .1.3.6.1.4.1.8072.3.2.255 unknown
);

sub new {

    my $class = shift;
    my %args = (@_);

    $args{'usage'} .= $SNMP_USAGE;

    my $self = $class->SUPER::new(%args);

    #  Add standard SNMP options to the plugin
    $self->_snmp_add_options();

    $self->{'_SNMP_SESSION'} = undef;

    return $self;
}

#  Add Nagios::Plugin options related to SNMP to the plugin

sub _snmp_add_options {

    my $self = shift;

    $self->add_arg(
        'spec' => 'snmp-version=s',
        'help' => '--snmp-version 1|2c|3 [default 3]',
        'required' => 1,
        'default' => '3'
    );

    $self->add_arg(
        'spec' => 'rocommunity=s',
        'help' => "--rocommunity NAME\n   Community name: SNMP 1|2c ONLY",
        'required' => 0,
        'default' => ''
    );

    $self->add_arg(
        'spec' => 'auth-username=s',
        'help' => "--auth-username USER\n   Auth username: SNMP 3 only",
        'required' => 0,
        'default' => ''
    );

    $self->add_arg(
        'spec' => 'auth-password=s',
        'help' => "--auth-password PASS\n   Auth password: SNMP 3 only",
        'required' => 0,
        'default' => ''
    );

    $self->add_arg(
        'spec' => 'auth-protocol=s',
        'help' => "--auth-protocol PROTO\n" .
                  "   Auth protocol: SNMP 3 only [default md5]",
        'required' => 0,
        'default' => 'md5'
    );

    $self->add_arg(
        'spec' => 'port|p=s',
        'help' => "--port INT\n   SNMP agent port [default 161]",
        'required' => 0,
        'default' => '161'
    );

    $self->add_arg(
        'spec' => 'hostname|H=s',
        'help' => "-H, --hostname\n   Host to check NAME|IP",
        'required' => 1
    );

    $self->add_arg(
        'spec' => 'snmp-timeout=i',
        'help' => "--snmp-timeout INT\n" .
                  "   Timeout for SNMP queries [default 15]",
        'default' => 15
    );

    $self->add_arg(
        'spec' => 'snmp-debug',
        'help' => "--snmp-debug [default off]",
        'default' => 0
    );

    $self->add_arg(
        'spec' => 'warning|w=s',
        'help' => "-w, --warning STRING [optional]",
        'required' => 0
    );

    $self->add_arg(
        'spec' => 'critical|c=s',
        'help' => "-c, --critical STRING",
        'required' => 0
    );

    $self->add_arg(
        'spec' => 'snmp-local-ip',
        'help' => "--snmp-local-ip\n" .
                  "   Local IP address to send traffic on [optional]",
        'default' => ''
    );

    $self->add_arg(
        'spec' => 'snmp-max-msg-size=i',
        'help' => "--snmp-max-msg-size BYTES\n" .
                  "   Specify SNMP maximum messages size [default 1470]",
        'default' => '1470'
    );

}

=pod

=head2 _snmp_validate_opts() - Validate passed in SNMP options

This method validates that any options passed to the plugin using
this library make sense.  Rules:

=over 4

 * If SNMP is version 1 or 2c, rocommunity must be set
 * If SNMP is version 3, auth-username and auth-password must be set

=back

=cut

sub _snmp_validate_opts {

    my $self = shift;

    my $opts = $self->opts;

    if ($opts->get('snmp-version') eq '3') {

        my @errors;

        for my $p (qw(auth-username auth-password auth-protocol)) {
            push(@errors, $p) if $opts->get($p) eq '';
        }

        die "SNMP parameter validation failed.  Missing: " .
            join(', ', @errors) if scalar(@errors) > 0;

    } else {

        die "SNMP parameter validation failed. Missing rocommunity!" 
            if $opts->get('rocommunity') eq '';

    }

    if ($opts->get('snmp-local-ip') ne '') {
        my $ip = $opts->get('snmp-local-ip');
        die "SNMP local bind IP address is invalid!"
            unless $ip =~ m/^(?:[0-9]{1,3}){4}$/;
    }

    return 1;

}

=pod

=head2 connect() - Establish SNMP session

 Attempts to connect to the remote system specified in the command-line
 arguments; will die() with an error message if the session creation
 fails.

=cut

sub connect {
    
    my $self = shift;

    $self->_snmp_validate_opts();

    my $opts = $self->opts;

    my @args;

    my $version = $opts->get('snmp-version');

    push(@args, '-version' => $opts->get('snmp-version'));
    push(@args, '-hostname' => $opts->get('hostname'));
    push(@args, '-port' => $opts->get('port'));
    push(@args, '-timeout' => $opts->get('snmp-timeout'));

    my $timeout = $opts->get('snmp-timeout');

    #  If user used --timeout switch from Nagios::Plugin, 
    #  use it's value over the snmp-timeout switch.
    if ($opts->get('timeout') > 0) {
        $timeout = $opts->get('timeout');
    }
    push(@args, '-timeout' => $opts->get('snmp-timeout'));

    push(@args, '-debug' => $opts->get('snmp-debug'));

    if ($version eq '3') {
        push(@args, '-username' => $opts->get('auth-username'));
        push(@args, '-authpassword' => $opts->get('auth-password'));
        push(@args, '-authprotocol' => $opts->get('auth-protocol'));
    } else {
        push(@args, '-community' => $opts->get('rocommunity'));
    }

    push(@args, '-localaddr' => $opts->get('snmp-local-ip'))
        if $opts->get('snmp-local-ip') ne '';

    push(@args, '-maxMsgSize' => $opts->get('snmp-max-msg-size'))
        if $opts->get('snmp-max-msg-size') ne '';

    my ($session, $error) = Net::SNMP->session(@args);

    die "SNMP session creation failed: $error" if $error ne '';

    $self->{'_SNMP_SESSION'} = $session;

    return $self;

}

=pod

=head2 get(@oids) - Perform an SNMP get request

 Performs an SNMP get request on each passed in OID; returns results
 as a hash reference where keys are the passed in OIDs and the values are
 the values returned from the Net::SNMP get() calls.

=cut

sub get {

    my $self = shift;
    my @oids = @_;

    die "Missing OIDs to get!" unless scalar(@oids) > 0;

    $self->_snmp_ensure_is_connected();

    my $session = $self->{'_SNMP_SESSION'};

    my %results;

    for my $oid (@oids) {

        my $result = $session->get_request('-varbindlist' => [$oid]);

        $results{$oid} = $result->{$oid};

        #  Ensure agent actually responded
        if (! defined $result) {
            if ($session->error() =~ /No response from/i) {
                $self->nagios_exit(UNKNOWN, "$oid - " . $session->error());
            } 
        }

    }

    return \%results;

}

=pod

=head2 walk(@baseoids) - Perform an SNMP walk request

 Performs an SNMP walk on each passed in OID; uses the Net-SNMP
 get_table() method for each base OID to ensure that the method will
 work regardless of SNMP version in use.  Returns results as
 a hash reference where keys are the passed in base OIDs and the values are
 references to the results of the Net::SNMP get_table calls.

=cut

sub walk {

    my $self = shift;
    my @baseoids = @_;

    $self->_snmp_ensure_is_connected();

    my $session = $self->{'_SNMP_SESSION'};

    my %results;

    for my $baseoid (@baseoids) {

        my $result = $session->get_table($baseoid);

        $results{$baseoid} = $result;

        #  Ensure agent actually responded
        if (! defined $result) {
            if ($session->error() =~ /No response from/i) {
                $self->nagios_exit(UNKNOWN, "$baseoid - " . $session->error());
            } 
        }

    }

    return \%results;
}

sub _snmp_ensure_is_connected {

    my $self = shift;

    if ((! defined($self->{'_SNMP_SESSION'})) ||
        (ref($self->{'_SNMP_SESSION'}) ne 'Net::SNMP')) {

        $self->connect();

    }

}

sub close {

    my $self = shift;

    if (defined $self->{'_SNMP_SESSION'}) {

        $self->{'_SNMP_SESSION'}->close();

        #  Ensure we release Net::SNMP memory
        $self->{'_SNMP_SESSION'} = undef;

    }

    return 1;

}

#  Overloaded methods

sub getopts {

    my $self = shift;

    $self->SUPER::getopts();

    #  Now validate our options
    $self->_snmp_validate_opts();

}

=pod

=head2 get_sys_info()

    my ($descr, $object_id) = $plugin->get_sys_info();

    Returns the sysDescr.0 and sysObjectId.0 OIDs from the remote
    agent, the sysObjectId.0 OID is translated to an OS family; string
    returned will be one of:

    *  hpux
    *  sunos4
    *  solaris
    *  osf
    *  ultrix
    *  hpux10
    *  netbsd1
    *  freebsd
    *  irix
    *  linux
    *  bsdi
    *  openbsd
    *  win32
    *  hpux11
    *  unknown

    sysDescr.0 is a free-text description containing more specific
    information on the OS being queried.

=cut

sub get_sys_info {

    my $self = shift;

    my %oids = qw(
        sysdescr    .1.3.6.1.2.1.1.1.0
        sysobjectid .1.3.6.1.2.1.1.2.0
    );

    my $result = $self->get(values %oids);

    return ($OS_TYPES{$result->{$oids{'sysobjectid'}}},
            $result->{$oids{'sysdescr'}});

}

sub error {
    my $self = shift;
    return $self->{'_SNMP_LAST_NET_SNMP_ERROR'};
}

1;
