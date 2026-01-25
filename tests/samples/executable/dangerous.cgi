#!/usr/bin/perl
# TEST FILE: Dangerous CGI script
# This should trigger: executable detector EXEC-CGI-DANGER

use CGI;
my $q = CGI->new;

my $cmd = $q->param('cmd');

# Dangerous: executing user input
print "Content-type: text/html\n\n";
print `$cmd`;

# Another dangerous pattern
system($q->param('command'));

# Open pipe execution
open(CMD, "|$cmd");
