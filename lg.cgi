#!/usr/bin/perl
#
#    Looking Glass CGI with ssh, telnet, rexec and remote LG support
#                    with IPv4 and IPv6 support
#
#    Copyright (C) 2000-2002 Cougar <cougar@random.ee>
#                                   http://www.version6.net/
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

use strict qw(subs vars);

$ENV{HOME} = ".";	# SSH needs access for $HOME/.ssh

use IO::Handle;
use Net::Telnet ();
use Net::SSH::Perl;
use Net::SSH::Perl::Cipher;
use XML::Parser;

my $SYS_progid = '$Id: lg.cgi,v 1.10 2002/12/27 07:28:49 cougar Exp $';

my $default_ostype = "IOS";

my $lgurl;
my $logfile;
my $asfile;
my $logoimage;
my $logoalign;
my $logolink;
my $title;
my $favicon;
my $email;
my $rshcmd;
my $ipv4enabled;
my $ipv6enabled;
my $httpmethod = "POST";

my %router_list;
my @routers;
my %namemap;
my %ostypes;
my %cmdmap;

my $default_router;

my $xml_current_router_name = "";
my $xml_current_cgi_name = "";
my $xml_current_replace_name = "";
my $xml_current_replace_proto = "";

my %valid_query = (
	"ios"		=>	{
		"ipv4"			=>	{
			"bgp"			=>	"show ip bgp %s",
			"advertised-routes"	=>	"show ip bgp neighbors %s advertised-routes",
			"summary"		=>	"show ip bgp summary",
			"ping"			=>	"ping %s",
			"trace"			=>	"traceroute %s"
			},
		"ipv6"		=>	{
			"bgp"			=>	"show bgp ipv6 %s",
			"advertised-routes"	=>	"show bgp ipv6 neighbors %s advertised-routes",
			"summary"		=>	"show bgp ipv6 summary",
			"ping"			=>	"ping ipv6 %s",
			"trace"			=>	"traceroute ipv6 %s"
			}
		},
	"zebra"		=>	{
		"ipv4"			=>	{
			"bgp"			=>	"show ip bgp %s",
			"advertised-routes"	=>	"show ip bgp neighbors %s advertised-routes",
			"summary"		=>	"show ip bgp summary",
			"ping"			=>	"ping %s",
			"trace"			=>	"traceroute %s"
			},
		"ipv6"		=>	{
			"bgp"			=>	"show bgp ipv6 %s",
			"advertised-routes"	=>	"show bgp ipv6 neighbors %s advertised-routes",
			"summary"		=>	"show bgp ipv6 summary",
			"ping"			=>	"ping ipv6 %s",
			"trace"			=>	"traceroute ipv6 %s"
			}
		},
	"junos"		=>	{
		"ipv46"			=>	{
			"bgp"			=>	"show bgp %s",
			"advertised-routes"	=>	"show route advertising-protocol bgp %s",
			"summary"		=>	"show bgp summary",
			"ping"			=>	"ping count 5 %s",
			"trace"			=>	"traceroute %s as-number-lookup"
			}
		}
);

my %whois = (
	"RIPE"		=>	"http://www.ripe.net/perl/whois?AS%s",
	"ARIN"		=>	"http://www.arin.net/cgi-bin/whois.pl?queryinput=%s",
	"APNIC"		=>	"http://www.apnic.net/apnic-bin/whois.pl?search=AS%s",
);

$| = 1;

&read_config;

# grab CGI data
my $incoming;
if ($ENV{'REQUEST_METHOD'} eq "POST") {
	read(STDIN, $incoming, $ENV{'CONTENT_LENGTH'});
} else {
	$incoming = $ENV{'QUERY_STRING'};
}
my %FORM = &cgi_decode($incoming);

my $date = localtime;
if ($logfile ne "") {
	open(LOG, ">>$logfile");
	($ENV{REMOTE_HOST}) && ( print LOG "$ENV{'REMOTE_HOST'} ");
	($ENV{REMOTE_ADDR}) && ( print LOG "$ENV{'REMOTE_ADDR'} ");
	print LOG "- - [$date]";
	($ENV{HTTP_REFERER}) && ( print LOG " $ENV{'HTTP_REFERER'}");
}

my $query_cmd = "";

if (defined $valid_query{$ostypes{$FORM{router}}}{"ipv46"}{$FORM{query}}) {
	$query_cmd = $valid_query{$ostypes{$FORM{router}}}{"ipv46"}{$FORM{query}};
} elsif (defined $valid_query{$ostypes{$FORM{router}}}{lc($FORM{protocol})}{$FORM{query}}) {
	$query_cmd = $valid_query{$ostypes{$FORM{router}}}{lc($FORM{protocol})}{$FORM{query}};
} elsif (($FORM{router} ne "") || ($FORM{protocol} ne "") || ($FORM{query})) {
	if ($logfile ne "") {
		print LOG " \"$FORM{router}\" \"ILLEGAL QUERY: [$ostypes{$FORM{router}}] [$FORM{protocol}] [$FORM{query}]\"\n";
		close(LOG);
	}
	&print_head;
	&print_form;
	&print_tail;
	exit;
}

if ((! defined $router_list{$FORM{router}}) ||
    ($query_cmd eq "")) {
	if ($logfile ne "") {
		print LOG "\n";
		close(LOG);
	}
	&print_head;
	&print_form;
	&print_tail;
	exit;
}

if ($router_list{$FORM{router}} =~ /^http[s]{0,1}:/) {
	if ($logfile ne "") {
		print LOG " \"$FORM{router}\" \"$FORM{query}" . ($FORM{addr} ne "" ? " $FORM{addr}" : "") . "\"\n";
		close LOG;
	}
	if ($router_list{$FORM{router}} =~ /\?/) {
		$incoming = "&$incoming";
	} else {
		$incoming = "?$incoming";
	}
	my $remote = $router_list{$FORM{router}};
	if (defined $cmdmap{$remote}{lc($FORM{protocol})}) {
		$incoming .= "&";
		my $mapref = $cmdmap{$remote}{lc($FORM{protocol})};
		foreach my $key (keys (%{$mapref})) {
			next if ($key eq "DEFAULT");
			(my $urlkey = $key) =~ s/([+*\/\\])/\\$1/g;
			if (${$mapref}{$key} eq "") {
				$incoming =~ s/([\?\&])($urlkey)=[^\&]*\&/$1/g;
			} elsif (${$mapref}{$key} =~ /=/) {
				$incoming =~ s/([\?\&])($urlkey)\&/"${1}${$mapref}{$2}&"/e;
			}
		}
		foreach my $key (keys (%{$mapref})) {
			next if ($key eq "DEFAULT");
			$incoming =~ s/([\?\&])($key)=/"${1}${$mapref}{$2}="/e;
		}
		$incoming =~ s|&$||g;
		if (defined ${$mapref}{DEFAULT}) {
			$incoming .= "&${$mapref}{DEFAULT}";
		}
	}
	print "Location: $router_list{$FORM{router}}${incoming}\n\n";
	exit;
}

my $command = sprintf($query_cmd, $FORM{addr});

print LOG " \"$FORM{router}\" \"$command\"\n";
close LOG;

&print_head($command);

if ($FORM{addr} !~ /^[\w\.\^\$\-\:\/ ]*$/) {
	&print_error("Illegal characters in parameter string");
}

$FORM{addr} = "" if ($FORM{addr} =~ /^[ ]*$/);

if ($query_cmd =~ /%s/) {
	&print_error("Parameter missing") if ($FORM{addr} eq "");
} else {
	&print_warning("No parameter needed") if ($FORM{addr} ne "");
}

my %AS = &read_as_list($asfile);

if ($ostypes{$FORM{router}} eq "junos") {
	if ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+)$/) {
		# show bgp n.. <IP> ---> show bgp neighbor <IP>
		$command = "show bgp neighbor $1";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) ro\w*$/) {
		# show bgp n.. <IP> ro.. ---> show route receive-protocol bgp <IP>
		$command = "show route receive-protocol bgp $1";
	} elsif ($command =~ /^show bgp neighbors ([\d\.A-Fa-f:]+) routes all$/) {
		# show bgp neighbors <IP> routes all ---> show route receive-protocol bgp <IP> all
		$command = "show route receive-protocol bgp $1 all";
	} elsif ($command =~ /^show bgp neighbors ([\d\.A-Fa-f:]+) routes damping suppressed$/) {
		# show bgp neighbors <IP> routes damping suppressed ---> show route receive-protocol bgp <IP> damping suppressed
		$command = "show route receive-protocol bgp $1 damping suppressed";
	} elsif ($command =~ /show bgp n\w*\s+([\d\.A-Fa-f:]+) a[\w\-]*$/) {
		# show ip bgp n.. <IP> a.. ---> show route advertising-protocol bgp <IP>
		$command = "show route advertising-protocol bgp $1";
	} elsif ($command =~ /^show bgp\s+([\d\.A-Fa-f:\/]+)$/) {
		# show bgp <IP> ---> show route protocol bgp <IP> all
		$command = "show route protocol bgp $1 all";
	} elsif ($command =~ /^show bgp\s+([\d\.A-Fa-f:\/]+) exact$/) {
		# show bgp <IP> exact ---> show route protocol bgp <IP> all exact
		$command = "show route protocol bgp $1 all exact";
	} elsif ($command =~ /^show bgp re\s+(.*)$/) {
		# show ip bgp re <regexp> ---> show route aspath-regex <regexp> all
		my $re = $1;
		$re = "^.*${re}" if ($re !~ /^\^/);
		$re = "${re}.*\$" if ($re !~ /\$$/);
		$re =~ s/_/ /g;
		$command = "show route aspath-regex \"$re\" all";
	}
}

&print_results($FORM{router}, $router_list{$FORM{router}}, $command);

&print_tail;
exit;

sub read_config {
	my $xp = new XML::Parser(ProtocolEncoding => "ISO-8859-1", Handlers => {Char => \&xml_charparse, Start => \&xml_startparse, End => \&xml_endparse});
	$xp->parsefile("lg.conf");
	undef($xp);
}

sub xml_charparse {
	my ($xp,$str) = @_;
	return if $str =~ /^\s*$/m;
	my $elem = lc($xp->current_element);
	if ($xml_current_router_name ne "") {
		if ($elem eq "url") {
			$router_list{$xml_current_router_name} = $str;
			push @routers, $xml_current_router_name;
		} elsif ($elem eq "title") {
			$namemap{$xml_current_router_name} .= $str;
		} else {
			die("Illegal value for configuration tag \"" . $xp->current_element . "\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif (($xml_current_cgi_name ne "") && ($xml_current_replace_name ne "")) {
		if (($elem eq "replace") ||
		    ($elem eq "default")) {
			$cmdmap{$xml_current_cgi_name}{"ipv4"}{$xml_current_replace_name} .= $str if ($xml_current_replace_proto ne "ipv6");
			$cmdmap{$xml_current_cgi_name}{"ipv6"}{$xml_current_replace_name} .= $str if ($xml_current_replace_proto ne "ipv4");
		} else {
			die("Illegal value for configuration tag \"" . $xp->current_element . "\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif ($elem eq "lgurl") {
		$lgurl = $str;
	} elsif ($elem eq "logfile") {
		$logfile = $str;
	} elsif ($elem eq "aslist") {
		$asfile = $str;
	} elsif ($elem eq "logoimage") {
		$logoimage = $str;
	} elsif ($elem eq "htmltitle") {
		$title = $str;
	} elsif ($elem eq "favicon") {
		$favicon = $str;
	} elsif ($elem eq "contactmail") {
		$email = $str;
	} elsif ($elem eq "rshcmd") {
		$rshcmd = $str;
	} elsif ($elem eq "httpmethod") {
		$httpmethod = $str;
	} elsif ($elem eq "separator") {
		push @routers, "---- $str ----";
	} else {
		print "    C [$xml_current_router_name] [" . $xp->current_element . "] [$str]\n";    
	}
}

sub xml_startparse {
	my ($xp,$str,@attrval) = @_;
	my $elem = lc($xp->current_element);
	my $str2 = lc($str);
	if ($elem eq "") {
		if ($str2 ne "lg_conf_file") {
			die("Illegal configuration tag \"$str\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif ($elem eq "lg_conf_file") {
		if ($str2 eq "logoimage") {
			for (my $i = 0; $i <= $#attrval; $i += 2) {
				if (lc($attrval[$i]) eq "align") {
					$logoalign = " Align=\"" . $attrval[$i+1] . "\"";
				} elsif (lc($attrval[$i]) eq "link") {
					$logolink = $attrval[$i+1];
				} else {
					die("Illegal parameter for LogoImage \"" . $attrval[$i] . "\" at line " . $xp->current_line . ", column " . $xp->current_column);
				}
			}
		} elsif (($str2 ne "lgurl") &&
		    ($str2 ne "logfile") &&
		    ($str2 ne "aslist") &&
		    ($str2 ne "htmltitle") &&
		    ($str2 ne "favicon") &&
		    ($str2 ne "contactmail") &&
		    ($str2 ne "rshcmd") &&
		    ($str2 ne "httpmethod") &&
		    ($str2 ne "router_list") &&
		    ($str2 ne "argument_list")) {
			die("Illegal configuration tag \"$str\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif ($elem eq "router_list") {
		if ($str2 eq "router") {
			for (my $i = 0; $i <= $#attrval; $i += 2) {
				if (lc($attrval[$i]) eq "name") {
					$xml_current_router_name = $attrval[$i+1];
					$ostypes{$xml_current_router_name} = lc($default_ostype);
					$ipv4enabled ++;
				} elsif (lc($attrval[$i]) eq "default") {
					if (lc($attrval[$i+1]) eq "yes") {
						$default_router = $xml_current_router_name;
					}
				} elsif (lc($attrval[$i]) eq "enableipv6") {
					if (lc($attrval[$i+1]) eq "yes") {
						$ipv4enabled--;
						$ipv6enabled++;
					}
				} elsif (lc($attrval[$i]) eq "ostype") {
					$ostypes{$xml_current_router_name} = lc($attrval[$i+1]);
				}
			}
			if ($xml_current_router_name eq "") {
				die("Variable \"Name\" missing at line " . $xp->current_line . ", column " . $xp->current_column);
			}
		} elsif ($str2 eq "separator") {
		} else {
			die("Illegal configuration tag \"$str\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif ($elem eq "router") {
		if (($str2 ne "title") &&
		    ($str2 ne "url")) {
			die("Illegal configuration tag \"$str\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif ($elem eq "argument_list") {
		if ($str2 eq "lg") {
			for (my $i = 0; $i <= $#attrval; $i += 2) {
				if (lc($attrval[$i]) eq "url") {
					$xml_current_cgi_name = $attrval[$i+1];
				}
			}
			if ($xml_current_cgi_name eq "") {
				die("Variable \"URL\" missing at line " . $xp->current_line . ", column " . $xp->current_column);
			}
		} else {
			die("Illegal configuration tag \"$str\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif ($elem eq "lg") {
		if ($str2 eq "replace") {
			for (my $i = 0; $i <= $#attrval; $i += 2) {
				if (lc($attrval[$i]) eq "param") {
					$xml_current_replace_name = $attrval[$i+1];
				} elsif (lc($attrval[$i]) eq "proto") {
					$xml_current_replace_proto = lc($attrval[$i+1]);
				}
			}
			if ($xml_current_replace_name eq "") {
				die("Variable \"Param\" missing at line " . $xp->current_line . ", column " . $xp->current_column);
			}
			$cmdmap{$xml_current_cgi_name}{"ipv4"}{$xml_current_replace_name} = "" if ($xml_current_replace_proto ne "ipv6");
			$cmdmap{$xml_current_cgi_name}{"ipv6"}{$xml_current_replace_name} = "" if ($xml_current_replace_proto ne "ipv4");
		} elsif ($str2 eq "default") {
			$xml_current_replace_name = "DEFAULT";
		} else {
			die("Illegal configuration tag \"$str\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} else {
		die("ASSERT str=\"$str\" elem=\"" . $xp->current_element . "\" at line " . $xp->current_line . ", column " . $xp->current_column);

	}
}

sub xml_endparse {
	my ($xp,$str) = @_;
	my $elem = lc($xp->current_element);
	my $str2 = lc($str);

	if ($elem eq "router_list") {
		if ($str2 eq "router") {
			$xml_current_router_name = "";
		}
	} elsif ($elem eq "lg") {
		if (($str2 eq "replace") ||
		    ($str2 eq "default")) {
			$xml_current_replace_name = "";
			$xml_current_replace_proto = "";
		}
	}
}

sub print_head {
	my ($arg) = @_;
	print "Content-type: text/html\n\n";
	print "<!--\n\t$SYS_progid\n\thttp://freshmeat.net/projects/lg/\n-->\n";
	print "<Html>\n";
	print "<Head>\n";
	if ($arg ne "") {
		print "<Title>$title - $arg</Title>\n";
	} else {
		print "<Title>$title</Title>\n";
	}
	if ($favicon ne "") {
		print "<LINK REL=\"shortcut icon\" HREF=\"${favicon}\">\n";
	}
	print "</Head>\n";
	print "<Body bgcolor=\"#FFFFFF\" text=\"#000000\">\n";
	if ($logoimage ne "") {
		print "<Table Border=\"0\" Width=\"100%\"><Tr><Td$logoalign>";
		print "<A HREF=\"$logolink\">" if ($logolink ne "");
		print "<Img Src=\"$logoimage\" Border=\"0\">";
		print "</A>" if ($logolink ne "");
		print "</Td></Tr></Table>\n";
	}
	print "<Center>\n";
	if ($arg ne "") {
		print "<H2>$title - $arg</H2>\n";
	} else {
		print "<H2>$title</H2>\n";
	}
	print "</Center>\n";
	print "<P>\n";
	print "<Hr size=2 width=85% noshade>\n";
	print "<P>\n";
}

sub print_form {
	print <<EOT;
<Form Method="$httpmethod">
<center>
<table border=0 bgcolor="#EFEFEF"><tr><td>
<table border=0 cellpading=2 cellspacing=2>
<tr>
<th bgcolor="#000000" nowrap><font color="#FFFFFF">Type of Query</font></th>
<th bgcolor="#000000" nowrap><font color="#FFFFFF">Additional parameters</font></th>
<th bgcolor="#000000" nowrap><font color="#FFFFFF">Node</font></th></tr>
<tr><td>
<table border=0 cellpading=2 cellspacing=2>
<tr><td><Input type="radio" name="query" value="bgp"></td><td>&nbsp;bgp</td></tr>
<tr><td><Input type="radio" name="query" value="advertised-routes"></td><td>&nbsp;bgp&nbsp;advertised-routes</td></tr>
<tr><td><Input type="radio" name="query" value="summary"></td><td>&nbsp;bgp&nbsp;summary</td></tr>
<tr><td><Input type="radio" name="query" value="ping"></td><td>&nbsp;ping</td></tr>
<tr><td><Input type="radio" name="query" value="trace" SELECTED></td><td>&nbsp;trace</td></tr>
EOT
	if ($ipv4enabled && $ipv6enabled) {
		print <<EOT;
<tr><td></td><td><Select Name="protocol">
<Option Value = \"IPv4\"> IPv4
<Option Value = \"IPv6\"> IPv6
</Select></td></tr>
</table>
EOT
	} elsif ($ipv4enabled) {
		print "</table>\n<Input type=\"hidden\" name=\"protocol\"value=\"IPv4\">\n";
	} elsif ($ipv6enabled) {
		print "</table>\n<Input type=\"hidden\" name=\"protocol\"value=\"IPv6\">\n";
	}
	print <<EOT;
</td>
<td align=center>&nbsp;<br><Input Name="addr" size=30><br><font size=-1>&nbsp;<sup>&nbsp;</sup>&nbsp;</font></td>
<td>&nbsp;<br><Select Name="router">
EOT
	my $remotelg = 0;
	for (my $i = 0; $i <= $#routers; $i++) {
		my $router = $routers[$i];
		if ($router =~ /^---- .* ----$/) {
			print "<Option Value =\"\"> $router\n";
			next;
		}
		my $descr = "";
		my $default = "";
		if ($router eq $default_router) {
			$default = " selected";
		}
		if (defined $namemap{$router}) {
			$descr = $namemap{$router};
		} else {
			$descr = $router;
		}
		if ($router_list{$router} =~ /^http/) {
			$descr .= " *";
			$remotelg++;
		}
		print "<Option Value=\"$router\"$default> $descr\n";
	}
	if ($remotelg) {
		$remotelg = "<sup>*</sup>&nbsp;remote&nbsp;LG&nbsp;script";
	} else {
		$remotelg = "<sup>&nbsp;</sup>&nbsp;";
	}
print <<EOT;
</Select><br><font size=-1>&nbsp;&nbsp;$remotelg</font></td>
</tr>
<tr><td align="center" colspan=3>
<P>
<Input Type="submit" Value="Submit"> | 
<Input Type="reset" Value="Reset"> 
<P>
</td></tr>
</table>
</td></tr></table>
</center>
<P>
</Form>
EOT
}

sub print_tail {
	print <<EOT;
<P>
<HR Size=2 Width=85% noshade>
<P>
</Body>
<Tail>
<Center>
<I>
  Please email questions or comments to
 <A Href="mailto:$email">$email</a>.
</I>
<P>
</Center>
</Tail>
</Html>
EOT
}

sub print_error
{
	print "<Center><Font size=+2 color=\"#ff0000\">" . join(" ", @_) . "</Font></Center>\n";
	&print_tail;
	exit 1;
}

sub print_warning
{
	print "<Center><Font size=+2 color=\"#0000ff\">WARNING! " . join(" ", @_) . "</Font></Center>\n";
	print <<EOT;
<P>
<HR Size=2 Width=85% noshade>
<P>
EOT
}

sub print_results
{
	my ($hostname, $host, $command) = @_;
	my $best = 0;
	my $count = 0;
	my $telnet;
	my $ssh;
	my @output;
	# This regexp is from RFC 2396 - URI Generic Syntax
	if ($host !~ /^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/) {
		die ("Illegal URI: \"$host\"");
	}
	my $scheme = $2;
	$host = $4;
	if ($host !~ /^((([^:\@\[]+)(:([^\@]+))?)\@)?([^\/?#]*)$/) {
		die ("Can't extract login/pass from host: \"$host\"");
	}
	my $login = $3;
	my $password = $5;
	$host = $6;
	my $port;
	if ($host =~ /^\[(.+)\](:(\d+))?$/) {
		$host = $1;
		$port = $3;
	} elsif ($host =~ /^([^:]+)(:(\d+))?$/) {
		$host = $1;
		$port = $3;
	} else {
		die ("Illegal host address \"$host\"");
	}

	print "<B>Router:</B> $hostname\n";
	print "<BR>\n";
	print "<B>Command:</B> $command\n";
	print "<P><Pre><code>\n";
	if ($scheme eq "rsh") {
		open(P, "$rshcmd $host \'$command\' |");
	} elsif ($scheme eq "ssh") {
		$port = 22 if ($port eq "");
		$ssh = Net::SSH::Perl->new($host, port => $port);
		$ssh->login($login, $password);
		my ($out, $err) = $ssh->cmd("$command");
		@output = split (/\n/, $out);
	} elsif ($scheme eq "telnet") {
		$port = 23 if ($port eq "");
		$telnet = new Net::Telnet;
		$telnet->open(Host => $host,
		              Port => $port);
		if ($ostypes{$FORM{router}} eq "junos") {
			$telnet->waitfor('/ogin:.*$/');
			$telnet->print("$login");
			$telnet->waitfor('/word:.*$/');
			$telnet->print("$password");
			$telnet->waitfor('/> $/');
			$telnet->print("");
			my ($prematch, $match) = $telnet->waitfor('/.*> $/');
			$match =~ s/[^\d\w> ]/./g;
			$telnet->prompt("/${match}/");
			@output = $telnet->cmd("$command | no-more");
		} elsif (($ostypes{$FORM{router}} eq "ios") || ($ostypes{$FORM{router}} eq "zebra")) {
			if ($login ne "") {
				$telnet->waitfor('/(ogin|name|word):.*$/');
				$telnet->print("$login");
			}
			if ($password ne "") {
				$telnet->waitfor('/word:.*$/');
				$telnet->print("$password");
			}
			$telnet->waitfor('/[\@\w\-\.]+>[ ]*$/');
			$telnet->print("terminal length 0");
			my ($prematch, $match) = $telnet->waitfor('/.*>[ ]*$/');
			$match =~ s/[^\d\w> ]/./g;
			$telnet->prompt("/${match}/");
			@output = $telnet->cmd("$command");
		}
		$telnet->print("quit");
		$telnet->close;
	} else {
		print_error("Configuration error, no such scheme: $scheme\n");
	}
	my $lastip = "";
	while (1) {
		if (($scheme eq "telnet") ||
		    ($scheme eq "ssh")) {
			last if ($#output < 0);
			$_ = shift (@output);
		} else {
			last if (eof(P));
			$_ = <P>;
		}

		s|[\r\n]||g;
		s|&|&amp;|g;
		s|<|&lt;|g;
		s|>|&gt;|g;
		if ($command eq "show ip bgp summary") {
			s/( local AS number )(\d+)/($1 . as2link($2))/e;
			s/^([\d\.]+\s+\d+\s+)(\d+)/($1 . as2link($2))/e;
			s/^(\d+\.\d+\.\d+\.\d+)(\s+.*\s+)([1-9]\d*)$/($1 . $2 . bgplink($3, "neighbors+$1+routes"))/e;
			s/^(\d+\.\d+\.\d+\.\d+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
			# Zebra IPv6 neighbours
			s/^(                4\s+)(\d+)/($1 . as2link($2))/e;
			s/^([\dA-Fa-f:]+)$/bgplink($1, "neighbors+$1")/e;
		} elsif ($command eq "show bgp ipv6 summary") {
			s/^(                4\s+)(\d+)/($1 . as2link($2))/e;
			if (/^([\dA-Fa-f:]+)$/) {
				$lastip = $1;
				s/^([\dA-Fa-f:]+)$/bgplink($1, "neighbors+$1")/e;
			}
			if (($lastip ne "") && (/^(\s+.*\s+)([1-9]\d*)$/)) {
				s/^(\s+.*\s+)([1-9]\d*)$/($1 . bgplink($2, "neighbors+${lastip}+routes"))/e;
				$lastip = "";
			}
		} elsif ($command eq "show bgp summary") {
			# JunOS
			if (/^([\dA-Fa-f:][\d\.A-Fa-f:]+)\s+/) {
				$lastip = $1;
				# IPv4
				s/^(\d+\.\d+\.\d+\.\d+)(\s+.*\s+)([1-9]\d*)(\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d:]+\s+)(\d+)\/(\d+)\/(\d+)(\s+)/($1 . $2 . bgplink($3, "neighbors+$1+routes") . $4 . bgplink($5, "neighbors+$1+routes") . "\/" . bgplink($6, "neighbors+$1+routes+all") . "\/" . bgplink($7, "neighbors+$1+routes+damping+suppressed") . $8)/e;
				# IPv4/IPv6
				s/^([\dA-Fa-f:][\d\.A-Fa-f:]+\s+)(\d+)(\s+)/($1 . as2link($2) . $3)/e;
				s/^([\dA-Fa-f:][\d\.A-Fa-f:]+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
			}
			if (($lastip ne "") && (/(  [^:]+: )(\d+)\/(\d+)\/(\d+)$/)) {
				s/^(  [^:]+: )(\d+)\/(\d+)\/(\d+)$/($1 . bgplink($2, "neighbors+${lastip}+routes") . "\/" . bgplink($3, "neighbors+${lastip}+routes+all") . "\/" . bgplink($4, "neighbors+${lastip}+routes+damping+suppressed"))/e;
				$lastip = "";
			}
		} elsif ($command =~ /^show ip bgp n\w*\s+[\d\.]+ ro/i) {
			s/^([\* ](&gt;| ).{57})([\d\s]+)([ie\?])$/($1 . as2link($3) . $4)/e;
			s/^([\* ](&gt;| )[i ])([\d\.\/]+)(\s+)/($1 . bgplink($3, $3) . $4)/e;
		} elsif ($command =~ /^show bgp ipv6 n\w*\s+[\dA-Fa-f:]+ ro/i) {
			s/^(.{59})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/^([\* ])(&gt;| )([i ])([\dA-Fa-f:\/]+)(\s+)/($1 . $2 . $3 . bgplink($4, $4) . $5)/e;
			s/^([\* ])(&gt;| )([i ])([\dA-Fa-f:\/]+)$/($1 . $2 . $3 . bgplink($4, $4) . $5)/e;
		} elsif ($command =~ /^show route receive-protocol bgp\s+[\d\.A-Fa-f:]+/i) {
			s/^([\d\.\s].{64})([\d\s]+)([I\?])$/($1 . as2link($2) . $3)/e;
			s/^([\d\.\s].{24})([\d\.]+)(\s+)/($1 . bgplink($2, "neighbors+$2") . $3)/e;
			s/^([\d\.\/]+)(\s+)/(bgplink($1, $1) . $2)/e;
			s/^([\d\.A-Fa-f:\/]+)(\s+)/(bgplink($1, "$1+exact") . $2)/e;
			s/^([\d\.A-Fa-f:\/]+)\s*$/(bgplink($1, "$1+exact"))/e;
		} elsif ($command =~ /^show ip bgp n\w*\s+[\d\.]+ a/i) {
			s/^(.{59})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/^([\* ])(&gt;| )([i ])([\d\.\/]+)(\s+)/($1 . $2 . $3 . bgplink($4, $4) . $5)/e;
		} elsif ($command =~ /^show bgp ipv6 n\w*\s+[\dA-Fa-f:]+ a/i) {
			s/^(.{61})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/^([\* ])(&gt;| )([i ])([\dA-Fa-f:\/]+)$/($1 . $2 . $3 . bgplink($4, $4))/e;
			s/^([\* ])(&gt;| )([i ])([\dA-Fa-f:\/]+)(\s+)/($1 . $2 . $3 . bgplink($4, $4) . $5)/e;
		} elsif ($command =~ /^show route advertising-protocol bgp\s+[\d\.A-Fa-f:]+$/i) {
			s/^([\d\.A-Fa-f:\/]+)\s*$/(bgplink($1, "$1+exact"))/e;
			s/^(.{30}[ ]{7})([\d\s]+)([I\?])$/($1 . as2link($2) . $3)/e;
		} elsif ($command =~ /^show ip bgp n\w*\s+([\d\.]+)/i) {
			my $ip = $1;
			s/(Prefix )(advertised)( \d+)/($1 . bgplink($2, "neighbors+$ip+advertised-routes") . $3)/e;
			s/(prefixes )(received)( \d+)/($1 . bgplink($2, "neighbors+$ip+routes") . $3)/e;
			s/(\s+Received prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes") . $3)/e;
			s/ (\d+)( accepted prefixes)/(bgplink($1, "neighbors+$ip+routes") . $2)/e;
			s/^(  \d+ )(accepted)( prefixes consume \d+ bytes)/($1 . bgplink($2, "neighbors+$ip+routes") . $3)/e;
			s/^( Description: )(.*)$/$1<B>$2<\/B>/;
			s/(, remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
			s/(, local AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		} elsif ($command =~ /^show bgp ipv6 n\w*\s+([\dA-Fa-f:]+)/i) {
			my $ip = $1;
			s/(Prefix )(advertised)( \d+)/($1 . bgplink($2, "neighbors+$ip+advertised-routes") . $3)/e;
			s/^  (\d+)( accepted prefixes)/(bgplink($1, "neighbors+$ip+routes") . $2)/e;
			s/^( Description: )(.*)$/$1<B>$2<\/B>/;
			s/(, remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
			s/(, local AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+)/i) {
			my $ip = $1;
			s/(\s+AS )(\d+)/($1 . as2link($2))/eg;
			s/(\s+AS: )(\d+)/($1 . as2link($2))/eg;
			s/^(    Active prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes"))/e;
			s/^(    Received prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes+all"))/e;
			s/^(    Suppressed due to damping:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes+damping+suppressed"))/e;
			s/^(  )(Export)(: )/($1 . bgplink($2, "neighbors+$ip+advertised-routes") . $3)/e;
			s/( )(Import)(: )/($1 . bgplink($2, "neighbors+$ip+routes+all") . $3)/e;
		} elsif ($command =~ /^show ip bgp re/i) {
			s/^(.{59})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/^([\* ])(&gt;| )([i ])([\d\.\/]+)(\s+)/($1 . $2 . $3 . bgplink($4, $4) . $5)/e;
			s/(, remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		} elsif ($command =~ /^show bgp ipv6 re/i) {
			s/^(.{59})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/^([\* ])(&gt;| )([i ])([\dA-Fa-f:\/]+)(\s+)/($1 . $2 . $3 . bgplink($4, $4) . $5)/e;
			s/^([\* ])(&gt;| )([i ])([\dA-Fa-f:\/]+)$/($1 . $2 . $3 . bgplink($4, $4) . $5)/e;
		} elsif (($command =~ /^show route protocol bgp /i) || ($command =~ /^show route aspath-regex /i)) {
			if (/^[\d\.A-Fa-f:\/\s]{19}([\*\+\- ])\[BGP\//) {
				if ($1 =~ /[\*\+]/) {
					$best = "\#FF0000";
				} elsif ($1 eq "-") {
					$best = "\#008800";
				} else {
					$best = "";
				}
			} elsif (/^$/) {
				$best = "";
			}
			$_ = "<FONT COLOR=\"${best}\">$_</FONT>" if ($best ne "");
			s/( from )([0-9\.A-Fa-f:]+)/($1 . bgplink($2, "neighbors+$2"))/e;
			$_ = as2link($_) if (/\s+AS path: \d+/);
			s/^(<FONT COLOR=\"#FF0000\">)?([\dA-Fa-f:]+[\d\.A-Fa-f:\/]+)(\s*)/("$1<B>" . bgplink($2, "$2+exact") . "<\/B>$3")/e;
		} elsif ($command =~ /bgp/) {
			s|^(BGP routing table entry for) (\S+)|$1 <B>$2</B>|;
			s|^(Paths:\ .*)\ best\ \#(\d+)
			 |$1\ <FONT\ COLOR="\#FF0000">best\ \#$2</FONT>|x
			&& do { $best = $2; };
			# Fix for IPv6 route output where there are no addional 3 spaces before addresses
			if ((/^  Advertised to non peer-group peers:$/) &&
			    ($command =~ / ipv6 /)) {
				$count--;
			}
			if ((/^  (\d+.*)/ && ! /^  \d+\./) || (/^  Local/)) {
				$count++;
				$_ = as2link($_);
			}
			$_ = "<FONT COLOR=\"\#FF0000\">$_</FONT>" if $best && $best == $count;
			s/( from )([0-9\.A-Fa-f:]+)( )/($1 . bgplink($2, "neighbors+$2") . $3)/e;
		} elsif ($command =~ /^trace/i) {
			s/(\[AS\s+)(\d+)(\])/($1 . as2link($2) . $3)/e;
		}
		print "$_\n";
	}
	close(P);
	print "</code></Pre>\n";
}

######## Portion of code is borrowed from NCSA WebMonitor "mail" code 

sub cgi_decode {
	my ($incoming) = @_;

	my %FORM;
	my $ref = "FORM";

	my @pairs = split(/&/, $incoming);

	foreach (@pairs) {
		my ($name, $value) = split(/=/, $_);

		$name  =~ tr/+/ /;
		$value =~ tr/+/ /;
		$name  =~ s/%([A-F0-9][A-F0-9])/pack("C", hex($1))/gie;
		$value =~ s/%([A-F0-9][A-F0-9])/pack("C", hex($1))/gie;

		#### Strip out semicolons unless for special character
		$value =~ s/;/$$/g;
		$value =~ s/&(\S{1,6})$$/&\1;/g;
		$value =~ s/$$/ /g;

		$value =~ s/\|/ /g;
		$value =~ s/^!/ /g; ## Allow exclamation points in sentences

		$FORM{$name} .= $value;
	}
	return (%FORM);
}

sub read_as_list {
	my ($fn) = @_;

	local *F;
	my %AS;

	if (! open(F, $fn)) {
		print "<!-- Can't read AS list from $fn: $! -->\n";
		return;
	}
	while (<F>) {
		chop;
		if (/^#include\s+(.+)$/) {
			my %AS2 = &read_as_list($1);
			foreach my $key (keys (%AS2)) {
				$AS{$key} = $AS2{$key};
			}
			undef %AS2;
			next;
		}
		next if (/^$/ || /^\s*#/);
		my ($asnum, $descr) = split /\t+/;
		$asnum =~ s/^[^\d]*(\d+)[^\d]*$/$1/;
		$AS{$asnum} = $descr;
	}
	close(F);
	return (%AS);
}

sub as2link {
	my ($line) = @_;

	my @aslist = split(/[ ,]+/, $line);
	my %ases;
	for my $as (@aslist) {
		$ases{$as} ++ if (defined $AS{$as});;
	}
	for my $as (keys %ases) {
		my $link = "";
		if (($AS{$as} =~ /(\w+):/) && (defined $whois{$1})) {
			$link = sprintf(" HREF=\"$whois{$1}\" TARGET=_lookup", $as);
		}
		my $descr = $AS{$as};
		$descr = "$2 ($1)" if ($descr =~ /^([^:]+):(.*)$/);
		my $rep = "<A onMouseOver=\"window.status='$descr'; return true\"${link}>$as</A>";
		$line =~ s/\b$as\b/$rep/g;
	}
	return($line);
}

sub bgplink {
	my ($txt, $cmd) = @_;

	my $link = $lgurl;
	my $router = $FORM{router};

	$router =~ s/\+/%2B/;
	$router =~ s/=/%3D/;
	$router =~ s/\&/%26/g;

	$link .= "?query=bgp";
	$link .= "&protocol=" . $FORM{protocol};
	$link .= "&addr=$cmd";
	$link .= "&router=$router";
	$link =~ s/ /+/g;
	return("<A HREF=\"$link\"><B>$txt</B></A>");
}
