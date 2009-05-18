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

use XML::Parser;

my $SYS_progid = '$Id: lg.cgi,v 1.30 2004/11/25 14:12:42 cougar Exp $';

my $default_ostype = "ios";

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
my $timeout;
my $disclaimer;
my $securemode = 1;

my %router_list;
my @routers;
my %namemap;
my %ostypes;
my %logicalsystem;
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
		"ipv4"			=>	{
			"trace"			=>	"traceroute %s as-number-lookup"
			},
		"ipv6"		=>	{
			"trace"			=>	"traceroute %s"
			},
		"ipv46"			=>	{
			"bgp"			=>	"show bgp %s",
			"advertised-routes"	=>	"show route advertising-protocol bgp %s %s",
			"summary"		=>	"show bgp summary",
			"ping"			=>	"ping count 5 %s"
			}
		}
);

my %whois = (
	"RIPE"		=>	"http://www.ripe.net/perl/whois?AS%s",
	"ARIN"		=>	"http://www.arin.net/cgi-bin/whois.pl?queryinput=%s",
	"APNIC"		=>	"http://www.apnic.net/apnic-bin/whois.pl?searchtext=AS%s",
	"default"	=>	"http://www.sixxs.net/tools/whois/?AS%s"
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

$FORM{addr} =~ s/\s.*// if (($FORM{query} eq "ping") || ($FORM{query} eq "trace"));
$FORM{addr} =~ s/[^\s\d\.:\w\-_\/\$]//g;

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

if ($FORM{addr} !~ /^[\w\.\^\$\-\/ ]*$/) {
	if ($FORM{addr} =~ /^[\w\.\^\$\-\:\/ ]*$/) {
		if (($FORM{protocol} ne "IPv6") && ($ostypes{$FORM{router}} ne "junos")){
			&print_error("ERROR: IPv6 address for IPv4 query");
		}
	} else {
		&print_error("Illegal characters in parameter string");
	}
}

$FORM{addr} = "" if ($FORM{addr} =~ /^[ ]*$/);

if ($query_cmd =~ /%s/) {
	&print_error("Parameter missing") if ($FORM{addr} eq "");
} else {
	&print_warning("No parameter needed") if ($FORM{addr} ne "");
}

my %AS;
if ($asfile =~ /\.db$/) {
	use DB_File;
	tie (%AS, 'DB_File', $asfile, O_RDONLY, 0644, $DB_HASH) or
		print STDERR "Can\'t read AS database $asfile: $!\n";
} else {
	%AS = &read_as_list($asfile);
}

my $table;
$table = "table inet.0" if ($FORM{protocol} eq "IPv4");
$table = "table inet6.0" if ($FORM{protocol} eq "IPv6");

if ($ostypes{$FORM{router}} eq "junos") {
	if ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+)$/) {
		# show bgp n.. <IP> ---> show bgp neighbor <IP>
		$command = "show bgp neighbor $1";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) ro\w*$/) {
		# show bgp n.. <IP> ro.. ---> show route receive-protocol bgp <IP>
		$command = "show route receive-protocol bgp $1 $table";
	} elsif ($command =~ /^show bgp neighbors ([\d\.A-Fa-f:]+) routes all$/) {
		# show bgp neighbors <IP> routes all ---> show route receive-protocol bgp <IP> all
		$command = "show route receive-protocol bgp $1 all $table";
	} elsif ($command =~ /^show bgp neighbors ([\d\.A-Fa-f:]+) routes damping suppressed$/) {
		# show bgp neighbors <IP> routes damping suppressed ---> show route receive-protocol bgp <IP> damping suppressed
		$command = "show route receive-protocol bgp $1 damping suppressed $table";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) advertised-routes ([\d\.A-Fa-f:\/]+)$/) {
		# show ip bgp n.. <IP> advertised-routes <prefix> ---> show route advertising-protocol bgp <IP> <prefix> exact detail
		$command = "show route advertising-protocol bgp $1 $2 exact detail $table";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) receive-protocol ([\d\.A-Fa-f:\/]+)$/) {
		# show ip bgp n.. <IP> receive-protocol <prefix> ---> show route receive-protocol bgp <IP> <prefix> exact detail
		$command = "show route receive-protocol bgp $1 $2 exact detail $table";
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+) a[\w\-]*$/) {
		# show ip bgp n.. <IP> a.. ---> show route advertising-protocol bgp <IP>
		$command = "show route advertising-protocol bgp $1 $table";
	} elsif ($command =~ /^show bgp\s+([\d\.A-Fa-f:]+\/\d+)$/) {
		# show bgp <IP>/mask ---> show route protocol bgp <IP> all
		$command = "show route protocol bgp $1 terse exact all $table";
	} elsif ($command =~ /^show bgp\s+([\d\.A-Fa-f:]+)$/) {
		# show bgp <IP> ---> show route protocol bgp <IP> all
		$command = "show route protocol bgp $1 terse $table";
	} elsif ($command =~ /^show bgp\s+([\d\.A-Fa-f:\/]+) exact$/) {
		# show bgp <IP> exact ---> show route protocol bgp <IP> exact detail all
		$command = "show route protocol bgp $1 exact detail all $table";
	} elsif ($command =~ /^show bgp re\w*\s+(.*)$/) {
		# show ip bgp re <regexp> ---> show route aspath-regex <regexp> all
		my $re = $1;
		$re = ".*${re}" if ($re !~ /^\^/);
		$re = "${re}.*" if ($re !~ /\$$/);
		$re =~ s/_/ /g;
		$command = "show route protocol bgp aspath-regex \"$re\" all $table terse";
	}
}

&run_command($FORM{router}, $router_list{$FORM{router}}, $command);

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
	} elsif ($elem eq "timeout") {
		$timeout = $str;
	} elsif ($elem eq "disclaimer") {
		$disclaimer = "<CENTER><TABLE WIDTH=\"85%\"><TR><TD><FONT SIZE=\"-3\">Disclaimer: $str</FONT></TD></TR></TABLE></CENTER>\n";
	} elsif ($elem eq "securemode") {
		if ($str =~ /^(0|off|no)$/i) {
			$securemode = 0;
		} elsif ($str =~ /^(1|on|yes)$/i) {
			$securemode = 1;
		} else {
			die("Illegal securemode \"$str\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif ($elem eq "separator") {
		push @routers, "---- $str ----";
	} else {
		print "<!--    C [$xml_current_router_name] [" . $xp->current_element . "] [$str] -->\n";
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
		    ($str2 ne "timeout") &&
		    ($str2 ne "disclaimer") &&
		    ($str2 ne "securemode") &&
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
				} elsif (lc($attrval[$i]) eq "logical-system") {
					$logicalsystem{$xml_current_router_name} = lc($attrval[$i+1]);
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
	my ($titlestr) = $title;
	$titlestr .= " - $arg" if ($arg ne "");
	print "Content-type: text/html\n\n";
	print "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n";
	print "<!--\n\t$SYS_progid\n\thttp://freshmeat.net/projects/lg/\n-->\n";
	print "<HTML>\n";
	print "<HEAD>\n";
	print "<TITLE>$titlestr</TITLE>\n";
	if ($favicon ne "") {
		print "<LINK REL=\"shortcut icon\" HREF=\"${favicon}\">\n";
	}
	print "<meta name=\"description\" content=\"$titlestr\" \>\n";
	print "<meta name=\"keywords\" content=\"Looking glass, LG, BGP, prefix-list, AS-path, ASN, traceroute, ping, IPv6, Cisco, Juniper, Zebra, Quagga, internet\" />\n";
	print "</HEAD>\n";
	print "<BODY BGCOLOR=\"#FFFFFF\" TEXT=\"#000000\">\n";
	if ($logoimage ne "") {
		print "<TABLE BORDER=\"0\" WIDTH=\"100%\"><TR><TD$logoalign>";
		print "<A HREF=\"$logolink\">" if ($logolink ne "");
		print "<IMG SRC=\"$logoimage\" BORDER=\"0\" ALT=\"LG\">";
		print "</A>" if ($logolink ne "");
		print "</TD></TR></TABLE>\n";
	}
	print "<CENTER>\n";
	print "<H2>$titlestr</H2>\n";
	print "</CENTER>\n";
	print "<P>\n";
	print "<HR SIZE=2 WIDTH=\"85%\" NOSHADE>\n";
	print "<P>\n";
}

sub print_form {
	print <<EOT;
<FORM METHOD="$httpmethod" ACTION="$lgurl">
<CENTER>
<TABLE BORDER=0 BGCOLOR="#EFEFEF"><TR><TD>
<TABLE BORDER=0 CELLPADDING=2 CELLSPACING=2>
<TR>
<TH BGCOLOR="#000000" NOWRAP><FONT COLOR="#FFFFFF">Type of Query</FONT></TH>
<TH BGCOLOR="#000000" NOWRAP><FONT COLOR="#FFFFFF">Additional parameters</FONT></th>
<TH BGCOLOR="#000000" NOWRAP><FONT COLOR="#FFFFFF">Node</FONT></TH></TR>
<TR><TD>
<TABLE BORDER=0 CELLPADDING=2 CELLSPACING=2>
<TR><TD><INPUT TYPE="radio" NAME="query" VALUE="bgp"></TD><TD>&nbsp;bgp</TD></TR>
<TR><TD><INPUT TYPE="radio" NAME="query" VALUE="advertised-routes"></TD><TD>&nbsp;bgp&nbsp;advertised-routes</TD></TR>
<TR><TD><INPUT TYPE="radio" NAME="query" VALUE="summary"></TD><TD>&nbsp;bgp&nbsp;summary</TD></TR>
<TR><TD><INPUT TYPE="radio" NAME="query" VALUE="ping"></TD><TD>&nbsp;ping</TD></TR>
<TR><TD><INPUT TYPE="radio" NAME="query" VALUE="trace" CHECKED></TD><TD>&nbsp;trace</TD></TR>
EOT
	if ($ipv4enabled && $ipv6enabled) {
		print <<EOT;
<TR><TD></TD><TD><SELECT NAME="protocol">
<OPTION VALUE=\"IPv4\"> IPv4
<OPTION VALUE=\"IPv6\"> IPv6
</SELECT></TD></TR>
</TABLE>
EOT
	} elsif ($ipv4enabled) {
		print "</TABLE>\n<INPUT TYPE=\"hidden\" NAME=\"protocol\" VALUE=\"IPv4\">\n";
	} elsif ($ipv6enabled) {
		print "</TABLE>\n<INPUT TYPE=\"hidden\" NAME=\"protocol\" VALUE=\"IPv6\">\n";
	}
	print <<EOT;
</TD>
<TD ALIGN="CENTER">&nbsp;<BR><INPUT NAME="addr" SIZE="30"><BR><FONT SIZE="-1">&nbsp;<SUP>&nbsp;</SUP>&nbsp;</FONT></TD>
<TD ALIGN="RIGHT">&nbsp;<BR><SELECT NAME="router">
EOT
	my $remotelg = 0;
	my $optgroup = 0;
	for (my $i = 0; $i <= $#routers; $i++) {
		my $router = $routers[$i];
		if ($router =~ /^---- (.*) ----$/) {
			$router = $1;
			print "</OPTGROUP>\n" if ($optgroup);
			print "<OPTGROUP LABEL=\"" . html_encode($router) . "\">\n";
			$optgroup = 1;
			next;
		}
		my $descr = "";
		my $default = "";
		if ($FORM{router} ne "") {
			if ($router eq $FORM{router}) {
				$default = " selected";
			}
		} elsif ($router eq $default_router) {
			$default = " SELECTED";
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
		print "<OPTION VALUE=\"". html_encode($router) . "\"$default> " . html_encode($descr) . "\n";
	}
	print "</OPTGROUP>\n" if ($optgroup);
	if ($remotelg) {
		$remotelg = "<SUP>*</SUP>&nbsp;remote&nbsp;LG&nbsp;script";
	} else {
		$remotelg = "<SUP>&nbsp;</SUP>&nbsp;";
	}
print <<EOT;
</SELECT><BR><FONT SIZE="-1">&nbsp;&nbsp;$remotelg</FONT></TD>
</TR>
<TR><TD ALIGN="CENTER" COLSPAN=3>
<P>
<INPUT TYPE="SUBMIT" VALUE="Submit"> | 
<INPUT TYPE="RESET" VALUE="Reset"> 
<P>
</TD></TR>
</TABLE>
</TD></TR></TABLE>
</CENTER>
<P>
</FORM>
EOT
}

sub print_tail {
	print <<EOT;
<P>
<HR SIZE="2" WIDTH="85%" NOSHADE>
$disclaimer
<P>
<CENTER>
<I>
  Please email questions or comments to
 <A HREF="mailto:$email">$email</A>.
</I>
<P>
</CENTER>
</BODY>
</HTML>
EOT
}

sub print_error
{
	print "<CENTER><FONT SIZE=\"+2\" COLOR=\"#ff0000\">" . join(" ", @_) . "</FONT></CENTER>\n";
	&print_tail;
	exit 1;
}

sub print_warning
{
	print "<CENTER><FONT SIZE=\"+2\" COLOR=\"#0000ff\">WARNING! " . join(" ", @_) . "</FONT></CENTER>\n";
	print <<EOT;
<P>
<HR SIZE=2 WIDTH="85%" NOSHADE>
<P>
EOT
}

my $regexp = 0;

sub run_command
{
	my ($hostname, $host, $command) = @_;
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
	if ($host =~ /^\[(.+)\](:([\d,]+))?$/) {
		$host = $1;
		$port = $3;
	} elsif ($host =~ /^([^:]+)(:([\d,]+))?$/) {
		$host = $1;
		$port = $3;
	} else {
		die ("Illegal host address \"$host\"");
	}

	print "<B>Router:</B> " . html_encode($hostname) . "\n";
	print "<BR>\n";
	print "<B>Command:</B> " . html_encode($command) . "\n";
	print "<P><PRE><CODE>\n";

	if (($command =~ /show route protocol bgp aspath-regex \"(.*)\"/) ||
	    ($command =~ /show ip bgp reg\w*\s+(.*)/)) {
		$regexp = $1;
	}

	if ($scheme eq "rsh") {
		print_error("Configuration error, missing rshcmd") if ($rshcmd eq "");
		open(P, "$rshcmd $host \'$command\' |");
		while (<P>) {
			showline($_);
		}
		close(P);
	} elsif ($scheme eq "ssh") {
		eval "
			use IO::Handle;
			use Net::SSH::Perl;
			use Net::SSH::Perl::Cipher;
		";
		die $@ if $@;
		my $remotecmd = $command;
		$remotecmd = "set cli logical-system $logicalsystem{$FORM{router}}; " . $command if (defined $logicalsystem{$FORM{router}});
		$port = 22 if ($port eq "");
		my $ssh = Net::SSH::Perl->new($host, port => $port);
		if ($] > 5.007) {
			require Encode;
			$login = Encode::encode_utf8($login);
			$password = Encode::encode_utf8($password);
			$remotecmd = Encode::encode_utf8($remotecmd);
		}
		$ssh->login($login, $password);
		$ssh->register_handler('stdout', sub { showline($_[1]->bytes); });
		$ssh->register_handler('stderr', sub { showline($_[1]->bytes); });
		$ssh->cmd("$remotecmd");
	} elsif ($scheme eq "telnet") {
		my @output;
		eval "
			use Net::Telnet;
		";
		die $@ if $@;
		if ($ostypes{$FORM{router}} eq "zebra") {
			if (($command =~ /^ping /) || ($command =~ /^traceroute /)) {
				$port = $1 if ($port =~ /^(\d+),\d*$/);
				$port = 2601 if ($port eq "");
			} else {
				$port = $1 if ($port =~ /^\d*,(\d+)$/);
				$port = 2605 if ($port eq "");
			}
		}
		$port = 23 if ($port eq "");
		my $telnet = new Net::Telnet;
		$telnet->errmode( sub { print "ERROR:" . join('|', @_) . "\n"; } );
		$telnet->timeout($timeout);
		$telnet->option_callback( sub { return; } );
		$telnet->option_accept(Do => 31);		# TELOPT_NAWS
		$telnet->open(Host => $host,
		              Port => $port);

		if ($login ne "") {
			$telnet->waitfor('/(ogin|name|word):.*$/');
			$telnet->print("$login");
		}
		if ($password ne "") {
			$telnet->waitfor('/word:.*$/');
			$telnet->print("$password");
		}

		$telnet->waitfor(Match => '/.*[\$%>] {0,1}$/',
		                 Match => '/^[^#]*[\$%#>] {0,1}$/');

		$telnet->telnetmode(0);
		$telnet->put(pack("C9",
		                  255,			# TELNET_IAC
		                  250,			# TELNET_SB
		                  31, 0, 200, 0, 0,	# TELOPT_NAWS
		                  255,			# TELNET_IAC
		                  240));		# TELNET_SE
		$telnet->telnetmode(1);

		my $telnetcmd = $command;
		$telnetcmd .= " | no-more" if ($ostypes{$FORM{router}} eq "junos");

		$telnet->print("$telnetcmd");
		$telnet->getline;		# read out command line
		while (1) {
			if ($#output >= 0) {
				$_ = shift (@output);
			} elsif (! $telnet->eof) {
				my ($prematch, $match) = $telnet->waitfor(
					Match => '/\n/',
					Match => '/[\$%#>] {0,1}$/',
					Errmode => "return")
				or do {
				};
				if ($match =~ /[\$%#>] {0,1}$/) {
					$telnet->print("quit");
					$telnet->close;
					last;
				}
				push @output, $prematch . $match;
				next;
			} else {
				last;
			}
			showline($_);
		}
	} else {
		print_error("Configuration error, no such scheme: $scheme\n");
	}
	print "</CODE></PRE>\n";
}

my $best = 0;
my $hidden = 0;
my $count = 0;
my $telnet;
my $lastip = "";
my $inemptyheader = 1;
my $linebuf = "";

sub showline {
	my $input = shift;
	$linebuf .= $input;

	if ($command =~ /^trace/i | $command =~ /^ping/i) {
		if ($command =~ /^trace/i) {
			$input =~ s/(\[AS\s+)(\d+)(\])/($1 . as2link($2) . $3)/e;
		}
		print $input;
		return;
	}

	if ($linebuf =~ /.+\n.+/) {
		my ($line1, $rest) = split(/\n/, $linebuf, 2);
		$linebuf = '';
		showline ($line1 . "\n");
		showline ($rest) if ($rest ne "");
		return;
	}
	$_ = $linebuf;
	return unless (/\n$/);
	$linebuf = '';
	chomp;

	next if (/Type escape sequence to abort./);
	next if (/Translating .*\.\.\.domain server/);
	next if (/Logical system: /);

	next if (($inemptyheader) && (/^$/));
	$inemptyheader = 0;

	$_ = html_encode($_);
	if ($command eq "show ip bgp summary") {
		s/( local AS number )(\d+)/($1 . as2link($2))/e;
		s/^([\d\.]+\s+\d+\s+)(\d+)/($1 . as2link($2))/e;
		s/^(\d+\.\d+\.\d+\.\d+)(\s+.*\s+)([1-9]\d*)$/($1 . $2 . bgplink($3, "neighbors+$1+routes"))/e;
		s/^(\d+\.\d+\.\d+\.\d+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
		# Zebra IPv6 neighbours
		s/^(.{15} 4\s+)(\d+)/($1 . as2link($2))/e;
		s/^([\dA-Fa-f]*:[\dA-Fa-f:]*)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
		s/^([\dA-Fa-f]*:[\dA-Fa-f:]*)$/bgplink($1, "neighbors+$1")/e;
	} elsif ($command eq "show bgp ipv6 summary") {
		s/^(.{15} 4\s+)(\d+)/($1 . as2link($2))/e;
		if (/^([\dA-Fa-f]*:[\dA-Fa-f:]*)\s+4\s+/) {
			$lastip = $1;
			s/^([\dA-Fa-f:]+)(\s+.*\s+)([1-9]\d*)$/($1 . $2 . bgplink($3, "neighbors+${lastip}+routes"))/e;
			s/^([\dA-Fa-f:]+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
			$lastip = "";
		}
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
		if ($securemode) {
			next if (/\.l[23]vpn/);		# don't show MPLS
			next if (/inet6?\.2/);		# don't show multicast
			next if (/\.inet6?\.0/);	# don't show VRFs
		}
		if (/^([\dA-Fa-f:][\d\.A-Fa-f:]+)\s+/) {
			$lastip = $1;
			# IPv4
			#s/^(\d+\.\d+\.\d+\.\d+)(\s+.*\s+)([1-9]\d*)(\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d:ywdh]+\s+)(\d+)\/(\d+)\/(\d+)(\s+)/($1 . $2 . bgplink($3, "neighbors+$1+routes") . $4 . bgplink($5, "neighbors+$1+routes") . "\/" . bgplink($6, "neighbors+$1+routes+all") . "\/" . bgplink($7, "neighbors+$1+routes+damping+suppressed") . $8)/e;
			s/^(\d+\.\d+\.\d+\.\d+)(\s+)([1-9]\d*)(\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d:ywdh]+\s+)(\d+)\/(\d+)\/(\d+)(\s+)/($1 . $2 . bgplink($3, "neighbors+$1+routes") . $4 . bgplink($5, "neighbors+$1+routes") . "\/" . bgplink($6, "neighbors+$1+routes+all") . "\/" . bgplink($7, "neighbors+$1+routes+damping+suppressed") . $8)/e;
			# IPv4/IPv6
			s/^([\dA-Fa-f:][\d\.A-Fa-f:]+\s+)(\d+)(\s+)/($1 . as2link($2) . $3)/e;
			s/^([\dA-Fa-f:][\d\.A-Fa-f:]+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
		}
		if (($lastip ne "") && (/(\s+inet6?\.0: )(\d+)\/(\d+)\/(\d+)$/)) {
			s/^(\s+inet6?\.0: )(\d+)\/(\d+)\/(\d+)$/($1 . bgplink($2, "neighbors+${lastip}+routes") . "\/" . bgplink($3, "neighbors+${lastip}+routes+all") . "\/" . bgplink($4, "neighbors+${lastip}+routes+damping+suppressed"))/e;
		}
	} elsif (($command =~ /^show ip bgp\s+n\w*\s+[\d\.]+\s+(ro|re|a)/i) ||
	         ($command =~ /^show bgp ipv6\s+n\w*\s+[\dA-Fa-f:]+\s+(ro|re|a)/i) ||
	         ($command =~ /^show ip bgp\s+re/i) ||
	         ($command =~ /^show bgp ipv6\s+re/i) ||
	         ($command =~ /^show ip bgp\s+[\d\.]+\s+[\d\.]+\s+(l|s)/i) ||
	         ($command =~ /^show (ip bgp|bgp ipv6) prefix-list/i) ||
	         ($command =~ /^show (ip bgp|bgp ipv6) route-map/i)) {
		s/^([\*r ](&gt;|d|h| ).{59})([\d\s,\{\}]+)([ie\?])$/($1 . as2link($3, $regexp) . $4)/e;
		s/^([\*r ](&gt;|d|h| )[i ])([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($3, $3) . $4)/e;
		s/^([\*r ](&gt;|d|h| )[i ])([\d\.A-Fa-f:\/]+)$/($1 . bgplink($3, $3))/e;
		s/^(( ){20}.{41})([\d\s,\{\}]+)([ie\?])$/($1 . as2link($3, $regexp) . $4)/e;
		s/(, remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
	} elsif ($command =~ /^show route (?:advertising|receive)-protocol bgp [\d\.A-Fa-f:]+ [\d\.A-Fa-f:\/]+ /i) {
		s/^([ \*] )([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($2, $2) . $3)/e;
		s/^(     AS path: )([\d\s,\{\}\[\]]+)( [IE\?] \((?:LocalAgg)?\))$/($1 . as2link($2) . $3)/e;
		s/^(     Communities: )([\d: ]+)/($1 . community2link($2))/e;
	} elsif ($command =~ /^show route ((advertising|receive)-protocol) bgp\s+([\d\.A-Fa-f:]+)/i) {
		my $type = $1;
		my $ip = $3;
		s/^([\* ] [\d\.\s].{62})([\d\s,\{\}\[\]]+)([IE\?])$/($1 . as2link($2) . $3)/e;
		s/^([\* ] [\d\.\s].{22}\s)([\d\.A-Fa-f:]+)(\s+)/($1 . bgplink($2, "neighbors+$2") . $3)/e;
		s/^([\dA-Fa-f:\/]+)(\s+)/(bgplink($1, "$1+exact") . $2)/e;
		s/^([\d\.\/]+)(\s+)/(bgplink($1, "$1+exact") . $2)/e;
		s/^([\dA-Fa-f:\/]+)(\s*)$/(bgplink($1, "$1+exact") . $2)/e;
		s/^([\d\.\/]+)\s*$/(bgplink($1, "$1+exact"))/e;
		s/^([ \*] )([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($2, "neighbors+$ip+" . (($type eq "advertising-protocol")?"advertised-routes":"receive-protocol") . "+$2") . $3)/e;
	} elsif (($command =~ /^show ip bgp n\w*\s+([\d\.]+)/i) ||
	         ($command =~ /^show ip bgp n\w*$/i)) {
		$lastip = $1 if ($1 ne "");
		$lastip = $1 if (/^BGP neighbor is ([\d\.]+),/);
		if ($securemode) {
			s/((Local|Foreign) port: )\d+/${1}???/g;
		}
		s/(Prefix )(advertised)( [1-9]\d*)/($1 . bgplink($2, "neighbors+$lastip+advertised-routes") . $3)/e;
		s/(    Prefixes Total:                 )(\d+)( )/($1 . bgplink($2, "neighbors+$lastip+advertised-routes") . $3)/e;
		s/(prefixes )(received)( [1-9]\d*)/($1 . bgplink($2, "neighbors+$lastip+routes") . $3)/e;
		s/^(    Prefixes Current: \s+)(\d+)(\s+)(\d+)/($1 . bgplink($2, "neighbors+$lastip+advertised-routes") . $3 .  bgplink($4, "neighbors+$lastip+routes"))/e;
		s/(\s+)(Received)( prefixes:\s+[1-9]\d*)/($1 . bgplink($2, "neighbors+$lastip+routes") . $3)/e;
		s/^(    Saved \(soft-reconfig\):\s+)(\d+|n\/a)(\s+)(\d+)/($1 . $2 . $3 .  bgplink($4, "neighbors+$lastip+received-routes"))/e;
		s/( [1-9]\d* )(accepted)( prefixes)/($1 . bgplink($2, "neighbors+$lastip+routes") . $3)/e;
		s/^(  [1-9]\d* )(accepted|denied but saved)( prefixes consume \d+ bytes)/($1 . bgplink($2, "neighbors+$lastip+received-routes") . $3)/e;
		s/^(BGP neighbor is )(\d+\.\d+\.\d+\.\d+)(,)/($1 . pinglink($2) . $3)/e;
		s/^( Description: )(.*)$/$1<B>$2<\/B>/;
		s/(,\s+remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		s/(, local AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		s/( update prefix filter list is )(\S+)/($1 . bgplink($2, "prefix-list+$2"))/e;
		s/(Route map for \S+ advertisements is\s+)(\S+)/($1 . bgplink($2, "route-map+$2"))/e;
	} elsif ($command =~ /^show bgp ipv6 n\w*\s+([\dA-Fa-f:]+)/i) {
		my $ip = $1;
		if ($securemode) {
			s/((Local|Foreign) port: )\d+/${1}???/g;
		}
		s/(Prefix )(advertised)( [1-9]\d*)/($1 . bgplink($2, "neighbors+$ip+advertised-routes") . $3)/e;
		s/^(  [1-9]\d* )(accepted)( prefixes)/($1 . bgplink($2, "neighbors+$ip+routes") . $3)/e;
		s/^( Description: )(.*)$/$1<B>$2<\/B>/;
		s/(\s+remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		s/(\s+local AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		s/( update prefix filter list is )(\S+)/($1 . bgplink($2, "prefix-list+$2"))/e;
		s/(Route map for \S+ advertisements is\s+)(\S+)/($1 . bgplink($2, "route-map+$2"))/e;
	} elsif ($command =~ /^show bgp n\w*\s+([\d\.A-Fa-f:]+)/i) {
		my $ip = $1;
		if ($securemode) {
			if ($hidden) {
				$hidden = 0 unless (/^    /);
				next if ($hidden);
			}
			s/^(Peer:\s+[\d\.A-Fa-f:]+\+)\d+(\s+AS\s+\d+\s+Local:\s+[\d\.A-Fa-f:]+\+)\d+(\s+AS\s+\d+)/${1}???${2}???${3}/g;
			if (/^  Table (.*\.l[23]vpn|inet6?\.2|\S+\.inet6?\.0)/) {
				s/^(  Table) \S+/$1 (hidden)/g;
				$hidden = 1;
			}
		}
		s/(\s+AS )(\d+)/($1 . as2link($2))/eg;
		s/(\s+AS: )(\d+)/($1 . as2link($2))/eg;
		s/^(    Active prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes"))/e;
		s/^(    Received prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes+all"))/e;
		s/^(    Suppressed due to damping:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+routes+damping+suppressed"))/e;
		s/^(    Advertised prefixes:\s+)(\d+)/($1 . bgplink($2, "neighbors+$ip+advertised-routes"))/e;
		s/^(  )(Export)(: )/($1 . bgplink($2, "neighbors+$ip+advertised-routes") . $3)/e;
		s/^(  )(Import)(: )/($1 . bgplink($2, "neighbors+$ip+routes+all") . $3)/e;
		# JUNOS bugfix
		s/([^ ])( )(Import)(: )/($1 . "\n " . $2 . bgplink($3, "neighbors+$ip+routes+all") . $4)/e;
	} elsif ($command =~ /^show route protocol bgp .* terse/i) {
		s/^(.{20} B .{25} (?:&gt;| ).{15}[^ ]*)( [\d\s,\{\}]+)(.*)$/($1 . as2link($2, $regexp) . $3)/e;
		s/^([\* ] )([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($2, "$2+exact") . $3)/e;
	} elsif (($command =~ /^show route protocol bgp /i) ||
		 ($command =~ /^show route aspath-regex /i)) {
		if ($securemode) {
			s/(Task: BGP_[\d\.A-Fa-f:]+\+)\d+/${1}???/g;
		}
		if (/^        (.)BGP    /) {
			if ($1 eq "*") {
				$best = "\#FF0000";
			} else {
				$best = "";
			}
		} elsif (/^[\d\.A-Fa-f:\/\s]{19}([\*\+\- ])\[BGP\//) {
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
		s/( from )([0-9A-Fa-f][0-9\.A-Fa-f:]+)/($1 . bgplink($2, "neighbors+$2"))/e;
		s/(                Source: )([0-9\.A-Fa-f:]+)/($1 . bgplink($2, "neighbors+$2"))/e;
		s/(\s+AS: )([\d ]+)/($1 . as2link($2))/eg;
		s/(Community: )([\d: ]+)/($1 . community2link($2))/e;
		s/(Communities: )([\d: ]+)/($1 . community2link($2))/e;
		s/(^\s+AS path: )(Merged\[3\]: )?([\d ]+)/($1 . $2 . as2link($3))/e;
		s/^([\dA-Fa-f:]+[\d\.A-Fa-f:\/]+)(\s*)/("<B>" . bgplink($1, "$1+exact") . "<\/B>$2")/e;
		$_ = "<FONT COLOR=\"${best}\">$_</FONT>" if ($best ne "");
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
		s/( from )([0-9A-Fa-f][0-9\.A-Fa-f:]+)( )/($1 . bgplink($2, "neighbors+$2") . $3)/e;
		s/(Community: )([\d: ]+)/($1 . community2link($2))/e;
		s/(Communities: )([\d: ]+)/($1 . community2link($2))/e;
		s/(^\s+AS path: )([\d ]+)/($1 . as2link($2))/e;
		if ($command =~ /-protocol/) {
			s/^([ \*] )([\d\.A-Fa-f:\/]+)(\s+)/($1 . bgplink($2, "$2+exact") . $3)/e;
		}
	}
	print "$_\n";
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
	my ($line, $regexp) = @_;

	my $prefix;
	my $suffix;
	if ($line =~ /^([^\d]*)((\d)|(\d[\d\s\[\]\{\}]*\d))([^\d]*)$/) {
		$prefix = $1;
		$line = $4;
		$suffix = $5;
	}
	return($prefix . $line . $suffix) if ($line =~ /^\s*$/);
	if ($line =~ /:/) {
		return($prefix . $line . $suffix);
	}
	my @aslist = split(/[^\d]+/, $line);
	my @separators = split(/[\d]+/, $line);
	my @regexplist = split(/[_^$ ]+/, $regexp);
	$line = "";
	for (my $i = 0; $i <= $#aslist; $i++) {
		my $as = $aslist[$i];
		my $sep = "";
		$sep = $separators[$i + 1] if ($i <= $#separators);
		my $astxt = $as;
		for (my $j = 0; $j <= $#regexplist; $j++) {
			if ($regexplist[$j] eq $as) {
				$astxt = "<EM>$as</EM>";
				last;
			}
		}
		my $rep;
		if (! defined $AS{$as}) {
			$rep = $astxt;
		} else {
			my $link = "";
			if ($AS{$as} =~ /(\w+):/) {
				if (defined $whois{$1}) {
					$link = sprintf(" HREF=\"$whois{$1}\" TARGET=_lookup", $as);
				} elsif (defined $whois{default}) {
					$link = sprintf(" HREF=\"$whois{default}\" TARGET=_lookup", $as);
				}
			}
			my $descr = $AS{$as};
			$descr = "$2 ($1)" if ($descr =~ /^([^:]+):(.*)$/);
			$rep = "<A title=\"" . html_encode($descr) . "\"${link}>$astxt</A>";
		}
		$line .= $rep . $sep;
	}
	$suffix =~ s/(aggregated by )(\d+)( )/($1 . as2link($2) . $3)/e;
	return($prefix . $line . $suffix);
}

sub community2link {
	my ($line) = @_;

	my $prefix;
	my $suffix;
	my @communitylist = split(/[^\d:]+/, $line);
	my @separators = split(/[\d:]+/, $line);
	$line = "";
	for (my $i = 0; $i <= $#communitylist; $i++) {
		my $community = $communitylist[$i];
		my $sep = "";
		$sep = $separators[$i + 1] if ($i <= $#separators);
		my $rep;
		if (! defined $AS{$community}) {
			$rep = $community;
		} else {
			my $link = "";
			my $descr = $AS{$community};
			my $asnum = $1 if ($community =~ /^(\d+):/);
			if (defined $AS{$asnum . ":URL"}) {
				$rep = "<A HREF=\"" . $AS{$asnum . ":URL"} . "\" TARGET=_lookup>$community</A> (" . html_encode($descr) . ")";
			} else {
				$rep = html_encode("$community ($descr)");
			}
		}
		$line .= $rep . $sep;
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
	$link .= "&amp;protocol=" . $FORM{protocol};
	$link .= "&amp;addr=$cmd";
	$link .= "&amp;router=$router";
	$link =~ s/ /+/g;
	return("<A HREF=\"$link\">$txt</A>");
}

sub pinglink {
	my ($ip) = @_;

	my $link = $lgurl;
	my $router = $FORM{router};

	$router =~ s/\+/%2B/;
	$router =~ s/=/%3D/;
	$router =~ s/\&/%26/g;

	$link .= "?query=ping";
	$link .= "&amp;protocol=" . $FORM{protocol};
	$link .= "&amp;addr=$ip";
	$link .= "&amp;router=$router";
	$link =~ s/ /+/g;
	return("<A HREF=\"$link\"><B>$ip</B></A>");
}

sub html_encode {
	($_) = @_;
	s|[\r\n]||g;
	s|&|&amp;|g;
	s|<|&lt;|g;
	s|>|&gt;|g;
	return $_;
}
