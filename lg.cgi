#!/usr/bin/perl
#
#    Looking Glass CGI with telnet, rexec and remote LG support
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

use strict;

use Socket;
use IO::Handle;

use XML::Parser;

my $SYS_progid = '$Id: lg.cgi,v 1.5 2002/06/25 14:38:19 cougar Exp $';

my $lgurl;
my $logfile;
my $asfile;
my $logoimage;
my $title;
my $email;
my $rshcmd;

my %router_list;
my @routers;
my %namemap;
my %cmdmap;

my $default_router;

my $xml_current_router_name = "";
my $xml_current_cgi_name = "";
my $xml_current_replace_name = "";

my %valid_ipv4_query = (
	"bgp"			=>	"show ip bgp %s",
	"advertised-routes"	=>	"show ip bgp neighbors %s advertised-routes",
	"summary"		=>	"show ip bgp summary",
	"ping"			=>	"ping %s",
	"trace"			=>	"traceroute %s"
);

my %valid_ipv6_query = (
	"bgp"			=>	"show bgp ipv6 %s",
	"advertised-routes"	=>	"show bgp ipv6 neighbors %s advertised-routes",
	"summary"		=>	"show bgp ipv6 summary",
	"ping"			=>	"ping ipv6 %s",
	"trace"			=>	"traceroute ipv6 %s"
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

if ((! defined $valid_ipv4_query{$FORM{query}}) ||
    (! defined $router_list{$FORM{router}})) {
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
		print LOG " \"$FORM{router}\" \"$FORM{query} $FORM{addr}\"\n";
		close LOG;
	}
	if ($router_list{$FORM{router}} =~ /\?/) {
		$incoming = "&$incoming";
	} else {
		$incoming = "?$incoming";
	}
	my $remote = $router_list{$FORM{router}};
	if (defined $cmdmap{$remote}) {
		$incoming .= "&";
		my $mapref = $cmdmap{$remote};
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

my $command = sprintf((($FORM{protocol} eq "IPv6") ? $valid_ipv6_query{$FORM{query}} : $valid_ipv4_query{$FORM{query}}), $FORM{addr});
print LOG " \"$FORM{router}\" \"$command\"\n";
close LOG;

&print_head($command);

if ($FORM{addr} !~ /^[\w\.\^\$\-\:\/ ]*$/) {
	&print_error("Illegal characters in parameter string");
}

$FORM{addr} = "" if ($FORM{addr} =~ /^[ ]*$/);

if ($valid_ipv4_query{$FORM{query}} =~ /%s/) {
	&print_error("Parameter missing") if ($FORM{addr} eq "");
} else {
	&print_warning("No parameter needed") if ($FORM{addr} ne "");
}

my %AS = &read_as_list("AS", $asfile);

&print_results($router_list{$FORM{router}}, $command);

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
			$cmdmap{$xml_current_cgi_name}{$xml_current_replace_name} .= $str;
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
	} elsif ($elem eq "contactmail") {
		$email = $str;
	} elsif ($elem eq "rshcmd") {
		$rshcmd = $str;
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
		if (($str2 ne "lgurl") &&
		    ($str2 ne "logfile") &&
		    ($str2 ne "aslist") &&
		    ($str2 ne "logoimage") &&
		    ($str2 ne "htmltitle") &&
		    ($str2 ne "contactmail") &&
		    ($str2 ne "rshcmd") &&
		    ($str2 ne "router_list") &&
		    ($str2 ne "argument_list")) {
			die("Illegal configuration tag \"$str\" at line " . $xp->current_line . ", column " . $xp->current_column);
		}
	} elsif ($elem eq "router_list") {
		if ($str2 eq "router") {
			for (my $i = 0; $i <= $#attrval; $i += 2) {
				if (lc($attrval[$i]) eq "name") {
					$xml_current_router_name = $attrval[$i+1];
				} elsif (lc($attrval[$i]) eq "default") {
					if (lc($attrval[$i+1]) eq "yes") {
						$default_router = $xml_current_router_name;
					}
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
					$cmdmap{$xml_current_cgi_name}{$xml_current_replace_name} = "";
				}
			}
			if ($xml_current_replace_name eq "") {
				die("Variable \"Param\" missing at line " . $xp->current_line . ", column " . $xp->current_column);
			}
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
		}
	}
}

sub print_head {
	my ($arg) = @_;
	print "Content-type: text/html\n\n";
	print "<!--\n\t$SYS_progid\n-->\n";
	print "<Html>\n";
	print "<Head>\n";
	if ($arg ne "") {
		print "<Title>$title - $arg</Title>\n";
	} else {
		print "<Title>$title</Title>\n";
	}
	print "</Head>\n";
	print "<Body bgcolor=\"#FFFFFF\" text=\"#000000\">\n";
	print "<Img Src=\"$logoimage\">\n" if ($logoimage ne "");
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
<Form Method="POST">
<center>
<table border=0 bgcolor="#EFEFEF"><tr><td>
<table border=0 cellpading=2 cellspacing=2>
<tr>
<th bgcolor="#000000" nowrap><font color="#FFFFFF">Type of Query</font></th>
<th bgcolor="#000000" nowrap><font color="#FFFFFF">Additional parameters</font></th>
<th bgcolor="#000000" nowrap><font color="#FFFFFF">Node</font></th></tr>
<tr><td>
<Input type="radio" name="query" value="bgp">&nbsp;bgp<br>
<Input type="radio" name="query" value="advertised-routes">&nbsp;bgp&nbsp;advertised-routes<br>
<Input type="radio" name="query" value="summary">&nbsp;bgp&nbsp;summary<br>
<Input type="radio" name="query" value="ping">&nbsp;ping<br>
<Input type="radio" name="query" value="trace" SELECTED>&nbsp;trace<br>
<Select Name="protocol">
<Option Value = \"IPv4\"> IPv4
<Option Value = \"IPv6\"> IPv6
</Select>
</td>
<td align=center>&nbsp;<br><Input Name="addr" size=30><br><font size=-1>&nbsp;<sup>&nbsp;</sup>&nbsp;</font></td>
<td>&nbsp;<br><Select Name="router">
EOT
	my $remotelg = 0;
#	foreach my $router (sort (keys %router_list)) {
	for (my $i = 0; $i <= $#routers; $i++) {
		my $router = $routers[$i];
		if ($router =~ /^---- .* ----$/) {
			print "<Option Value = \"\"> $router\n";
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
		print "<Option Value = \"$router\"$default> $descr\n";
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
	my ($host, $command) = @_;
	my $best = 0;
	my $count = 0;
	my $method = "";
	if ($host =~ /^([^:]+):(.*)$/) {
		$method = $1;
		$host = $2;
	}

	print "<B>Host:</B> $host\n";
	print "<BR>\n";
	print "<B>Command:</B> $command\n";
	print "<P><Pre>\n";
	if ($method eq "rsh") {
		open(P, "$rshcmd $host $command |");
	} elsif ($method =~ /^telnet(.*)/) {
		my ($tmp, $port, $login, $password) = split (/\//, $1);
		$port = 23 if ($port eq "");
		&connect_to(*P, $host, $port);
		$_ = P->getc;			# be sure we got some answer
		if ($login ne "") {
			print P "$login\r";
			$_ = <P>;
			if ($password ne "") {
				print P "$password\r";
				$_ = <P>;
			}
		}
		print P "terminal length 0\r";	# password
		$_ = <P>;
		print P "$command\r";
		$_ = <P>;
	} else {
		print_error("Configuration error, no such method: $method\n");
	}
	my $header = 1;
	my $linecache = "";
	while (! (P->eof)) {
		if ($method =~ /^telnet/) {
			my $last_char = P->getc;
			$linecache .= $last_char;
			if ($header && $linecache =~ /($command)/) {
				my $tmp = <P>;
				$linecache = "";
				$header = 0;
				next;
			}
			if ($header) {
				$linecache = "" if ($last_char eq "\n");
				next;
			}
			if ($linecache =~ /^[\w\-\.]+>/) {
				$linecache = "";
				print P "quit\r";
				last;
			}
			next unless ($last_char eq "\n");
			$_ = $linecache;
			$linecache = "";
		} else {
			$_ = <P>
		}

		s|[\r\n]||g;
		if ($command eq "show ip bgp summary") {
			s/( local AS number )(\d+)/($1 . as2link($2))/e;
			s/^([\d\.]+\s+\d+\s+)(\d+)/($1 . as2link($2))/e;
			s/^(\d+\.\d+\.\d+\.\d+)(\s+.*\s+)([1-9]\d*)$/($1 . $2 . bgplink($3, "neighbors+$1+routes"))/e;
			s/^(\d+\.\d+\.\d+\.\d+)(\s+)/(bgplink($1, "neighbors+$1") . $2)/e;
		} elsif ($command eq "show bgp ipv6 summary") {
			s/^(                4\s+)(\d+)/($1 . as2link($2))/e;
		} elsif ($command =~ /^show ip bgp n\w*\s+[\d\.]+ ro/i) {
			s/^(.{59})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/^([\* ][> ][i ])([\d\.\/]+)(\s+)/($1 . bgplink($2, $2) . $3)/e;
		} elsif ($command =~ /^show ip bgp n\w*\s+[\d\.]+ a/i) {
			s/^(.{59})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/^([\* ][> ][i ])([\d\.\/]+)(\s+)/($1 . bgplink($2, $2) . $3)/e;
		} elsif ($command =~ /^show ip bgp n\w*\s+([\d\.]+)/i) {
			my $ip = $1;
			s/(Prefix )(advertised)( \d+)/($1 . bgplink($2, "neighbors+$ip+advertised-routes") . $3)/e;
			s/(prefixes )(received)( \d+)/($1 . bgplink($2, "neighbors+$ip+routes") . $3)/e;
			s/^(  \d+ )(accepted)( prefixes consume \d+ bytes)/($1 . bgplink($2, "neighbors+$ip+routes") . $3)/e;
			s/^( Description: )(.*)$/$1<B>$2<\/B>/;
			s/(, remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		} elsif (($command =~ /^show ip bgp re/i) ||
		         ($command =~ /^show ip bgp n/i)) {
			s/^(.{59})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/(, remote AS )(\d+)(,)/($1 . as2link($2) . $3)/e;
		} elsif (($command =~ /^show bgp ipv6 re/i) ||
		         ($command =~ /^show bgp ipv6 n/i)) {
			s/^(.{61})([\d\s]+)([ie\?])$/($1 . as2link($2) . $3)/e;
			s/( AS )(\d+)(,)/($1 . as2link($2) . $3)/ge;
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
			s/( from )([0-9\.]+)( )/($1 . bgplink($2, "neighbors+$2") . $3)/e;
		} elsif ($command =~ /^trace/i) {
			s/(\[AS )(\d+)(\])/($1 . as2link($2) . $3)/e;
		}
		print "$_\n";
	}
	close(P);
	print "</Pre>\n";
}

######## The rest is borrowed from NCSA WebMonitor "mail" code 

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
	my ($ref, $fn) = @_;

	local *F;
	my %AS;

	open(F, $fn) || die "Can't read AS list from $fn: $!";
	while (<F>) {
		chop;
		next if (/^$/ || /^\s*#/);
		my ($asnum, $descr) = split /\t+/;
		$asnum =~ s/^[^\d]*(\d+)[^\d]*$/$1/;
		$AS{$asnum} = $descr;
	}
	close(F);
	return (%AS);
}

sub connect_to {
	my ($fd, $remote, $port) = @_;
	my $iaddr = inet_aton($remote)|| die "no host: $remote";
	my $paddr = sockaddr_in($port, $iaddr);
	my $proto = getprotobyname('tcp');
	socket($fd, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
	connect($fd, $paddr) || return -1;
	$fd->autoflush(1);
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
