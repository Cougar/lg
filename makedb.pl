#!/usr/bin/perl

use DB_File;

my $asfile = "as.txt";
my $communityfile = "communities.txt";
my $dbfile = "as.db";

my %GLOBALVAR;
my %LOCALVAR;
my %COMMUNITY;
my %ANYNUM = ("0=0" => "", "1=1" => "", "2=2" => "", "3=3" => "", "4=4" => "",
              "5=5" => "", "6=6" => "", "7=7" => "", "8=8" => "", "9=9" => "");

my %AS;

tie (%AS, 'DB_File', $dbfile, O_RDWR|O_CREAT, 0644, $DB_HASH) or
	die "Can\'t write AS database $dbfile: $!";

undef %AS;

print "Reading AS names..\n";
%AS = &read_as_list($asfile);
print " OK\n";

print "Reading community names..\n";
my %COMMUNITY = &read_community_list($communityfile);
foreach my $key (keys (%COMMUNITY)) {
	$AS{$key} = $COMMUNITY{$key};
}
print " OK\n";

print "Setting up database..\n";
untie %AS;
print " OK\n";

sub read_as_list {
	my ($fn) = @_;

	local *F;
	my %AS;

	if (! open(F, $fn)) {
		print "ERROR: Can't read AS list from $fn: $!\n";
		return;
	}
	print " Read AS list from $fn..\n";
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

sub read_community_list {
	my ($fn) = @_;

	local *F;

	if (! open(F, $fn)) {
		print "ERROR: Can't read community list from $fn: $!\n";
		return;
	}
	print " Read community list from $fn..\n";
	my $asnum = "";
	while (<F>) {
		chop;
		if (/^#include\s+(.+)$/) {
			my %COMMUNITY2 = &read_community_list($1);
			foreach my $key (keys (%COMMUNITY2)) {
				$COMMUNITY{$key} = $COMMUNITY2{$key};
			}
			undef %COMMUNITY2;
			next;
		}
		next if (/^$/ || /^\s*#/);
		s/#.*$//;

		if (/^AS(\d+)$/) {
			$asnum = $1;
			undef %LOCALVAR;
			next;
		}

		my ($community, $descr) = split /\t+/;
		
		if ($community =~ /^(\d+):/) {
			die "ERROR! AS $1 begin tag missing at line $." unless ($1 == $asnum);
		}

		if ($community =~ /^([A-Z]+=\d+)$/) {
			$GLOBALVAR{$community} = $descr;
			next;
		}
		if ($community =~ /^([a-z]+=\d+)$/) {
			$LOCALVAR{$community} = $descr;
			next;
		}
		if ($community =~ /^\d+:\d+$/) {
			$COMMUNITY{$community} = $descr;
			next;
		}
		if ($community =~ /^URL$/) {
			$COMMUNITY{$asnum . ":URL"} = $descr;
			next;
		}
		if ($community =~ /^(\d+):(\d*)([a-zA-Z\.].*)$/) {
			&complete_community($community, $descr, %LOCALVAR);
			next;
		}
		die "ERROR: Illegal community line $.: \"$_\"";
	}
	close(F);
	return (%COMMUNITY);
}

sub complete_community {
	my ($community, $descr) = @_;

	if ($community =~ /^\d+:\d+$/) {
		$COMMUNITY{$community} = $descr;
		return;
	}

	my @clist;
	if ($community =~ /^\d+:\d*([a-zA-Z\.]).*$/) {
		my $var1 = $1;
		$var1 .= "+" if ($var1 ne ".");
		$community =~ /^(\d+):(\d*)(($var1))(.*)$/;
		my $asnum = $1;
		my $commpref = $2;
		my $commvar = $3;
		my $commsuf = $5;

		my $varref;
		if ($commvar =~ /^[A-Z]+$/) {
			$varref = \%GLOBALVAR;
		} elsif ($commvar =~ /^[a-z]+$/) {
			$varref = \%LOCALVAR;
		} elsif ($commvar eq ".") {
			$varref = \%ANYNUM;
		} else {
			die "Illegal community variable \"$commvar\" in \"$community\"";
		}

		my $c = 0;
		foreach my $key (sort keys (%{$varref})) {
			if ($key !~ /^($commvar)=(.+)$/) {
				next;
			}
			my $repl = $2;
			my $newcomm = $asnum . ":" . $commpref . $repl . $commsuf;
			my $descr2 = ${$varref}{$key};
			$descr2 = $key if ($commvar eq ".");
			(my $newdescr = $descr) =~ s/(\$$commvar)/$descr2/g;
			&complete_community($newcomm, $newdescr);
			$c++;
		}
		if ($c == 0) {
			die "$community - no match for \"$commvar\"";
		}
		return;
	}
	die "complete_community() called without proper pattern";
}
