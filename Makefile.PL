use ExtUtils::MakeMaker;

for my $req_exe (qw(b58 b58-dec)) {
    system("which $req_exe >/dev/null 2>&1") 
        and die "required program missing: $req_exe";
}

WriteMakefile(
  ABSTRACT => "Bitcoin private / public keypairs, and addresses",
  VERSION  => "0.1",
  AUTHOR   => 'Tom Jones <tom@oxix.org>',
  DISTNAME => 'Bitcoin',
  LICENSE  => 'MIT',
  NAME     => 'Bitcoin',
);
