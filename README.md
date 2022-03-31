check-springshell
=================

This tool will try to determine if the host it is
running on is likely vulnerable to
[CVE-2022-22963](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22963),
a [SpEL / Spring Expression Resource Access
Vulnerability](https://tanzu.vmware.com/security/cve-2022-22963),
as well as
[CVE-2022-22965](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965),
the so-called
"[SpringShell](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)"
RCE vulnerability.

This works very similar to the
[check-log4](https://github.com/yahoo/check-log4j)
tool, whereby it traverses the filesystem looking for
Java archives, cracks those open, and then looks for
known vulnerable jars or classes.

Please see the [manual
page](./doc/check-springshell.1.txt) for full
details.

Installation
============

To install the command and manual page somewhere
convenient, run `make install`; the Makefile defaults
to '/usr/local' but you can change the PREFIX:

```
$ make PREFIX=~ install
```

Documentation
=============

```
NAME
     check-springshell - try to determine if a host is vulnerable to the
     SpringShell vulnerabilities

SYNOPSIS
     check-springshell [-Vhv] [-j jar] [-p path] [-s skip]

DESCRIPTION
     The check-springshell tool attempts to determine whether the host it is
     executed on is vulnerable to the vulnerabilities grouped together under the
     "SpringShell" name.

     This includes CVE-2022-22963, a Spring SpEL / Expression Resource Access
     Vulnerability, as well as CVE-2022-22965, the spring-webmvc/spring-webflux
     RCE termed "SpringShell".

     check-springshell will look for nested Java archive files and so may be
     somewhat intrusive to run and should be executed with care and
     consideration of the system's load.  Please see DETAILS for more
     information.

OPTIONS
     The following options are supported by check-springshell:

     -V	      Print version number and exit.

     -h	      Print a short help message and exit.

     -j jar   Check only this archive, nothing else.  Can be specified multiple
	      times for multiple JAR (or other zip formatted archive) files.

     -p path  Limit filesystem traversal to this directory.  Can be specified
	      multiple times.  If not specified, check-springshell will default
	      to '/'.

     -s skip  Skip the given checks.  Valid arguments are 'files', 'packages',
	      and 'processes'.

     -v	      Be verbose.  Can be specified multiple times.

DETAILS
     CVE-2022-22963 describes a possible remote code execution (RCE)
     vulnerability in the popular Spring Boot framework.  Simply sending a POST
     request with a specific payload can cause the vulnerable server to execute
     commands on the attacker's behalf.

     Likewise, CVE-2022-22965 describes another possible RCE vulnerability,
     termed "SpringShell", which follows a common webshell upload pattern.

     To determine whether a host is vulnerable, the check-springshell tool will
     look for classes and java archives relating to the known vulnerable
     versions of the Spring framework.

     The discovery process may include running find(1), lsof(1), rpm(1), or
     yinst(1); please use the -s flag to skip any checks that might have a
     negative impact on your host.

     The output of the command attempts to be human readable and provide
     sufficient information to judge whether the host requires attention.

ENVIRONMENT
     The following environment variables influence the behavior of
     check-springshell:

     CHECK_SPRINGSHELL_FIND_OPTS_PRE
	     Additional options to pass to find(1) prior to the path name(s).

	     By default, check-springshell runs "find / -type f -name
	     '*.[ejw]ar'"; the contents of this variable are placed immediately
	     after the 'find' and before the path name(s).

     CHECK_SPRINGSHELL_FIND_OPTS_POST
	     Additional options to pass to find(1) immediately after the path
	     name(s).

EXAMPLES
     Sample invocation on a non-vulnerable host:

	   $ check-springshell
	   No obvious indicators of vulnerability found.
	   $

     Sample invocation only looking at processes

	   $ check-springshell -s files -s packages -v -v
	   => Running all checks...
	   ==> Skipping package check.
	   ==> Looking for jars...
	   ==> Skipping files check.
	   ==> Checking all found jars...
	   check-springshell 1.0 localhost: Possibly vulnerable jar 'BOOT-INF/lib/spring-beans-5.3.16.jar' (inside of /usr/local/myapp/myservice-0.0.1.jar) used by process 15569.

	   $

     Sample invocation searching only /var and /usr/local/lib and skipping
     package and process checks:

	   $ check-springshell -p /var -p /usr/local/lib -s packages -s processes
	   The following archives of likely vulnerable versions were found:
	   /var/./spring-beans-3.0.5.jar
	   /usr/local/lib/./log4shell-vulnerable-app-0.0.1-SNAPSHOT.jar:BOOT-INF/lib/spring-webmvc-5.3.13.jar
	   $

     Note version comparisons are only done for packages, which is why the above
     output incudes files ending in a seemingly non-vulnerable version.

     To avoid mountpoint traversal on a Unix system where find(1) requires the
     -x flag to precede the paths:

	   $ env CHECK_SPRINGSHELL_FIND_OPTS_PRE="-x" check-springshell
	   No obvious indicators of vulnerability found.

     To only search files newer than '/tmp/foo':

	   $ env CHECK_SPRINGSHELL_FIND_OPTS_POST="-newer /tmp/foo" check-springshell
	   No obvious indicators of vulnerability found.

EXIT STATUS
     check-springshell will return 0 if the host was found not to be vulnerable
     and not in need of any update; it will return 1 if a vulnerable jar or
     package was detected.

SEE ALSO
     find(1), lsof(1), rpm(1), yinst(1)

HISTORY
     check-springshell was originally written by Jan Schaumann
     <jschauma@netmeister.org> in March 2022.

BUGS
     Please file bugs and feature requests via GitHub pull requests and issues
     or by emailing the author.
```
