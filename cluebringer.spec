%define apacheconfdir %{_sysconfdir}/httpd/conf.d
# this path is hardcoded
%define cblibdir /usr/lib/policyd-2.0

Summary: Postfix Policy Daemon
Name: cluebringer
Version: 2.0.5
Release: 1
License: GPLv2
Group: System/Daemons
URL: http://www.policyd.org
Source0: http://downloads.sourceforge.net/policyd/%{name}-%{version}.tar.bz2

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildArch: noarch

Provides: cbpolicyd

Provides: policyd = %{version}
Obsoletes: policyd

Requires: perl(Net::Server), perl(Config::IniFiles), perl(Cache::FastMmap), httpd


%description
Policyd v2 (codenamed "cluebringer") is a multi-platform policy server
for popular MTAs. This policy daemon is designed mostly for large
scale mail hosting environments. The main goal is to implement as many
spam combating and email compliance features as possible while at the
same time maintaining the portability, stability and performance
required for mission critical email hosting of today. Most of the
ideas and methods implemented in Policyd v2 stem from Policyd v1
as well as the authors' long time involvement in large scale mail
hosting industry.


%prep
%setup -q

# hack to prevent rpmbuild from automatically detecting "requirements" that
# aren't actually external requirements.  See https://fedoraproject.org/wiki/Packaging/Perl#In_.25prep_.28preferred.29
cat << EOF > %{name}-req
#!/bin/sh
%{__perl_requires} $* | sed -e '/perl(cbp::/d'
EOF

%define __perl_requires %{_builddir}/%{name}-%{version}/%{name}-req
chmod +x %{__perl_requires}


%build
cd database
for db_type in mysql4 mysql pgsql sqlite; do
	./convert-tsql ${db_type} core.tsql > policyd.${db_type}.sql
	for file in `find . -name \*.tsql -and -not -name core.tsql`; do
		./convert-tsql ${db_type} ${file}
	done >> policyd.${db_type}.sql
	cd whitelists
		./parse-checkhelo-whitelist >> policyd.${db_type}.sql
		./parse-greylisting-whitelist >> policyd.${db_type}.sql
	cd ..
done


%install
rm -rf $RPM_BUILD_ROOT


# Cbpolicyd
mkdir -p $RPM_BUILD_ROOT%{cblibdir}
mkdir -p $RPM_BUILD_ROOT%{_sbindir}
mkdir -p $RPM_BUILD_ROOT%{_initrddir}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
cp -R cbp $RPM_BUILD_ROOT%{cblibdir}
install -m 755 cbpolicyd cbpadmin database/convert-tsql $RPM_BUILD_ROOT%{_sbindir}
install -m 644 cluebringer.conf $RPM_BUILD_ROOT%{_sysconfdir}/cluebringer.conf
install -m 755 contrib/initscripts/Fedora/cbpolicyd $RPM_BUILD_ROOT%{_initrddir}

# Webui
mkdir -p $RPM_BUILD_ROOT%{_datadir}/%{name}
mkdir -p $RPM_BUILD_ROOT%{apacheconfdir}
cp -R webui/* $RPM_BUILD_ROOT%{_datadir}/%{name}
install -m 644 contrib/httpd/cluebringer.conf $RPM_BUILD_ROOT%{apacheconfdir}/cluebringer.conf

# Docdir
mkdir -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/contrib
mkdir -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/database
install -m 644 AUTHORS INSTALL LICENSE TODO WISHLIST $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}
cp -R contrib $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/contrib/amavisd-new
install -m 644 database/*.sql $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/database


%post
/sbin/chkconfig --add cbpolicyd


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)

%{cblibdir}/

%{_sbindir}/cbpolicyd
%{_sbindir}/cbpadmin
%{_sbindir}/convert-tsql

%{_initrddir}/cbpolicyd

%attr(-,root,apache) %{_datadir}/%{name}/*.php
%attr(-,root,apache) %{_datadir}/%{name}/*.css
%attr(-,root,apache) %{_datadir}/%{name}/images
%attr(-,root,apache) %{_datadir}/%{name}/tooltips
%attr(-,root,apache) %{_datadir}/%{name}/includes/db.php
%attr(-,root,apache) %{_datadir}/%{name}/includes/footer.php
%attr(-,root,apache) %{_datadir}/%{name}/includes/header.php
%attr(-,root,apache) %{_datadir}/%{name}/includes/tooltipdata.php
%attr(-,root,apache) %{_datadir}/%{name}/includes/tooltips.php

%config(noreplace) %{_sysconfdir}/cluebringer.conf
%config(noreplace) %{apacheconfdir}/cluebringer.conf
%attr(-,root,apache) %config(noreplace) %{_datadir}/%{name}/includes/config.php


%doc %{_docdir}/%{name}-%{version}


%changelog
* Tue Nov 18 2008 Christopher St Pierre <stpierre@NebrWesleyan.edu> - 
- Initial build.

