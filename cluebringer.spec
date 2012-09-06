%global apacheconfdir %{_sysconfdir}/httpd/conf.d
# this path is hardcoded
%global cblibdir %{_libdir}/cbpolicyd-2.1
%global awitptlibdir %{_libdir}/cbpolicyd-2.1

Summary: Postfix Policy Daemon
Name: cluebringer
Version: @PKG_VER_MAIN@
Release: @PKG_VER_REL@
License: GPLv2
Group: System Environment/Daemons
URL: http://www.policyd.org
Source0: http://downloads.policyd.org/%{version}/%{name}-%{version}-%{release}.tar.xz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildArch: noarch

# Provide policyd
Provides: cbpolicyd = %{version}-%{release}
Provides: policyd = %{version}-%{release}
# Obsolete old policyd
Obsoletes: policyd < %{version}

Requires: perl(Cache::FastMmap)
Requires: perl(Config::IniFiles)
Requires: perl(Date::Parse)
Requires: perl(DBI)
Requires: perl(Net::CIDR)
Requires: perl(Net::DNS)
Requires: perl(Net::Server)

Requires: httpd
Requires: mysql-server

AutoReq: no
AutoProv: no


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
%setup -q -n @PKG_DIR_RPM@


%build
cd database
for db_type in mysql4 mysql pgsql sqlite; do
	./convert-tsql ${db_type} core.tsql > cbpolicyd.${db_type}.sql
	for file in `find . -name \*.tsql -and -not -name core.tsql`; do
		./convert-tsql ${db_type} ${file}
	done >> cbpolicyd.${db_type}.sql
	cd whitelists
		./parse-checkhelo-whitelist >> cbpolicyd.${db_type}.sql
		./parse-greylisting-whitelist >> cbpolicyd.${db_type}.sql
	cd ..
done


%install
rm -rf $RPM_BUILD_ROOT


# cbpolicyd
mkdir -p $RPM_BUILD_ROOT%{cblibdir}
mkdir -p $RPM_BUILD_ROOT%{awitptlibdir}
mkdir -p $RPM_BUILD_ROOT%{_sbindir}
mkdir -p $RPM_BUILD_ROOT%{_initrddir}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/cbpolicyd
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/run/cbpolicyd
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/cbpolicyd

cp -R cbp $RPM_BUILD_ROOT%{cblibdir}
cp -R awitpt/awitpt $RPM_BUILD_ROOT%{awitptlibdir}
install -m 755 cbpolicyd cbpadmin database/convert-tsql $RPM_BUILD_ROOT%{_sbindir}
install -m 644 cluebringer.conf $RPM_BUILD_ROOT%{_sysconfdir}/cbpolicyd/cluebringer.conf
install -m 644 contrib/cluebringer.logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/cluebringer
install -m 755 contrib/initscripts/Fedora/cbpolicyd $RPM_BUILD_ROOT%{_initrddir}
install -m 755 contrib/cluebringer.cron $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily/cluebringer


# Webui
mkdir -p $RPM_BUILD_ROOT%{_datadir}/%{name}/webui
mkdir -p $RPM_BUILD_ROOT%{apacheconfdir}
cp -R webui/* $RPM_BUILD_ROOT%{_datadir}/%{name}/webui/
install -m 644 contrib/httpd/cluebringer-httpd.conf $RPM_BUILD_ROOT%{apacheconfdir}/cluebringer.conf
# Move config into /etc
mv $RPM_BUILD_ROOT%{_datadir}/%{name}/webui/includes/config.php $RPM_BUILD_ROOT%{_sysconfdir}/cbpolicyd/webui.conf
ln -s %{_sysconfdir}/cbpolicyd/webui.conf $RPM_BUILD_ROOT%{_datadir}/%{name}/webui/includes/config.php
chmod 0640 $RPM_BUILD_ROOT%{_sysconfdir}/cbpolicyd/webui.conf

# Docdir
mkdir -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/database
install -m 644 AUTHORS INSTALL LICENSE TODO ChangeLog WISHLIST $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}
cp -R contrib $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/
cp -R database $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/


%pre
/usr/sbin/groupadd cbpolicyd 2>/dev/null || :
/usr/sbin/useradd -d / -s /sbin/nologin -c "PolicyD User" -g cbpolicyd cbpolicyd 2>/dev/null || :


%post
/sbin/chkconfig --add cbpolicyd

%preun
/sbin/service cbpolicyd stop
/sbin/chkconfig --del cbpolicyd


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc %{_docdir}/%{name}-%{version}
%{cblibdir}/
%{_sbindir}/cbpolicyd
%{_sbindir}/cbpadmin
%{_sbindir}/convert-tsql
%{_initrddir}/cbpolicyd
%dir %attr(0700,cbpolicyd,cbpolicyd) %{_localstatedir}/run/cbpolicyd
%dir %attr(0700,cbpolicyd,cbpolicyd) %{_localstatedir}/log/cbpolicyd

%dir %{_datadir}/%{name}
%attr(-,root,apache) %{_datadir}/%{name}/webui/

%dir %{_sysconfdir}/cbpolicyd
%config(noreplace) %{_sysconfdir}/logrotate.d/cluebringer
%config(noreplace) %{_sysconfdir}/cron.daily/cluebringer
%config(noreplace) %attr(0600,cbpolicyd,cbpolicyd) %{_sysconfdir}/cbpolicyd/cluebringer.conf
%config(noreplace) %attr(0640,cbpolicyd,apache) %{_sysconfdir}/cbpolicyd/webui.conf

%config(noreplace) %{apacheconfdir}/cluebringer.conf


%changelog
