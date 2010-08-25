Name:		sip-callback
Version:	0.2
Release:	1%{?dist}
Summary:	A simple callback aplication
Group:		Applications/Internet
License:	GPLv2+
URL:		http://github.com/lemenkov/callback
BuildArch:      noarch
# wget http://github.com/lemenkov/callback/tarball/0.2
Source0:	lemenkov-callback-%{version}-0-g6ff9f76.tar.gz
Patch0:		callback-path.diff
Requires:	python-sippy
Requires:	python-simplejson
Requires:	python-application
Requires(pre):  /usr/sbin/useradd
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
Requires(postun): /sbin/service
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)


%description
A simple SIP web-callback application


%prep
%setup -q -n lemenkov-callback-6ff9f76
%patch0 -p0 -b .path


%build


%install
rm -rf $RPM_BUILD_ROOT
install -D -p -m 0644 config.ini $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/config.ini
install -D -p -m 0755 callback.py  $RPM_BUILD_ROOT%{_sbindir}/%{name}
install -D -p -m 0755 callback.init  $RPM_BUILD_ROOT%{_initrddir}/%{name}
install -d $RPM_BUILD_ROOT%{_localstatedir}/run/%{name}


%pre
getent group %{name} >/dev/null || groupadd -r %{name}
getent passwd %{name} >/dev/null || useradd -r -g %{name} -d / -s /sbin/nologin -c "SIP Callback daemon" %{name}
exit 0


%post
/sbin/chkconfig --add %{name}


%preun
if [ $1 = 0 ]; then
        /sbin/service %{name} stop >/dev/null 2>&1
        /sbin/chkconfig --del %{name}
fi


%postun
if [ "$1" -ge "1" ]; then
        /sbin/service %{name} condrestart >/dev/null 2>&1
fi


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/config.ini
%{_initrddir}/%{name}
%{_sbindir}/%{name}
%attr(755,%{name},%{name}) %{_localstatedir}/run/%{name}

%changelog
* Wed Aug 25 2010 Peter Lemenkov <lemenkov@gmail.com> - 0.2-1
- Initial package
