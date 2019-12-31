Name:           bgpq4
Version:        0.0.4
Release:        0%{?dist}

Group:          System/Utilities
Summary:        Generate BGP filters based on routing database information
URL:            https://github.com/bgp/bgpq4
License:        BSD
Source0:        https://github.com/bgp/bgpq4
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
You are running BGP in your network and want to automate filter generation for your routers? Well, with BGPQ4 it's easy.

%prep
%setup -q

%global debug_package %{nil}

%build
./configure --prefix=$RPM_BUILD_ROOT%{_prefix} --mandir=%{_mandir}
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
make install

%files
%defattr(-,root,root,-)
/usr/bin/bgpq4
/usr/man/man8/bgpq4.8.gz
%doc COPYRIGHT CHANGES

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Tue Dec 31 2019 Job Snijders <job@ntt.net> 0.0.4
- Remove '-3' command line option, assume all devices are 32-bit ASN safe

* Mon Dec 30 2019 Job Snijders <job@ntt.net> 0.0.3
- Remove the '-2' command line option
- Significant code reformating
- Improve performance by using IRRd 4's A query when available

* Sat Dec 14 2019 Job Snijders <job@ntt.net> 0.0.2
- Add Mikrotik support
- Remove ASDDOT support

* Sat Dec 14 2019 Job Snijders <job@ntt.net> 0.0.1
- Fork from bgpq3

* Tue Nov 30 2018 Alexandre Snarskii <snar@snar.spb.ru> 0.1.35
- Version updated

* Fri Oct 14 2016 Alexandre Snarskii <snar@snar.spb.ru> 0.1.33
- Version updated

* Tue Jun 23 Alexandre Snarskii <snar@snar.spb.ru> 0.1.31
- Version updated

* Tue Mar 10 Alexandre Snarskii <snar@snar.spb.ru> 0.1.28
- Version updated

* Wed Oct 29 Alexandre Snarskii <snar@snar.spb.ru> 0.1.25
- Version updated

* Thu Jun 5 2014 Alexandre Snarskii <snar@snar.spb.ru> 0.1.21-0.snar
- Version updated

* Thu May 9 2013 Alexandre Snarskii <snar@snar.spb.ru> 0.1.19-0.snar
- Version updated

* Sun Feb 24 2013 Alexandre Snarskii <snar@snar.spb.ru> 0.1.18-3.snar
- License corrected

* Wed Feb 20 2013 Arnoud Vermeer <arnoud@tumblr.com> 0.1.18-2.tumblr
- Adding missing group info (arnoud@tumblr.com)

* Wed Feb 20 2013 Arnoud Vermeer <arnoud@tumblr.com> 0.1.18-1.tumblr
- new package built with tito
