Name:           %{name}
Version:        %{version}
Release:        %{release}
Summary:        s3cmd

License:        Michal Ludvig <michal@logix.cz>
URL:            http://s3tools.org
Source0:        %{name}-%{version}.tar.gz
BuildRoot:		%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)


%description
s3cmd

%prep
%setup -q

%build

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
cp -p s3cmd $RPM_BUILD_ROOT/usr/bin
cp -rp S3/ $RPM_BUILD_ROOT/usr/bin

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/usr/bin/s3cmd
/usr/bin/S3/*

%changelog
* Thu Jun 27 2013 Joris Conijn <sysops@woodwing.com> 1.5.0
Initial packaging