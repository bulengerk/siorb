Name:           siorb
Version:        %{siorb_version}
Release:        1%{?dist}
Summary:        Offline-first semantic package orchestrator
License:        Apache-2.0
URL:            https://github.com/bulengerk/siorb
Source0:        siorb
Source1:        LICENSE

%description
Siorb resolves portable logical package intent into an auditable plan for
native package managers. It does not require a hosted Siorb service.

%prep

%build

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/siorb
install -D -m 0644 %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%license %{_licensedir}/%{name}/LICENSE
%{_bindir}/siorb
