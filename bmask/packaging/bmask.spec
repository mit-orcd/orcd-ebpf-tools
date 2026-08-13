%{!?commit:%global commit 93b6919d60c2707ac95ec1dd14a164e7f4ed38c4}
%{!?shortcommit:%global shortcommit 93b6919}

# Preserve debuginfo, but do not generate an empty debugsource package.
%undefine _debugsource_packages

Name:           bmask
Version:        0.1.0
Release:        %{shortcommit}%{?dist}
Summary:        Enforce a chmod permission mask using eBPF LSM

License:        MIT
URL:            https://github.com/mit-orcd/orcd-ebpf-tools
# Generated locally by `make source`; the upstream URL is provenance only:
# https://github.com/mit-orcd/orcd-ebpf-tools/archive/%{commit}/orcd-ebpf-tools-%{commit}.tar.gz
Source0:        orcd-ebpf-tools-%{commit}.tar.gz
Source1:        bmask-vendor-%{commit}.tar.gz
Source2:        vmlinux.h
Source3:        bmask.service
Source4:        bmask.sysconfig
Source5:        SHA256SUMS

BuildRequires:  golang >= 1.25.9
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  libbpf-devel
BuildRequires:  systemd-rpm-macros

%{?systemd_requires}
ExclusiveArch:  x86_64

%description
bmask loads an eBPF Linux Security Module program attached to path_chmod. It
denies chmod operations whose resulting mode contains configured permission
bits for non-whitelisted users.

%prep
%autosetup -n orcd-ebpf-tools-%{commit}
tar -xzf %{SOURCE1} -C bmask
install -m 0644 %{SOURCE2} bmask/bpf/vmlinux.h

%build
cd bmask
export GOFLAGS="-mod=vendor"
export GOTOOLCHAIN=local
export CGO_ENABLED=0
go generate ./...
go build -trimpath -buildvcs=false -o bmask .

%install
install -Dpm 0755 bmask/bmask %{buildroot}%{_sbindir}/bmask
install -Dpm 0644 %{SOURCE3} %{buildroot}%{_unitdir}/bmask.service
install -Dpm 0644 %{SOURCE4} %{buildroot}%{_sysconfdir}/sysconfig/bmask

%check
cd bmask
export GOFLAGS="-mod=vendor"
export GOTOOLCHAIN=local
export CGO_ENABLED=0
go test ./...

%post
%systemd_post bmask.service
# echo message only on install (not upgrade)
if [ "$1" -eq 1 ]; then
  echo "bmask installed. Configure /etc/sysconfig/bmask and then run: systemctl enable --now bmask.service" >&2
fi

%preun
%systemd_preun bmask.service

%postun
%systemd_postun_with_restart bmask.service

%files
%license LICENSE
%doc bmask/README.md
%{_sbindir}/bmask
%{_unitdir}/bmask.service
%config(noreplace) %{_sysconfdir}/sysconfig/bmask

%changelog
* Thu Aug 06 2026 Luis Turino <turino14@mit.edu>
- Initial package
