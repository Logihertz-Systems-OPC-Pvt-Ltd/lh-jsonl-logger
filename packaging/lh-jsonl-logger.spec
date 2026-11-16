Name:           lh-jsonl-logger
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-logger - Tamper-Evident SHA-256 Cryptographic Hash Chaining Invariant
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jsonl-logger
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      noarch

%description
High-throughput PHP 8.2+ atomic flock NDJSON/JSONL telemetry logger with tamper-evident SHA-256 cryptographic hash chaining, recursive PII/secret redaction, CRLF sanitization, and CERT-In log posture auditor.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-logger ]; then
    install -m 0755 bin/lh-logger %{buildroot}%{_bindir}/lh-logger
elif [ -f lh-logger ]; then
    install -m 0755 lh-logger %{buildroot}%{_bindir}/lh-logger
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-jsonl-logger.
