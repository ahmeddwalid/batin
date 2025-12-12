Name:           batin
Version:        0.2.0
Release:        1%{?dist}
Summary:        Security-hardened file type detection with entropy analysis

License:        GPLv3
URL:            https://github.com/ahmeddwalid/batin
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  rust-packaging
BuildRequires:  cargo
BuildRequires:  gcc

%description
Batin is a professional-grade file identification tool using magic bytes,
Shannon entropy, and advanced threat detection for cybersecurity applications.
It detects polyglot files, packed executables, and embedded threats.

%prep
%autosetup

%build
cargo build --release --all-features

%install
rm -rf $RPM_BUILD_ROOT
install -D -m 755 target/release/batin $RPM_BUILD_ROOT%{_bindir}/batin

%files
%license LICENSE
%doc README.md
%{_bindir}/batin

%changelog
* Sat Dec 06 2025 Ahmed Walid <devahmedwalid@proton.me> - 0.2.0-1
- Initial package release
