Name:           janus-agent
Version:        %{janus_version}
Release:        %{janus_release}%{?dist}
Summary:        Janus CryptoBOM endpoint agent
License:        Proprietary
BuildArch:      %{janus_arch}
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Janus Agent inventories cryptographic assets and reports them to a Janus
control plane. This package installs the passive, hardened systemd profile.

%prep

%build

%install
install -D -m 0755 %{janus_binary} %{buildroot}%{_bindir}/janus-agent
install -D -m 0640 %{janus_config} \
  %{buildroot}%{_sysconfdir}/janus-agent/janus-agent.toml
install -D -m 0644 %{janus_unit} \
  %{buildroot}%{_unitdir}/janus-agent.service
install -D -m 0644 %{janus_tmpfiles} \
  %{buildroot}%{_tmpfilesdir}/janus-agent.conf
install -d -m 0755 %{buildroot}%{_datadir}/janus-agent/systemd-profiles
install -m 0644 %{janus_profiles}/* \
  %{buildroot}%{_datadir}/janus-agent/systemd-profiles/

%pre
getent group janusagent >/dev/null 2>&1 || \
  groupadd --system janusagent >/dev/null 2>&1 || true
getent passwd janusagent >/dev/null 2>&1 || \
  useradd --system --gid janusagent --home-dir /var/lib/janus-agent \
    --no-create-home --shell /sbin/nologin janusagent >/dev/null 2>&1 || true

%post
install -d -m 0750 -o root -g janusagent /etc/janus-agent
chown root:janusagent /etc/janus-agent/janus-agent.toml
chmod 0640 /etc/janus-agent/janus-agent.toml
install -d -m 0700 -o janusagent -g janusagent /var/lib/janus-agent
systemd-tmpfiles --create janus-agent.conf >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl preset janus-agent.service >/dev/null 2>&1 || true

%preun
if [ "$1" -eq 0 ]; then
  systemctl disable --now janus-agent.service >/dev/null 2>&1 || true
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || true

%files
%{_bindir}/janus-agent
%dir %attr(0750,root,janusagent) %{_sysconfdir}/janus-agent
%config(noreplace) %attr(0640,root,janusagent) %{_sysconfdir}/janus-agent/janus-agent.toml
%{_unitdir}/janus-agent.service
%{_tmpfilesdir}/janus-agent.conf
%{_datadir}/janus-agent/systemd-profiles

%changelog
* Mon Jan 01 2024 Janus CryptoBOM Maintainers
- Native Linux package
