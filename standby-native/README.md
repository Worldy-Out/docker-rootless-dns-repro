This fixture uses a fresh hosted Ubuntu runner and a private pair of Linux network
namespaces. Its addresses have no interface or route to the Internet. It tests
the actual systemd service loop, service-cgroup broker authorization, and
kernel lease rules with synthetic authority. A separate rootless Docker
fixture verifies stopped attachment and synthetic SQL file integrity. No VPS,
production credentials, Remnawave identity or application data are included.
