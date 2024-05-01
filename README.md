# cert-watcher

**cert-watcher** is a certificate monitoring utility for watching TLS certificates. These checks get exposed as Prometheus metrics to be viewed on a dashboard, or *soft* alert cluster operators.

- **Certificate Monitoring**: `cert-watcher` continuously monitors TLS certificates. It likely checks various aspects of the certificates such as expiration dates, issuer information, and certificate chains to ensure they are valid and properly configured.

- **Exposing Metrics**: The results of these certificate checks are exposed as Prometheus metrics. This means that `cert-watcher` provides endpoints or interfaces that Prometheus can scrape to collect metrics about the certificates' status and health.

- **Dashboard Viewing**: The exposed Prometheus metrics can be visualized on a dashboard. This allows cluster operators or administrators to monitor the status of TLS certificates in real-time and identify any issues or anomalies.

- **Soft Alerting**: Additionally, the Prometheus metrics can be used for soft alerting. Soft alerts typically serve as early warnings or notifications about potential issues rather than immediate action alerts. Cluster operators can set up alerting rules based on these metrics to be notified if any certificates are approaching expiration or if there are other issues detected.

## Features

### Testing for Certificate Errors

cert-watcher supports the following types of certificate errors (and possible more):

- Expired certificates
- Wrong host
- Bad root certificates
- Revoked certificate
- Cipher suites not allowed
    * `dh480`
    * `dh512`
    * `null`
    * `rc4`

If cert-watcher finds any certificate errors, these are displayed on the Grafana dashboard.

#### Testing for minimal TLS Version is not supported as genkiroid doesn't support the same



See [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security) for more info.

### Permissions

The **cert-watcher** implementation boasts a remarkable feature: it can operate without requiring `root` access on Unix-like systems, `CAP_NET_RAW` capability, or Administrator privileges on Windows.

1. **Enhanced Security**: Operating without elevated privileges minimizes the potential security risks associated with privileged processes. By adhering to regular user permissions, `cert-watcher` reduces its attack surface and mitigates security vulnerabilities.

2. **Simplified Deployment**: The absence of the need for `root` or Administrator access simplifies deployment processes. System administrators can effortlessly install and configure `cert-watcher` without requiring superuser permissions, streamlining deployment procedures and reducing administrative overhead.

3. **Portability**: `cert-watcher`'s ability to run without specific capabilities on Unix-like systems and without Administrator privileges on Windows enhances its portability across diverse environments. This flexibility facilitates deployment on various systems and platforms without encountering permission-related barriers.

4. **Implementation Considerations**: Achieving this capability entails designing `cert-watcher` to utilize network and file system access in a manner that circumvents the need for elevated privileges. For example:
   - Network operations can be performed using standard networking APIs that don't necessitate raw socket access or other capabilities restricted to privileged processes.
   - File system operations can be confined to directories accessible by the user running `cert-watcher`, eliminating the necessity for root/Administrator access to sensitive system locations.

5. **Cross-Platform Compatibility**: Ensuring `cert-watcher` operates without elevated privileges on both Unix-like systems and Windows requires meticulous consideration of platform-specific differences in permissions and system APIs. Implementing platform-independent code or handling platform-specific permissions appropriately enables `cert-watcher` to maintain its functionality across different operating systems.

In summary, the ability of `cert-watcher` to function without requiring elevated privileges enhances its security, ease of deployment, portability, and compatibility across diverse systems, making it a more accessible and dependable tool for certificate monitoring in varied environments.


---

