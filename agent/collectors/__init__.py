# Oktopus — Collectors Package
# Import collectors only if they exist (to support minimal Android deployments)

try:
    from agent.collectors.linux_collector import LinuxCollector
except ImportError:
    pass

try:
    from agent.collectors.windows_collector import WindowsCollector
except ImportError:
    pass

try:
    from agent.collectors.network_collector import NetworkCollector
except ImportError:
    pass

try:
    from agent.collectors.system_collector import SystemCollector
except ImportError:
    pass

try:
    from agent.collectors.android_collector import (
        AndroidSystemCollector,
        AndroidNetworkCollector,
        AndroidLogCollector
    )
except ImportError:
    pass
