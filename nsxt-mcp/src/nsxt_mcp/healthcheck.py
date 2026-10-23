"""Container liveness: TLS HTTP probe when configured, process liveness for stdio."""

import os
import ssl
import urllib.request


def main() -> None:
    url = os.environ.get("NSXT_HEALTH_URL")
    if not url:
        os.kill(1, 0)
        return
    context = ssl.create_default_context(cafile=os.environ.get("NSXT_HEALTH_CA"))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )
    with opener.open(url, timeout=3) as response:
        if response.status != 200:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
