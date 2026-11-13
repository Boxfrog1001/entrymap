# Hacking on Entrymap

This document describes how to write analysis and active measurement modules for `entrymap`.

---

## Architecture Overview

`entrymap` iterates over Tor relays published in the network status consensus that match the user's filter criteria (typically `Guard` or `HSDir`). For each matching relay, it invokes the module's entry point.

Modules are placed in `src/modules/<module_name>.py`.

---

## Module Interface

A valid `entrymap` module must define an `analyze(relay, options)` function.

```python
"""
Module description for entrymap documentation.
"""

def analyze(relay, options):
    """
    Called for each relay matching the filter criteria.

    :param relay: Dictionary containing authoritative consensus metadata:
                  - 'fingerprint': 40-character hex fingerprint
                  - 'nickname': Relay nickname
                  - 'or_addresses': List of IPv4/IPv6 OR addresses with ports
                  - 'flags': List of consensus flags (e.g. ['Fast', 'Guard', 'Running'])
                  - 'as': Autonomous System number (e.g. 'AS24940')
                  - 'as_name': Autonomous System description
                  - 'alleged_family': Declared family list or None
                  - 'effective_family': Formed family list
                  - 'observed_bandwidth': Bytes per second
                  - 'advertised_bandwidth': Bytes per second
                  - 'contact': Operator contact string or None
                  - 'platform': Operating system and Tor version string
    :param options: Parsed command-line arguments (argparse Namespace)
    :return: None, or a dictionary/object if the relay triggered a detection.
    """
    pass
```

### Optional Lifecycle Hooks

- `init(options)`: Called once before the relay processing loop begins. Useful for initializing network caches, loading local MaxMind DBs, or starting threads.
- `finish(results, options)`: Called once after all relays have been processed. Receives the list of all return values from `analyze()`. Ideal for aggregating statistics, formatting markdown reports, or writing evidence files.

---

## Best Practices

1. **Passive First**: Prioritize metadata, descriptor, and routing table analysis over active network probing to preserve target operational security.
2. **Deterministic Output**: Output machine-readable JSON or cleanly formatted markdown.
3. **Respect Network Limits**: When performing active TCP handshakes (e.g. in `probe_timing_jitter.py`), enforce strict timeouts ($\le 3$ seconds) and limit concurrent threads.
