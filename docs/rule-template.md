# Detection template

```yaml
title: <short name>
id: <uuid>
status: experimental        # experimental | test | stable
description: <what it detects and why>
author: <name>
date: YYYY-MM-DD
logsource:
  product: <product>
  service: <service>
detection:
  selection: {}
  condition: selection
falsepositives:
  - <known benign cases>
level: medium               # low | medium | high | critical
references:
  - <url>
```
