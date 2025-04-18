# 🧩 Custom Rulesets for SockEm

SockEm lets you load external rulesets in JSON format to tailor detection for your environment.

These rules allow you to flag unexpected process/port pairs, memory usage anomalies, and known suspicious tools like `nc`, `telnet`, or `socat`.

**NB: Memory data is stored in kilobytes**

---

## 🔧 Ruleset Format

Rules must be in valid JSON and structured as an array of rule objects. Each rule object can include any of the following keys:

| Key                 | Type       | Description |
|---------------------|------------|-------------|
| `rule_id`           | Integer    | Unique rule identifier |
| `description`       | String     | Description for this rule (`{}` will be replaced by process info) |
| `severity`          | String     | One of `low`, `medium`, `high`, or `critical` |
| `match_all`         | List       | List of `port` + `valid_process` pairs |
| `blacklist_process` | List       | Process names that should never be active with a socket |
| `blacklist_port`    | List       | Ports that are suspicious regardless of process |
| `match_state`       | Dictionary | Conditions for runtime state matching (e.g., memory_kb > value) |

---

## 📚 Examples

### 🎯 Rule 1: Mismatched Process-Port Pair

```json
{
  "rule_id": 100001,
  "match_all": [
    {
      "port": 8288,
      "valid_process": ["ssh"]
    }
  ],
  "severity": "medium",
  "description": "Usually this is an SSH port, but that's not an ssh connection: {}"
}
```

### 🎯 Rule 2: Known-Executables
```json
{
        "rule_id":100002,
        "match_blacklist_process":[
            "nc",
            "socat"
        ],
        "severity":"CRITICAL",
        "description":"Potential Reverse-Bind Shell detected {}"
}
```

### 🎯 Rule 3: Known Suspicious Port
```json
{
        "rule_id":100003,
        "match_blacklist_port":[
            5555,
            4444
        ],
        "severity":"MEDIUM",
        "description":"A suspicious port is actively listening.. {}"
}
```


### 🎯 Rule 4: Anomalous process state
```json
{
        "rule_id":100004,
        "match_state":{
            "memory_kb":">5000000"

        },
        "severity":"HIGH",
        "description":"High memory consumption from process {}"
}
```


**IMPORTANT NOTE**: Make sure for each rule to have **unique rule_id**, only the first rule with a distinct rule_id will be executed.