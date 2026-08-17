window.BENCHMARK_DATA = {
  "lastUpdate": 1786952331188,
  "repoUrl": "https://github.com/StephenWakely/syslog-loose",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "fungus.humungus@gmail.com",
            "name": "Stephen Wakely",
            "username": "StephenWakely"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "72452dbf0c646b290717623856c7d25f385afb68",
          "message": "Add benchmark workflow (#49)",
          "timestamp": "2026-03-27T18:33:31Z",
          "tree_id": "9cfa8e1832ca38a2798c1d728e688ef35c81097a",
          "url": "https://github.com/StephenWakely/syslog-loose/commit/72452dbf0c646b290717623856c7d25f385afb68"
        },
        "date": 1774636518338,
        "tool": "cargo",
        "benches": [
          {
            "name": "RFC5424/with_structured_data/177",
            "value": 1644,
            "range": "± 26",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/with_structured_data_long_message/1893",
            "value": 947,
            "range": "± 17",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/with_structured_data_long_message/1960",
            "value": 1645,
            "range": "± 33",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/without_structured_data/110",
            "value": 947,
            "range": "± 23",
            "unit": "cycles/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "fungus.humungus@gmail.com",
            "name": "Stephen Wakely",
            "username": "StephenWakely"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4ed0d87a0ec2455c0679ce213e27f14a8f6b9970",
          "message": "Add benches for 3164 (#51)",
          "timestamp": "2026-03-27T20:44:32Z",
          "tree_id": "4483a851b3c13c191320b99caab318dac9be1951",
          "url": "https://github.com/StephenWakely/syslog-loose/commit/4ed0d87a0ec2455c0679ce213e27f14a8f6b9970"
        },
        "date": 1774644394049,
        "tool": "cargo",
        "benches": [
          {
            "name": "RFC5424/with_structured_data/177",
            "value": 1485,
            "range": "± 46",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/with_structured_data_long_message/1893",
            "value": 943,
            "range": "± 9",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/with_structured_data_long_message/1960",
            "value": 1479,
            "range": "± 9",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/without_structured_data/110",
            "value": 944,
            "range": "± 6",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC3164/simple/57",
            "value": 1437,
            "range": "± 12",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC3164/long_msg/201",
            "value": 1491,
            "range": "± 7",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC3164/with_structured_data/153",
            "value": 2494,
            "range": "± 24",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC3164/rfc3339_timestamp/170",
            "value": 2484,
            "range": "± 20",
            "unit": "cycles/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "fungus.humungus@gmail.com",
            "name": "Stephen Wakely",
            "username": "StephenWakely"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "da1fc19098189816ebaf545bd4d415c110f7a939",
          "message": "Ensure IPv6 addresses ending with :: are not treated as separators. (#53)",
          "timestamp": "2026-08-17T08:36:18+01:00",
          "tree_id": "72ab956c93e8d4db1c9ba638220745ebff83e149",
          "url": "https://github.com/StephenWakely/syslog-loose/commit/da1fc19098189816ebaf545bd4d415c110f7a939"
        },
        "date": 1786952330735,
        "tool": "cargo",
        "benches": [
          {
            "name": "RFC5424/with_structured_data/177",
            "value": 1382,
            "range": "± 23",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/with_structured_data_long_message/1893",
            "value": 807,
            "range": "± 16",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/with_structured_data_long_message/1960",
            "value": 1374,
            "range": "± 15",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC5424/without_structured_data/110",
            "value": 812,
            "range": "± 11",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC3164/simple/57",
            "value": 1353,
            "range": "± 20",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC3164/long_msg/201",
            "value": 1337,
            "range": "± 8",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC3164/with_structured_data/153",
            "value": 2203,
            "range": "± 196",
            "unit": "cycles/iter"
          },
          {
            "name": "RFC3164/rfc3339_timestamp/170",
            "value": 2124,
            "range": "± 23",
            "unit": "cycles/iter"
          }
        ]
      }
    ]
  }
}