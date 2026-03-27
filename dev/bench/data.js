window.BENCHMARK_DATA = {
  "lastUpdate": 1774636518625,
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
      }
    ]
  }
}