- Raise the Tooling Tests job limit from 35 to 45 minutes after successful
  merge-group runs reached 33.9 minutes and one run hit the limit. Pytest
  still limits each test to 300 seconds.
