| case_id          | domain   | attribute           | ref_disp   |   ref_exp_lo |   ref_exp_hi | ref_urgent   | choice      |   p_REVIEW |   choice_confidence |   noul |   score |
|:-----------------|:---------|:--------------------|:-----------|-------------:|-------------:|:-------------|:------------|-----------:|--------------------:|-------:|--------:|
| sca-conflict-01  | sca      | reachable           | REVIEW     |            0 |            1 | False        | STANDARD    |       0.28 |                0.43 |   0.14 |    1.39 |
| sca-conflict-02  | sca      | internet            | REVIEW     |            0 |            1 | False        | DEFER       |       0.17 |                0.45 |   0.54 |    1.85 |
| sca-conflict-03  | sca      | exploit             | REVIEW     |            0 |            1 | False        | STANDARD    |       0.26 |                0.65 |   0.17 |    1.31 |
| sca-conflict-04  | sca      | asset               | REVIEW     |            0 |            1 | False        | DEFER       |       0.38 |                0.47 |   0.51 |    1.76 |
| sca-conflict-05  | sca      | control             | REVIEW     |            0 |            1 | False        | DEFER       |       0.28 |                0.37 |   0.26 |    1.6  |
| sca-conflict-06  | sca      | reachable           | REVIEW     |            0 |            2 | False        | ACCELERATED |       0.02 |                0.81 |   0.67 |    2.6  |
| sca-conflict-07  | sca      | internet            | REVIEW     |            0 |            1 | False        | STANDARD    |       0.14 |                0.48 |   0.34 |    1.6  |
| sca-conflict-08  | sca      | exploit             | REVIEW     |            0 |            1 | False        | REVIEW      |       0.53 |                0.4  |   0.32 |    1.67 |
| sca-conflict-09  | sca      | asset               | REVIEW     |            0 |            1 | False        | REVIEW      |       0.52 |                0.4  |   0.43 |    2.56 |
| sca-conflict-10  | sca      | control             | REVIEW     |            0 |            1 | False        | DEFER       |       0.24 |                0.45 |   0.22 |    1.34 |
| sast-conflict-01 | sast     | attacker_controlled | REVIEW     |            0 |            2 | False        | ACCELERATED |       0.29 |                0.47 |   0.67 |    2.51 |
| sast-conflict-02 | sast     | reachable           | REVIEW     |            0 |            1 | False        | ACCELERATED |       0.21 |                0.28 |   0.47 |    2.86 |
| sast-conflict-03 | sast     | sanitization        | REVIEW     |            0 |            1 | False        | ACCELERATED |       0.34 |                0.19 |   0.35 |    2.04 |
| sast-conflict-04 | sast     | internet            | REVIEW     |            0 |            1 | False        | ACCELERATED |       0.06 |                0.61 |   0.58 |    2.42 |
| sast-conflict-05 | sast     | auth                | REVIEW     |            0 |            2 | False        | STANDARD    |       0.2  |                0.66 |   0.21 |    1.71 |
| sast-conflict-06 | sast     | attacker_controlled | REVIEW     |            0 |            1 | False        | DEFER       |       0.26 |                0.31 |   0.23 |    1.54 |
| sast-conflict-07 | sast     | reachable           | REVIEW     |            0 |            1 | False        | STANDARD    |       0.34 |                0.42 |   0.31 |    1.71 |
| sast-conflict-08 | sast     | sanitization        | REVIEW     |            1 |            3 |              | REVIEW      |       0.62 |                0.52 |   0.55 |    2.79 |
| sast-conflict-09 | sast     | internet            | REVIEW     |            2 |            3 |              | ACCELERATED |       0.05 |                0.63 |   0.75 |    2.42 |
| sast-conflict-10 | sast     | auth                | REVIEW     |            2 |            4 |              | EMERGENCY   |       0.14 |                0.47 |   0.8  |    3.78 |
