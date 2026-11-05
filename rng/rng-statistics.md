# RNG entropy statistics

Processed **4 profiles** and **32 test windows**. Entropy values are bits per raw bit.

![RNG entropy and lag-1 through lag-4 correlation distributions](https://raw.githubusercontent.com/cagscalclabs/lwip-ce/statistics-assets/rng/rng-distributions.png?run=41948304942-1)

> Smoothed distributions are descriptive rather than fitted normal curves. Every circle is an individual test window.

## Aggregate

| Scope | Profiles | Windows | Samples | Marginal H₉₉ | Worst ρ₁…₄ (heuristic) | Projected lag-screen failures | Markov H₉₉ | Dependency factor | Conservative H |
|---|---:|---:|---:|---:|---|---:|---:|---:|---:|
| All models | 4 | 32 | 1,048,576 | 0.541947 | ρ1=+0.1757, ρ2=+0.0479, ρ3=+0.0315, ρ4=+0.0315 | 0/32 | 0.520507 | 0.960439 | 0.520507 |

## Per model

| Scope | Profiles | Windows | Samples | Marginal H₉₉ | Worst ρ₁…₄ (heuristic) | Projected lag-screen failures | Markov H₉₉ | Dependency factor | Conservative H |
|---|---:|---:|---:|---:|---|---:|---:|---:|---:|
| TI-84 Plus CE / AA | 2 | 16 | 524,288 | 0.541947 | ρ1=+0.1757, ρ2=+0.0479, ρ3=+0.0315, ρ4=+0.0239 | 0/16 | 0.520507 | 0.960439 | 0.520507 |
| TI-84 Plus CE / M | 1 | 8 | 262,144 | 0.932816 | ρ1=+0.0221, ρ2=+0.0101, ρ3=+0.0089, ρ4=+0.0165 | 0/8 | 0.901891 | 0.966849 | 0.901891 |
| TI-84 Plus CE / PRE-A | 1 | 8 | 262,144 | 0.888241 | ρ1=+0.0302, ρ2=+0.0249, ρ3=+0.0227, ρ4=+0.0315 | 0/8 | 0.842106 | 0.948060 | 0.842106 |

## Production health-test diagnostics

| Scope | Version 4 runs | Evaluated mask | Passed mask | RCT failures | APT failures/windows | Startup marginal failures | Lag 1/2/3/4 failures | Distribution failures/windows |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| All models | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |
| TI-84 Plus CE / AA | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |
| TI-84 Plus CE / M | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |
| TI-84 Plus CE / PRE-A | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |

## Interpretation

- **Marginal H₉₉** is the lower 99% MCV estimate, conservatively taking the poorer of the pooled and worst-window results.
- **Worst ρ₁…₄** uses the stationary-binary correlation heuristic `1-qₖ/(2p₀p₁)`; these values diagnose periodicity and do not add entropy credit.
- **Projected lag-screen failures** compares each version 3-or-newer run's aggregate lag rates with the startup bounds; version 4 health diagnostics separately count exact non-overlapping 952-sample windows.
- **Conservative H** is the lower of the marginal and first-order Markov estimates.
- The aggregate headline is a worst-supported bound across the dataset, not an average calculator.

> ⚠️ The Markov result is a coarse first-order dependence bound, not a complete SP 800-90B non-IID entropy assessment; longer-range dependence can reduce actual min-entropy. Lag-2 through lag-4 results are diagnostics only and do not increase entropy credit.
