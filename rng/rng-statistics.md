# RNG entropy statistics

Processed **7 profiles** and **56 test windows**. Entropy values are bits per raw bit.

![RNG entropy and lag-1 through lag-4 correlation distributions](https://raw.githubusercontent.com/cagscalclabs/lwip-ce/statistics-assets/rng/rng-distributions.png?run=41005543782-1)

> Smoothed distributions are descriptive rather than fitted normal curves. Every circle is an individual test window.

## Aggregate

| Scope | Profiles | Windows | Samples | Marginal H₉₉ | Worst ρ₁…₄ (heuristic) | Projected lag-screen failures | Markov H₉₉ | Dependency factor | Conservative H |
|---|---:|---:|---:|---:|---|---:|---:|---:|---:|
| All models | 7 | 56 | 1,835,008 | 0.473090 | ρ1=+0.1197, ρ2=+0.0144, ρ3=+0.0148, ρ4=+0.0089 | 0/8 | 0.405578 | 0.857296 | 0.405578 |

## Per model

| Scope | Profiles | Windows | Samples | Marginal H₉₉ | Worst ρ₁…₄ (heuristic) | Projected lag-screen failures | Markov H₉₉ | Dependency factor | Conservative H |
|---|---:|---:|---:|---:|---|---:|---:|---:|---:|
| AF1 | 1 | 8 | 262,144 | 0.851514 | ρ1=+0.0302, ρ2=+0.0144, ρ3=+0.0148, ρ4=+0.0089 | 0/8 | 0.814394 | 0.956407 | 0.814394 |
| TI-84 Plus CE / AA | 2 | 16 | 524,288 | 0.473090 | ρ1=+0.1197, ρ2=n/a, ρ3=n/a, ρ4=n/a | 0/0 | 0.405578 | 0.857296 | 0.405578 |
| TI-84 Plus CE / L | 2 | 16 | 524,288 | 0.702461 | ρ1=+0.0471, ρ2=n/a, ρ3=n/a, ρ4=n/a | 0/0 | 0.653686 | 0.930566 | 0.653686 |
| TI-84 Plus CE / M | 1 | 8 | 262,144 | 0.763463 | ρ1=-0.0107, ρ2=n/a, ρ3=n/a, ρ4=n/a | 0/0 | 0.752404 | 0.985514 | 0.752404 |
| TI-84 Plus CE / preA | 1 | 8 | 262,144 | 0.750474 | ρ1=+0.0246, ρ2=n/a, ρ3=n/a, ρ4=n/a | 0/0 | 0.726605 | 0.968195 | 0.726605 |

## Production health-test diagnostics

| Scope | Version 4 runs | Evaluated mask | Passed mask | RCT failures | APT failures/windows | Startup marginal failures | Lag 1/2/3/4 failures | Distribution failures/windows |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| All models | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |
| AF1 | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |
| TI-84 Plus CE / AA | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |
| TI-84 Plus CE / L | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |
| TI-84 Plus CE / M | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |
| TI-84 Plus CE / preA | 0 | n/a | n/a | 0 | 0/0 | 0 | 0/0/0/0 | 0/0 |

## Interpretation

- **Marginal H₉₉** is the lower 99% MCV estimate, conservatively taking the poorer of the pooled and worst-window results.
- **Worst ρ₁…₄** uses the stationary-binary correlation heuristic `1-qₖ/(2p₀p₁)`; these values diagnose periodicity and do not add entropy credit.
- **Projected lag-screen failures** compares each version 3-or-newer run's aggregate lag rates with the startup bounds; version 4 health diagnostics separately count exact non-overlapping 952-sample windows.
- **Conservative H** is the lower of the marginal and first-order Markov estimates.
- The aggregate headline is a worst-supported bound across the dataset, not an average calculator.

> ⚠️ The Markov result is a coarse first-order dependence bound, not a complete SP 800-90B non-IID entropy assessment; longer-range dependence can reduce actual min-entropy. Lag-2 through lag-4 results are diagnostics only and do not increase entropy credit.
