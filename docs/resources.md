# Resource consumption

## Live acceptance sample

Seven snapshots bracketed run `9007ca4b` between 18:07:53 and 18:08:44 UTC on 2026-11-25. One preceded the exercise, five were taken during it, and one followed it. The host had eight logical CPUs and 31 GiB RAM. Available RAM ranged from 6.4 to 6.6 GiB and swap in use ranged from 5.3 to 5.4 GiB. The project filesystem had 25 GiB available of 236 GiB. Host figures include concurrent non-SOC workloads.

| Component | Reported CPU range | Observed RAM range | Writable disk layer |
| --- | --- | --- | --- |
| Wazuh manager and Filebeat | 36.95–55.03% | 328.5–333.7 MB | 15.29 MiB |
| Indexer | 4.48–4.51% | 1.095–1.098 GB | 114 KiB |
| Dashboard | 1.03–1.04% | 148.9–150.7 MB | 387 KiB |
| Dedicated Debian guest | 4.6–4.7% | 369.7–370.3 MiB resident | 484 MiB guest overlay |

Podman reported image-backed root filesystems of 1.62, 1.37 and 1.34 GiB for the manager, indexer and dashboard. These can share layers. Fifteen project volumes occupied 519.5 MiB. The Debian backing image occupied a further 335 MiB. CPU figures are the values reported by Podman and the QEMU process lifetime average from `ps`. These discrete samples establish observed utilization during one exercise.

## Configured limits

| Component | Memory | CPU |
| --- | --- | --- |
| Rootless Wazuh manager and Filebeat | 1.5 GiB | 2 |
| Indexer | 3 GiB including 1 GiB Java heap | 2 |
| Dashboard | 1.5 GiB | 1.5 |
| Dedicated Debian guest | 1.5 GiB configured guest RAM | 2 virtual CPUs |

The central containers have a combined memory ceiling of 6 GiB. QEMU host overhead and filesystem cache vary separately. The guest disk uses a growable overlay with a 12 GiB virtual capacity. Concurrent CPU allocations can contend with other host workloads.

From the Fedora host, collect baseline and in-exercise samples with `scripts/measure.sh` after the services and the Linux guest are healthy. Record the workload, run ID and UTC timestamps. Raw samples are retained under the ignored `local-results/` directory.
