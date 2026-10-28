# System_Persistence_Scanner

## Indicator of Compromise (IoC) Ruleset for PersistenceScanner

- Purpose: An external, dynamically loaded JSON rule base, injected directly into analytical modules (systemd, cron) via a network request. It allows updating threat signatures without the need to recompile the Go source code.

- Detection Scope: 

## Acknowledgments & Sources (Pattern Authors): 
The database was generated and optimized based on public infosec community research and recognized open-source projects. Malicious behavior signatures draw directly from:

- MITRE ATT&CK® Framework – tactic categorization (T1053, T1574, T1059).

- GTFOBins (Emilio Pinna, Andrea Cardaci, and the community) – patterns for abusing native Unix/Linux binaries.

- PentestMonkey – original interactive shell vectors (Reverse Shell Cheatsheet).

- PayloadsAllTheThings (SwisskyRepo) – advanced defense evasion techniques and one-liners.
