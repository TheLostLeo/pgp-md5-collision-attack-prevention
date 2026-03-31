# PGP Key Signing with Weak Hash (MD5) - Collision Forgery Demo

This project demonstrates how weak hash-based signing (MD5) can enable signature forgery in a PGP-like workflow, and how strong hash prevention methods block the attack.

## What this project shows

- **Attack model (vulnerable):** MD5 collision-based signature transplantation.
- **Prevention model (secure):** switch to strong hash algorithms.
- **Automated testing:** 25 test cases per run with measurable success/failure.
- **GUI demo:** Tkinter interface with logs, prevention selection, and graph viewer.
- **Graph outputs:** mandatory and additional comparative analysis PNG files.

## Prevention methods implemented

1. SHA-256
2. SHA3-256
3. SHA-512
4. BLAKE2B-256

## Project structure

- `src/core/`
  - `rsa_core.py` - RSA key generation, sign, verify
  - `md5_core.py` - custom MD5 implementation
- `src/attack/`
  - `experiment_engine.py` - test engine, metrics, prevention modes
  - `attack_simulation.py` - CLI summary flow
- `src/gui/`
  - `gui.py` - main Tkinter application (production GUI)
- `src/analysis/`
  - `graphs.py` - mandatory + additional graph generation
- `scripts/`
  - `run_gui.py` - launch GUI
  - `run_attack.py` - run CLI attack/prevention summary
  - `run_graphs.py` - generate graph package
- `outputs/graphs/`
  - generated PNG files

## Setup

### 1) Create and activate virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Linux Tkinter note

If GUI does not start with a Tk library error, install Tk runtime.

Arch Linux:

```bash
sudo pacman -S --needed tk
```

## Run

### GUI (recommended for final demo)

```bash
python scripts/run_gui.py
```

### CLI attack/prevention summary

```bash
python scripts/run_attack.py
```

### Generate graphs package

```bash
MPLBACKEND=Agg python scripts/run_graphs.py
```

## Demo flow (suggested)

1. Click **Generate Keys / Parameters**
2. Click **Run Attack (Collision)** in MD5 mode
3. Select prevention method and click **Apply Prevention**
4. Re-run attack and confirm forgery drops to 0%
5. Click **Show Graphs** to generate and open graph viewer

## Expected behavior

- MD5 mode: high forgery success (target >= 90%)
- Prevention modes: 0% forgery success
- Graphs: generated in `outputs/graphs/`

## Graph outputs

Mandatory:

- `mandatory_1_success_rate.png`
- `mandatory_2_time_vs_key_size.png`
- `mandatory_3_cia_rates.png`
- `mandatory_4_latency_overhead.png`
- `project_required_graphs.png` (combined mandatory dashboard)

Additional:

- `additional_1_method_success_trend.png`
- `additional_2_hash_latency_comparison.png`
- `additional_3_e2e_latency_comparison.png`
- `additional_4_improvement_vs_md5.png`

## Notes

- This is an **educational security simulation** for comparative analysis.
- The code intentionally demonstrates vulnerable behavior under MD5 mode for research/reporting purposes.
