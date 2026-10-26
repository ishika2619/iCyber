# iCyber - Threat Intelligence Aggregator

**iCyber** is a Python + Streamlit tool that checks an IP address, domain, URL or file hash against **VirusTotal (API v3)** and **AlienVault OTX**, merges the results into one report, and assigns a transparent **Low / Medium / High / Unknown** risk rating. Built for the IBM Cybersecurity Bootcamp.

## Dataset
No external dataset is used. Live data comes from the official APIs:
- VirusTotal API v3: https://docs.virustotal.com/reference/overview
- AlienVault OTX API: https://otx.alienvault.com/api

`sample_data/samples.json` holds **mock** API-style responses so the demo works offline with zero API credits. They are not real findings.

## Features
- Validates IP / domain / URL / MD5-SHA1-SHA256 (also accepts defanged input like `hxxp://evil[.]com`)
- Combined report with malicious counts, reputation, pulses, tags, malware families
- Explainable risk rules, shown separately from the confirmed API findings
- Handles invalid input, 404s, rate limits (429 plus a local 4/min limiter), bad keys, timeouts
- CSV export of each report and of the session history
- API keys only from environment variables; **missing data is never treated as "safe"**

## Technologies
Python 3.9+, Requests, Streamlit, Pandas, python-dotenv, pytest.

## Project structure
```
icyber/
├── iCyber_iCyber.py   # single-file submission version
├── app.py                  # Streamlit dashboard (modular version)
├── src/
│   ├── config.py           # reads keys from environment
│   ├── validators.py       # input detection/validation
│   ├── clients.py          # VirusTotal + OTX clients, parsers, rate limiter
│   ├── risk.py             # rule-based scoring
│   ├── report.py           # combined report + CSV table
│   ├── demo.py             # offline demo mode
│   └── investigator.py     # ties it all together
├── sample_data/samples.json
├── tests/test_core.py
├── .env.example  .gitignore  requirements.txt  pytest.ini
```

## Setup and run
```bash
# 1. create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. install dependencies
pip install -r requirements.txt

# 3. (Live mode only) add your keys
cp .env.example .env              # Windows: copy .env.example .env
#    then edit .env and paste your VT_API_KEY and OTX_API_KEY

# 4. run the dashboard
streamlit run app.py
#    or the single-file version:
streamlit run iCyber_iCyber.py

# 5. run the tests (no network or credits needed)
python -m pytest -v
```
Start in **Demo (sample data)** mode in the sidebar: no keys are needed.

Free keys: sign up at virustotal.com (profile > API key) and otx.alienvault.com (Settings > API Integration).

## Risk rules
| Rule | Points |
|---|---|
| VirusTotal malicious engines >= 5 / 1-4 | +3 / +2 |
| VirusTotal suspicious engines >= 1 | +1 |
| VirusTotal reputation <= -10 | +1 |
| OTX pulses >= 5 / 1-4 | +2 / +1 |
| OTX pulses name malware families | +1 |

**High** >= 4, **Medium** 2-3, **Low** < 2 *only if VirusTotal analysis data exists*, otherwise **Unknown**. No data at all = **Unknown**, never "safe".

## Troubleshooting
| Problem | Fix |
|---|---|
| `streamlit: command not found` | Activate the venv, or use `python -m streamlit run app.py` |
| "VT_API_KEY is not set" | Create `.env` from `.env.example`, paste your key, restart Streamlit |
| "rejected the API key" | Key is wrong or has extra spaces/quotes; regenerate it |
| "rate limit" message | Public VT keys allow about 4 requests/min; wait a minute (results are cached 10 min) |
| "no record" (404) | The service has not seen that indicator. This is **not** proof it is safe |
| `ModuleNotFoundError: src` | Run commands from the project root folder |
| Demo says "Not in the demo sample set" | Pick a scenario from the sidebar or switch to Live mode |

## Security notes
Never commit `.env` (it is in `.gitignore`). If a key is ever exposed, revoke and regenerate it. Treat all API text (pulse names, tags) as untrusted; the dashboard shows it in tables, not as HTML.

## Limitations
Two sources only; OTX pulses are community-submitted and may include benign infrastructure; the scoring is a triage aid, not a verdict. Follow each provider's current terms and rate limits.
