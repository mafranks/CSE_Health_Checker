# README screenshots

The current app screenshots are rendered from the real Qt widgets using synthetic connector data from `tests/gui_fixtures.py` and public publisher certificate metadata. They illustrate controls, layouts, and result formats. Connectivity outcomes and recommendation results are mocked, and no live connector, credentials, or cloud account is used. Windows fonts and native window decorations may differ from the rendered previews.

| File | View |
| --- | --- |
| `Main_Page.png` | Dashboard in light mode, including the theme toggle |
| `Main_Page_Dark.png` | Dashboard in dark mode |
| `Isolation_Code.png` | Connector health with an illustrative isolation unlock code |
| `TETRA_Version.png` | Definitions and policy version cards |
| `Live_Debugging.png` | Live paths / processes, collection controls, and counters |
| `Live_Top_Processes.png` | Live process rankings |
| `Run_Analysis.png` | Analysis categories and export controls |
| `Manual_Analysis.png` | Independent log selection and manual analysis |
| `Connectivity.png` | Regional connectivity settings and per-host outcomes |
| `Certificate_Viewer.png` | A synthetic public certificate with fingerprints and validity tabs |
| `Trusted_Signers.png` | Publisher certificate identities with valid-date, historical, and unverified tabs |
| `Recommend_Exclusions.png` | Illustrative exclusion-set candidates and catalog freshness |
| `Check_Engines.png` | Read-only engine policy settings |
| `View_Exclusions.png` | Stored local policy exclusion entries |
| `View_Process_Exclusions.png` | Stored process exclusion entries |
| `View_Process_Exclusions_Dark.png` | The stored process exclusions view in dark mode |

From the repository directory with runtime requirements installed:

```shell
python tests/render_gui.py --output images --theme light
python tests/render_gui.py --output /tmp/cse-dark-previews --theme dark
```

Copy the dark renderer's `Main_Page.png` and `View_Process_Exclusions.png` to `Main_Page_Dark.png` and `View_Process_Exclusions_Dark.png` in this directory. On Windows, choose a temporary output directory such as `C:/Temp/cse-dark-previews` instead of `/tmp/cse-dark-previews`.
