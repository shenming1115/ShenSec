# Real desktop screenshots

These images come from the actual Qt workbench and authenticated loopback HTTP fixtures, using `examples/capture_workbench.py`. They are not UI mockups. Fixture credentials are synthetic. The role screenshot deliberately selects the older, vulnerable run; the session screenshot selects the hardened run.

| Image | What it demonstrates |
| --- | --- |
| [Permission matrix](permissions-workbench.png) | Four roles, two endpoints and three unexpected grants before hardening |
| [Automatic login](login-workbench.png) | Guided login, expiry and verification configuration |
| [Sessions](sessions-workbench.png) | Login/refresh activity after hardening |
| [API requests](api-workbench.png) | Explicit request plans and the API editor |
| [Findings](workbench.png) | History, comparison filters and evidence |

Reproduce from a source checkout with the GUI extra installed:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
uv run python examples/capture_workbench.py --identities --before --view permissions --output docs/permissions-workbench.png
uv run python examples/capture_workbench.py --identities --view login --output docs/login-workbench.png
uv run python examples/capture_workbench.py --identities --view sessions --output docs/sessions-workbench.png
uv run python examples/capture_workbench.py --configure --output docs/api-workbench.png
uv run python examples/capture_workbench.py --output docs/workbench.png
```

For binary verification, `ShenSec.exe --self-test OUTPUT` renders the actual bundled Qt application and writes a screenshot, reports and a JSON verification result. This flag is for release automation; normal desktop use requires no command.
