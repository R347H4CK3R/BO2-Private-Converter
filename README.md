# BO2 Private Converter

Private orchestration repository for processing a user-owned local BO2 PS3_GAME tree on a Windows self-hosted GitHub Actions runner.

Raw game files are never committed by this workflow. Reports are written to the runner workspace and uploaded as Actions artifacts.

Expected source path: `C:\BO2\PS3_GAME` (override with workflow input).
