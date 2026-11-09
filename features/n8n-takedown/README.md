# n8n-takedown

**Status:** DONE

## What it does

The **n8n-takedown** feature provides a ready-to-use n8n workflow JSON that
drafts phishing takedown reports.  It is designed for automation of phishing
report filing and includes a **DRY_RUN** mode by default so that no actual
reports are sent unless explicitly enabled.

### Features

- **DRY_RUN by default** – the workflow generates a draft report JSON but does
  not submit it to any external endpoint.  Set `DRY_RUN=false` to enable the
  mock sender step.
- **Modular nodes** – the workflow consists of three nodes:
  1. **Start** – workflow entry point
  2. **Generate Report** – creates a draft report (parameters configurable)
  3. **Mock Sender** – posts the report to a configurable URL (disabled in
   DRY_RUN mode)
- **Self‑contained** – the only artifact is `workflow.json`; no external
  dependencies or environment variables are required for the basic flow.

### How to run it

1. Import the workflow into n8n:
   ```bash
   n8n import --file features/n8n-takedown/workflow.json
   ```
2. Run the workflow in n8n.  By default it will stop at the **Generate Report**
   node and display the draft report in the execution output.
3. To enable actual sending, toggle the **Mock Sender** node's DRY_RUN setting
   to `false` or override it via the workflow execution UI.

### Customisation

- Change the `url` in the **Mock Sender** node to point at your own reporting
  API.
- Adjust the **Generate Report** node's parameters to include the phishing URL,
  reporter details, or any other metadata your organisation requires.
- Set the `dryRun` parameter to `false` globally or per-execution to switch
  between draft‑only and send‑mode.

## Tests

No unit tests are provided (the workflow is validated by visual inspection and
n8n's own import validation).

## License

MIT — see the project root.