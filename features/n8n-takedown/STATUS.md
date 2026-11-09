# n8n-takedown

**Status:** DONE

## What it does

The **n8n-takedown** feature provides a ready-to-use n8n workflow JSON that
drafts phishing takedown reports.  It is designed for automation of phishing
report filing and includes a **DRY_RUN** mode by default so that no actual
reports are sent unless explicitly enabled.

### DRY_RUN mode (default)

When `DRY_RUN=true` (the default), the workflow:

1. Generates a draft report JSON via the **Generate Report** node.
2. **Stops** before the **Mock Sender** node – no HTTP request is made.
3. Outputs the draft report in the n8n execution log.

To enable actual sending, set `DRY_RUN=false` either in the workflow settings
or per-execution via the n8n UI.

## How to run it

```bash
# 1. Import the workflow into n8n
n8n import --file features/n8n-takedown/workflow.json

# 2. Run the workflow in the n8n UI.
#    - Default behaviour: draft report only, no sending.
#    - To send: set DRY_RUN=false in the workflow or execution options.
```