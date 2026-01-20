# Quokka's Wiz Integration

Example Usage:

```
python upload_sarif.py --sarif quokka_data_file.json \
  --client-id "INSERT YOUR CLIENT ID" \
  --client-secret "INSERT YOUR CLIENT SECRET" \
  --data-source-id "Your Datasource ID" \
  --fallback-repo-url "Source Control URL (e.g. https://github.com/myorg/testapp)" \
  --fallback-branch "Source Control Branch (e.g. main)" \
  --api-url "https://api.us18.app.wiz.io/graphql" \
  --auth-url "https://auth.app.wiz.io/oauth/token"
```

And to poll the systemActivity to see if it was successfully processed (may take up to 12 hours)

```
python upload_sarif.py \
  --poll-only \
  --system-activity-id "ACTIVITY ID RETURNED FROM SUBMISSION SCRIPT" \
  --client-id "INSERT YOUR CLIENT ID" \
  --client-secret "INSERT YOUR CLIENT SECRET" \
  --api-url "https://api.us18.app.wiz.io/graphql" \
  --auth-url "https://auth.app.wiz.io/oauth/token"
```
