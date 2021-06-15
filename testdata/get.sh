curl https://verifier-api.acc.coronacheck.nl/v4/verifier/public_keys | jq -r .payload | base64 -d | jq > public_keys.json
