curl -s https://verifier-api.coronacheck.nl/v4/verifier/config | jq -r .payload | base64 -d | jq > config.json
curl -s https://verifier-api.acc.coronacheck.nl/v4/verifier/public_keys | jq -r .payload | base64 -d | jq > public_keys.json
