set -eu

urls=(
  https://www.npkd.nl/files/nl-health-dsc-certs/HealthDSCforrecovery.pem
  https://www.npkd.nl/files/nl-health-dsc-certs/HealthDSCfortest.pem
  https://www.npkd.nl/files/nl-health-dsc-certs/HealthDSCforvaccinations.pem
)

for url in ${urls[@]}; do
  pem=$(curl -s "$url")
  kid=$(echo "$pem" | openssl x509 -inform pem -outform der | openssl dgst -binary -sha256 | head -c8 | openssl base64)
  
  subjectPk=$(echo "$pem" | openssl x509 -pubkey -noout)
  lines=$(echo "$subjectPk" | wc -l)
  subjectPk=$(echo "$subjectPk" | tail -n $(($lines-1)) | head -n $(($lines-2)) | tr -d '\n')

  printf "\"$kid\": [\n  {\n    \"subjectPk\": \"$subjectPk\",\n    \"keyUsage\": []\n  }\n],\n"
done


#cat ~/Downloads/HealthDSCforvaccinations.pem | openssl x509 -inform pem -outform der | openssl dgst -binary -sha256 | head -c8 | openssl base64