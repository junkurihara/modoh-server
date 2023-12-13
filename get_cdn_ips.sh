#!/bin/bash

OUTPUT_FILE="cdn_ips.txt"
TMP_FILE="/tmp/cdn_ips.txt"

# Get Cloudflare IPs
CLOUDFLARE_API="https://api.cloudflare.com/client/v4/ips"

echo 'Get Cloudflare IPs'
curl -q ${CLOUDFLARE_API} > ${TMP_FILE}
SUCCESS=(`cat ${TMP_FILE} | jq .success`)
if [ ${SUCCESS} != "true" ]; then
    echo 'Failed to get Cloudflare IPs'
    exit 1
fi
echo "# Cloudflare IPs" > ${OUTPUT_FILE}
cat ${TMP_FILE} | jq .result.'ipv4_cidrs' | sed 's/[][ \t\",]//g' |sed '/^$/d' >> ${OUTPUT_FILE}
cat ${TMP_FILE} | jq .result.'ipv6_cidrs' | sed 's/[][ \t\",]//g' |sed '/^$/d' >> ${OUTPUT_FILE}

echo "" >> ${OUTPUT_FILE}

# Get Fastly IPs
FASTLY_API="https://api.fastly.com/public-ip-list"

echo 'Get Fastly IPs'
curl -q ${FASTLY_API} > ${TMP_FILE}
echo "# Fastly IPs" >> ${OUTPUT_FILE}
cat ${TMP_FILE} | jq .addresses | sed 's/[][ \t\",]//g' |sed '/^$/d' >> ${OUTPUT_FILE}
cat ${TMP_FILE} | jq .ipv6_addresses | sed 's/[][ \t\",]//g' |sed '/^$/d' >> ${OUTPUT_FILE}
