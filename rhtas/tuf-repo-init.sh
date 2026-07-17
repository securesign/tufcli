#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat << EOF
Usage: $(basename "${BASH_SOURCE[0]}") [OPTION] [TUF_REPO_PATH]

Initialize a TUF repository with given targets in TUF_REPO_PATH using tufcli.

Options:
  -h, --help
    Display this help message

  --export-keys
    Where to save keys - either a file:///path/to/dir or a string - k8s secret name

  --fulcio-cert
    Fulcio certificate chain file

  --tsa-cert
    TSA certificate chain file

  --ctlog-key
    CTLog public key file

  --fulcio-uri
    Fulcio base URI

  --oidc-uri
    OIDC provider URI (used with Fulcio for authentication)

  --rekor-key
    Rekor public key file

  --rekor-uri
    Rekor base URI

  --tsa-uri
    TSA base URI

  --ctlog-uri
    CTLog base URI

  --metadata-expiration
    tufcli-compatible metadata expiration time; defaults to 'in 52 weeks'

  --operator
    Operator name for signing config services; defaults to "rhtas"
EOF
}

export TUF_REPO_PATH=""
export EXPORT_KEYS=""
export FULCIO_CERT=""
export TSA_CERT=""
export CTLOG_KEY=""
export REKOR_KEY=""
export FULCIO_URI=""
OIDC_URIS=()
export TSA_URI=""
export CTLOG_URI=""
export REKOR_URI=""
export METADATA_EXPIRATION="in 52 weeks"
export OPERATOR="rhtas"

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      shift
      usage
      exit
      ;;
    --export-keys)
      EXPORT_KEYS="$2"
      shift
      shift
      ;;
    --fulcio-cert)
      FULCIO_CERT="$2"
      shift
      shift
      ;;
    --fulcio-uri)
      FULCIO_URI="$2"
      shift
      shift
      ;;
    --oidc-uri)
      OIDC_URIS+=("$2")
      shift
      shift
      ;;
    --tsa-cert)
      TSA_CERT="$2"
      shift
      shift
      ;;
    --tsa-uri)
      TSA_URI="$2"
      shift
      shift
      ;;
    --ctlog-key)
      CTLOG_KEY="$2"
      shift
      shift
      ;;
    --ctlog-uri)
      CTLOG_URI="$2"
      shift
      shift
      ;;
    --rekor-key)
      REKOR_KEY="$2"
      shift
      shift
      ;;
    --rekor-uri)
      REKOR_URI="$2"
      shift
      shift
      ;;
    --metadata-expiration)
      METADATA_EXPIRATION="$2"
      shift
      shift
      ;;
    --operator)
      OPERATOR="$2"
      shift
      shift
      ;;
    -*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      if [ -n "${TUF_REPO_PATH}" ]; then
        echo "Only expected one positional argument"
        usage
        exit 1
      fi
      TUF_REPO_PATH="$1"
      shift
      ;;
  esac
done

if [ -z "${TUF_REPO_PATH}" ]; then
  echo "TUF repo path not specified"
  usage
  exit 1
fi

if [ -e "${TUF_REPO_PATH}/root.json" ]; then
  echo "Repo seems to already be initialized (${TUF_REPO_PATH}/root.json exists)"
  exit 2
fi

export WORKDIR=""
WORKDIR=$(mktemp -d /tmp/tuf.XXXX)

echo "Initializing TUF repository in ${WORKDIR} using tufcli ..."

export ROOT="${WORKDIR}/root/root.json"
export INPUTDIR="${WORKDIR}/input"
export KEYDIR="${WORKDIR}/keys"
export ROOTDIR="${WORKDIR}/root"
export OUTDIR="${WORKDIR}/tuf-repo"
mkdir -p "${ROOTDIR}" "${KEYDIR}" "${INPUTDIR}" "${OUTDIR}"

# Initialize the root
echo "Creating root.json ..."
tufcli root init --path "${ROOT}"
tufcli root expire --path "${ROOT}" --time "${METADATA_EXPIRATION}"

# Set thresholds
tufcli root set-threshold --path "${ROOT}" --role root --threshold 1
tufcli root set-threshold --path "${ROOT}" --role snapshot --threshold 1
tufcli root set-threshold --path "${ROOT}" --role targets --threshold 1
tufcli root set-threshold --path "${ROOT}" --role timestamp --threshold 1

echo "Generating signing keys in ${KEYDIR} ..."

# Generate keys and add them to their respective roles
tufcli root gen-rsa-key --path "${ROOT}" --output "${KEYDIR}/root.pem" --role root --bits 2048
tufcli root gen-rsa-key --path "${ROOT}" --output "${KEYDIR}/snapshot.pem" --role snapshot --bits 2048
tufcli root gen-rsa-key --path "${ROOT}" --output "${KEYDIR}/targets.pem" --role targets --bits 2048
tufcli root gen-rsa-key --path "${ROOT}" --output "${KEYDIR}/timestamp.pem" --role timestamp --bits 2048

echo "Signing the root file ${ROOT} ..."

# Sign root
tufcli root sign --path "${ROOT}" --key "${KEYDIR}/root.pem"

echo "Initializing empty repository in ${OUTDIR} ..."

# Create the repo
tufcli create \
  --root "${ROOT}" \
  --key "${KEYDIR}/root.pem" \
  --key "${KEYDIR}/snapshot.pem" \
  --key "${KEYDIR}/targets.pem" \
  --key "${KEYDIR}/timestamp.pem" \
  --add-targets "${INPUTDIR}" \
  --targets-expires "${METADATA_EXPIRATION}" \
  --targets-version 1 \
  --snapshot-expires "${METADATA_EXPIRATION}" \
  --snapshot-version 1 \
  --timestamp-expires "${METADATA_EXPIRATION}" \
  --timestamp-version 1 \
  --outdir "${OUTDIR}"

echo "Adding trust root targets ..."

# Prepare targets
if [ -n "${FULCIO_CERT}" ]; then
  echo "Adding Fulcio certificate chain ${FULCIO_CERT} ..."
  OIDC_ARGS=()
  for uri in "${OIDC_URIS[@]}"; do
    OIDC_ARGS+=(--oidc-uri "$uri")
  done
  tufcli rhtas \
    --follow \
    --root "${ROOT}" \
    --key "${KEYDIR}/snapshot.pem" \
    --key "${KEYDIR}/targets.pem" \
    --key "${KEYDIR}/timestamp.pem" \
    --set-fulcio-target "${FULCIO_CERT}" \
    --fulcio-uri "${FULCIO_URI}" \
    "${OIDC_ARGS[@]}" \
    --operator "${OPERATOR}" \
    --targets-expires "${METADATA_EXPIRATION}" \
    --targets-version 1 \
    --snapshot-expires "${METADATA_EXPIRATION}" \
    --snapshot-version 1 \
    --timestamp-expires "${METADATA_EXPIRATION}" \
    --timestamp-version 1 \
    --force-version \
    --outdir "${OUTDIR}" \
    --metadata-url "file://${OUTDIR}"
fi

if [ -n "${TSA_CERT}" ]; then
  echo "Adding TSA certificate chain ${TSA_CERT} ..."
  tufcli rhtas \
    --follow \
    --root "${ROOT}" \
    --key "${KEYDIR}/snapshot.pem" \
    --key "${KEYDIR}/targets.pem" \
    --key "${KEYDIR}/timestamp.pem" \
    --set-tsa-target "${TSA_CERT}" \
    --tsa-uri "${TSA_URI}" \
    --operator "${OPERATOR}" \
    --targets-expires "${METADATA_EXPIRATION}" \
    --targets-version 1 \
    --snapshot-expires "${METADATA_EXPIRATION}" \
    --snapshot-version 1 \
    --timestamp-expires "${METADATA_EXPIRATION}" \
    --timestamp-version 1 \
    --force-version \
    --outdir "${OUTDIR}" \
    --metadata-url "file://${OUTDIR}"
fi

if [ -n "${CTLOG_KEY}" ]; then
  echo "Adding CTLog public key ${CTLOG_KEY} ..."
  tufcli rhtas \
    --follow \
    --root "${ROOT}" \
    --key "${KEYDIR}/snapshot.pem" \
    --key "${KEYDIR}/targets.pem" \
    --key "${KEYDIR}/timestamp.pem" \
    --set-ctlog-target "${CTLOG_KEY}" \
    --ctlog-uri "${CTLOG_URI}" \
    --operator "${OPERATOR}" \
    --targets-expires "${METADATA_EXPIRATION}" \
    --targets-version 1 \
    --snapshot-expires "${METADATA_EXPIRATION}" \
    --snapshot-version 1 \
    --timestamp-expires "${METADATA_EXPIRATION}" \
    --timestamp-version 1 \
    --force-version \
    --outdir "${OUTDIR}" \
    --metadata-url "file://${OUTDIR}"
fi

if [ -n "${REKOR_KEY}" ]; then
  echo "Adding Rekor public key ${REKOR_KEY} ..."
  tufcli rhtas \
    --follow \
    --root "${ROOT}" \
    --key "${KEYDIR}/snapshot.pem" \
    --key "${KEYDIR}/targets.pem" \
    --key "${KEYDIR}/timestamp.pem" \
    --set-rekor-target "${REKOR_KEY}" \
    --rekor-uri "${REKOR_URI}" \
    --operator "${OPERATOR}" \
    --targets-expires "${METADATA_EXPIRATION}" \
    --targets-version 1 \
    --snapshot-expires "${METADATA_EXPIRATION}" \
    --snapshot-version 1 \
    --timestamp-expires "${METADATA_EXPIRATION}" \
    --timestamp-version 1 \
    --force-version \
    --outdir "${OUTDIR}" \
    --metadata-url "file://${OUTDIR}"
fi

if [ "${EXPORT_KEYS:0:7}" = "file://" ]; then
  export EXPORT_DIR=${EXPORT_KEYS:7}
  echo "Exporting keys to directory ${EXPORT_DIR} ..."
  mkdir -p "${EXPORT_DIR}"
  cp "${KEYDIR}/"* "${EXPORT_DIR}"
elif [ -n "${EXPORT_KEYS}" ]; then
  echo "Exporting keys to k8s secret ${EXPORT_KEYS} ..."

  export AUTHDIR="/var/run/secrets/kubernetes.io/serviceaccount"
  export K8SCACERT="${AUTHDIR}/ca.crt"
  export K8SSECRETS="https://kubernetes.default.svc/api/v1/namespaces/${NAMESPACE}/secrets"
  export K8SAUTH=""
  export SECRET_CONTENT=""

  K8SAUTH="Authorization: Bearer $(cat ${AUTHDIR}/token)"
  SECRET_CONTENT=$(cat <<EOF
{
 "apiVersion":"v1",
 "kind" :"Secret",
 "metadata" :{"namespace": "${NAMESPACE}", "name": "${EXPORT_KEYS}"},
 "type": "Opaque",
 "data": {
   "root.pem": "$(base64 -w0 < "${KEYDIR}/root.pem")",
   "snapshot.pem": "$(base64 -w0 < "${KEYDIR}/snapshot.pem")",
   "targets.pem": "$(base64 -w0 < "${KEYDIR}/targets.pem")",
   "timestamp.pem": "$(base64 -w0 < "${KEYDIR}/timestamp.pem")"
  }
}
EOF
)
  export KEYS_CREATE_HTTP_STATUS="-1"
  # if the secret exists, replace it with the content, otherwise create it
  KEYS_CREATE_HTTP_STATUS=$(curl -X POST \
    --silent \
    --output /dev/null \
    --write-out "%{http_code}" \
    --cacert "${K8SCACERT}" \
    -H "${K8SAUTH}" \
    --header 'Content-Type: application/json' \
    --data @- \
    "${K8SSECRETS}" <<EOF
${SECRET_CONTENT}
EOF
    )

  if [ "${KEYS_CREATE_HTTP_STATUS}" = "409" ]; then
    curl --fail -X PUT \
      --output /dev/null \
      --cacert "${K8SCACERT}" \
      -H "${K8SAUTH}" \
      --header 'Content-Type: application/json' \
      --data @- \
      "${K8SSECRETS}/${EXPORT_KEYS}" <<EOF
${SECRET_CONTENT}
EOF
  elif [ "${KEYS_CREATE_HTTP_STATUS:0:1}" != "2" ]; then
    echo "Bad HTTP status when creating K8S secret ${EXPORT_KEYS}: ${KEYS_CREATE_HTTP_STATUS}"
    exit 1
  fi
else
  echo "Key export location not specified, not exporting keys"
fi

# Remove unused trusted_root.json files from ${OUTDIR}/targets (keep only the latest)
mapfile -t files_to_delete < <(find "${OUTDIR}/targets/" -type f -name "*.trusted_root.json" -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | tail -n +2)
for file in "${files_to_delete[@]}"; do
    rm -- "$file"
done

# Remove unused signing_config.v0.2.json files from ${OUTDIR}/targets
mapfile -t files_to_delete < <(find "${OUTDIR}/targets/" -type f -name "*.signing_config.v0.2.json" -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | tail -n +2)
for file in "${files_to_delete[@]}"; do
    rm -- "$file"
done

echo "Setting 644 permissions on public repository files..."
find "${OUTDIR}" -type f -exec chmod 644 {} +

# Test - list the repository structure
ls -Rla "${OUTDIR}"

echo "Copying the TUF repository to final location ${TUF_REPO_PATH} ..."
cp -R "${OUTDIR}/." "${TUF_REPO_PATH}"

echo "Finished successfully!"
echo "TUF repository initialized at: ${TUF_REPO_PATH}"
