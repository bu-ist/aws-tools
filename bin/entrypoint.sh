#!/bin/sh

if [ "$1" = shib-auth ]; then
  echo "Shibboleth authentication for profile: $2"
  echo ""
else
  echo "If you need to authenticate for a regular AWS account: aws configure"
  echo ""
  echo "If you need to authenticate using Shibboleth: shib-auth"
fi

if [ ! -f /root/.aws/credentials ]; then
    mkdir -p /root/.aws
    touch /root/.aws/credentials
fi

exec "$@"
