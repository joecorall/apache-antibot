#!/usr/bin/env bash

set -eou pipefail

echo "Waiting for apache to come online"
while ! curl -s -o /dev/null -f http://localhost:8080/; do sleep 1; done
while ! curl -s -o /dev/null -f http://localhost:9000/healthcheck; do sleep 1; done

echo "Starting tests"

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/ | grep -q 200 \
  || (echo "Unprotected path should return 200" && exit 1)

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/foo | grep -q 404 \
  || (echo "404 on unprottected should return 404" && exit 1)

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/protected | grep -q 429 \
  || (echo "Protected path should challenge" && exit 1)

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/protected/foo | grep -q 429 \
  || (echo "Nested protected path should challenge" && exit 1)

curl -XPOST -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/ | grep -q 200 \
  || (echo "POST to a unprotected path should return 200" && exit 1)

curl -XPOST -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/?challenge=1" | grep -q 200 \
  || (echo "POST to a unprotected path with challenge key should return 200" && exit 1)

curl -XPOST -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/protected | grep -q 404 \
  || (echo "POST to a protected path without challenge key should 404" && exit 1)

curl -XPOST -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/protected?challenge_no=1" | grep -q 404 \
  || (echo "POST to a protected path with non-challenge key should 404" && exit 1)

curl -XPOST -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/protected?challenge=1" | grep -q 403 \
  || (echo "POST to a protected path with challenge key should 403" && exit 1)

echo "Tests passed 🚀"
