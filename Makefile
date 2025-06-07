build:
	docker compose -f test/docker-compose.yaml build

test: build
	docker compose -f test/docker-compose.yaml up -d
	bash ./test/run.sh

.PHONY: build test
