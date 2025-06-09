build:
	docker compose -f test/docker-compose.yaml build

test: build
	docker compose -f test/docker-compose.yaml up -d
	bash ./test/run.sh

clean:
	docker compose -f test/docker-compose.yaml down

.PHONY: build test clean
