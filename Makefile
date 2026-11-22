.PHONY: secrets up verify firewall-test backup restore-test down clean

secrets:        ## create .env and secrets/ (once)
	./scripts/gen-secrets.sh

up: secrets     ## build and start the stack
	docker compose up -d --build

verify:         ## end-to-end security checks -> reports/verification-report.md
	./scripts/verify.sh

firewall-test:  ## load nftables.conf in a throwaway namespace and test it
	./firewall/test-firewall.sh | tee reports/firewall-test.txt

backup:         ## run a backup now
	docker compose exec backup backup.sh

restore-test:   ## restore the latest backup into a scratch database
	docker compose exec backup restore-test.sh

down:           ## stop, keep data
	docker compose down

clean:          ## stop and delete all data volumes
	docker compose down -v
