.PHONY: check convert lint stats help

help:
	@echo "ECOP Detection Rules — dev commands"
	@echo "  make check    - ตรวจ syntax + schema + metadata ของทุก rule"
	@echo "  make convert  - ลองแปลงทุก rule เป็น Splunk query (ตรวจ convertibility)"
	@echo "  make lint     - ตรวจ metadata standard ของ ECOP"
	@echo "  make stats    - อัปเดต .stats.json (จำนวน rule สำหรับ badge)"

check: lint
	sigma check sigma/ emerging-threats/

convert:
	@for rule in $$(find sigma emerging-threats -name '*.yml'); do \
		echo "→ $$rule"; \
		sigma convert -t splunk -p sysmon "$$rule" > /dev/null || exit 1; \
	done
	@echo "ทุก rule แปลงผ่าน ✅"

lint:
	python .github/scripts/lint_metadata.py

stats:
	@count=$$(find sigma emerging-threats -name '*.yml' | wc -l | tr -d ' '); \
	printf '{ "count": %s }\n' "$$count" > .stats.json; \
	echo "อัปเดต .stats.json → $$count rules"
