VERSION ?= 0.0.1

deploy:
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t matt3010/wg-acl:latest \
		-t matt3010/wg-acl:$(VERSION) \
		. --push --no-cache