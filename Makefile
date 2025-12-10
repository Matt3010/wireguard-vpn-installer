deploy:
	docker buildx build --platform linux/arm64 -t matt3010/WgACL:latest . --push --no-cache