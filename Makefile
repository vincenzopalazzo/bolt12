#! /usr/bin/make

check:
	cd js && npm install && npm run build && npm test
